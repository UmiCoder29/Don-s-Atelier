import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { storageService } from '@/lib/storage/storage-service';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { ValidationError, BadRequestError } from '@/lib/errors/api-error';
import { uuidSchema } from '@/lib/validation/zod-helpers';
import { sanitizeText } from '@/lib/validation/sanitizer';

// Zod schema for JSON uploads (e.g. base64 encoded image or metadata)
const jsonImageUploadSchema = z
  .object({
    file: z.string().min(1, 'Base64 image file data is required'),
    mimeType: z
      .enum(['image/jpeg', 'image/png', 'image/webp'], {
        errorMap: () => ({
          message: 'Unsupported file type. Only JPEG, PNG, and WebP are permitted',
        }),
      })
      .optional(),
    productId: uuidSchema.optional(),
    altText: z
      .string()
      .max(255, 'Alt text cannot exceed 255 characters')
      .transform(sanitizeText)
      .optional(),
    sortOrder: z.number().int().min(0).max(100).default(0),
  })
  .strict();

/**
 * POST /api/admin/products/images
 * Admin-only route for uploading product showcase images to Supabase Storage ('product-images' bucket).
 *
 * Security Pipeline:
 * 1. Strict server-side RBAC: requireRole('ADMIN')
 * 2. MIME type validation (JPEG, PNG, WebP)
 * 3. Binary magic-byte inspection (strictly rejects executables, scripts, and non-images)
 * 4. Maximum file size enforcement (5MB)
 * 5. Metadata stripping (removes EXIF, GPS, camera, and device info via Sharp)
 * 6. Cryptographically random UUID renaming (never keeps client filenames)
 * 7. System audit logging for Atelier administrative actions
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const contentType = req.headers.get('content-type') || '';

  let buffer: Buffer;
  let declaredMimeType: string | undefined;
  let productId: string | undefined;
  let altText: string | undefined;
  let sortOrder: number = 0;

  if (contentType.includes('multipart/form-data')) {
    const formData = await req.formData();
    const fileEntry = formData.get('file');

    if (!fileEntry || !(fileEntry instanceof Blob)) {
      throw new ValidationError(
        [{ field: 'file', message: 'A valid image file must be provided in form data under "file"' }],
        'Missing upload file'
      );
    }

    const arrayBuffer = await fileEntry.arrayBuffer();
    buffer = Buffer.from(arrayBuffer);
    declaredMimeType = fileEntry.type;

    const pid = formData.get('productId');
    if (pid && typeof pid === 'string') {
      productId = uuidSchema.parse(pid);
    }

    const alt = formData.get('altText');
    if (alt && typeof alt === 'string') {
      altText = sanitizeText(alt);
    }

    const order = formData.get('sortOrder');
    if (order && typeof order === 'string') {
      const parsedOrder = parseInt(order, 10);
      if (!isNaN(parsedOrder)) {
        sortOrder = parsedOrder;
      }
    }
  } else if (contentType.includes('application/json')) {
    const body = await req.json();
    const input = jsonImageUploadSchema.parse(body);

    // Extract base64 payload (strip data URI prefix if present)
    const base64Data = input.file.replace(/^data:image\/[a-z]+;base64,/, '');
    buffer = Buffer.from(base64Data, 'base64');
    declaredMimeType = input.mimeType;
    productId = input.productId;
    altText = input.altText;
    sortOrder = input.sortOrder;
  } else {
    // Attempt direct binary body read if Content-Type is an image
    if (contentType.startsWith('image/')) {
      const arrayBuffer = await req.arrayBuffer();
      buffer = Buffer.from(arrayBuffer);
      declaredMimeType = contentType;
    } else {
      throw new BadRequestError(
        'Invalid Content-Type. Must be multipart/form-data, application/json, or image binary'
      );
    }
  }

  // Upload and process via StorageService
  const result = await storageService.uploadProductImage(adminUser, {
    buffer,
    declaredMimeType,
    productId,
    altText,
    sortOrder,
  });

  // Audit log event
  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_PRODUCT_IMAGE_UPLOADED',
    entity: 'ProductImage',
    entityId: result.id || result.storagePath,
    metadata: {
      storagePath: result.storagePath,
      mimeType: result.mimeType,
      size: result.size,
      productId: result.productId,
      fileName: result.fileName,
    },
  });

  return successResponse(result, requestId, {}, 201);
});
