import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { storageService } from '@/lib/storage/storage-service';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { ValidationError, BadRequestError } from '@/lib/errors/api-error';
import { productIdParamSchema } from '@/services/catalog/types';
import { sanitizeText } from '@/lib/validation/sanitizer';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

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
    altText: z
      .string()
      .max(255, 'Alt text cannot exceed 255 characters')
      .transform(sanitizeText)
      .optional(),
    sortOrder: z.number().int().min(0).max(100).default(0),
  })
  .strict();

/**
 * POST /api/admin/products/[id]/images
 * Admin endpoint to upload and bind an image directly to a product in the catalog.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id: productId } = productIdParamSchema.parse(resolvedParams);

  const contentType = req.headers.get('content-type') || '';

  let buffer: Buffer;
  let declaredMimeType: string | undefined;
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

    const base64Data = input.file.replace(/^data:image\/[a-z]+;base64,/, '');
    buffer = Buffer.from(base64Data, 'base64');
    declaredMimeType = input.mimeType;
    altText = input.altText;
    sortOrder = input.sortOrder;
  } else if (contentType.startsWith('image/')) {
    const arrayBuffer = await req.arrayBuffer();
    buffer = Buffer.from(arrayBuffer);
    declaredMimeType = contentType;
  } else {
    throw new BadRequestError(
      'Invalid Content-Type. Must be multipart/form-data, application/json, or image binary'
    );
  }

  const result = await storageService.uploadProductImage(adminUser, {
    buffer,
    declaredMimeType,
    productId,
    altText,
    sortOrder,
  });

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_PRODUCT_IMAGE_UPLOADED',
    entity: 'ProductImage',
    entityId: result.id || result.storagePath,
    metadata: {
      productId,
      storagePath: result.storagePath,
      mimeType: result.mimeType,
      size: result.size,
    },
  });

  return successResponse(result, requestId, {}, 201);
});
