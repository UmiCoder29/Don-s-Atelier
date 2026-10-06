import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth, Role } from '@/lib/auth/supabase-auth';
import { sanitizeText } from '@/lib/validation/sanitizer';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { STORAGE_BUCKETS } from '@/lib/storage/buckets';
import { createSignedUploadUrl } from '@/lib/storage/signed-urls';
import { ForbiddenError } from '@/lib/errors/api-error';

const EXTENSION_MAP: Record<string, string> = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};

export const initiateUploadSchema = z
  .object({
    fileName: z
      .string()
      .min(1, 'File name is required')
      .max(255, 'File name cannot exceed 255 characters')
      .transform(sanitizeText),
    mimeType: z.enum(['image/jpeg', 'image/png', 'image/webp'], {
      errorMap: () => ({
        message: 'Unsupported file type. Only reference photos (JPEG, PNG, WebP) are permitted',
      }),
    }),
    size: z
      .number()
      .int('File size must be an integer')
      .positive('File size must be positive')
      .max(10 * 1024 * 1024, 'File size exceeds maximum allowed limit of 10MB'),
    folder: z.enum(['custom-orders', 'showcase']).default('custom-orders'),
  })
  .strict();

export type InitiateUploadInput = z.infer<typeof initiateUploadSchema>;

/**
 * POST /api/uploads
 * Initiates an authorized upload session for client file uploads to Supabase Storage.
 *
 * Security Pipeline:
 * - Server-side authentication
 * - Role-based bucket isolation (showcase requires ADMIN; custom-orders private to user)
 * - Server-generated random UUID object paths under per-user folders (never trusts client file names)
 * - Reference photos only: JPEG, PNG, WebP (PDF removed)
 * - Rate limiting (Upload group: per IP and per User)
 * - Anti-CSRF protection for cookie-authenticated clients
 * - Strict payload validation and sanitization
 * - Short-expiry signed upload URL generation (60s)
 * - System audit logging
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const body = await req.json();
  const input = initiateUploadSchema.parse(body);

  // Showcase image uploads are strictly reserved for Atelier administrators
  if (input.folder === 'showcase' && user.role !== Role.ADMIN) {
    throw new ForbiddenError(
      'Access denied: Only atelier administrators can initiate showcase image uploads'
    );
  }

  const targetBucket =
    input.folder === 'showcase'
      ? STORAGE_BUCKETS.PRODUCT_IMAGES
      : STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS;

  const ext = EXTENSION_MAP[input.mimeType] || '.jpg';
  const fileUuid = crypto.randomUUID();

  // Object path is ALWAYS generated on the server: random UUID under a per-user folder.
  // Never uses client-supplied fileName for the object path.
  const storagePath =
    input.folder === 'showcase'
      ? `catalog/${fileUuid}${ext}`
      : `custom-orders/${user.id}/${fileUuid}${ext}`;

  // Generate short-lived signed upload URL (60 seconds)
  const { signedUrl, token, expiresIn } = await createSignedUploadUrl(
    targetBucket,
    storagePath,
    { expiresIn: 60 }
  );

  await logAuditEventFromRequest(req, {
    actorId: user.id,
    action: 'UPLOAD_SESSION_INITIATED',
    entity: 'Upload',
    entityId: storagePath,
    metadata: {
      clientFileName: input.fileName,
      storagePath,
      mimeType: input.mimeType,
      size: input.size,
      folder: input.folder,
      bucket: targetBucket,
      expiresIn,
    },
  });

  return successResponse(
    {
      storagePath,
      bucket: targetBucket,
      signedUrl,
      token,
      expiresIn,
      maxSizeBytes: 10 * 1024 * 1024,
      allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'],
    },
    requestId,
    {},
    201
  );
});
