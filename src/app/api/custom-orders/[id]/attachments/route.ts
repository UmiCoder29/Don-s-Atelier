import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { prisma } from '@/lib/db/prisma';
import { NotFoundError, BadRequestError } from '@/lib/errors/api-error';
import { uuidSchema } from '@/lib/validation/zod-helpers';
import { sanitizeText } from '@/lib/validation/sanitizer';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import {
  validateCustomOrderStoragePath,
  revalidateAndSanitizeAttachment,
  sanitizeClientFileName,
  SanitizedAttachmentResult,
} from '@/services/bespoke/attachment-sanitizer';
import { supabaseAdmin } from '@/lib/db/supabase';
import { STORAGE_BUCKETS } from '@/lib/storage/buckets';
import { logger } from '@/lib/api/logger';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

const paramsSchema = z.object({
  id: uuidSchema,
}).strict();

export const uploadAttachmentSchema = z.object({
  fileName: z
    .string()
    .min(1, 'File name is required')
    .transform((val) => sanitizeClientFileName(sanitizeText(val)) || 'attachment')
    .optional(),
  mimeType: z.enum(
    ['image/jpeg', 'image/png', 'image/webp'],
    { errorMap: () => ({ message: 'Unsupported file type. Only reference photos (JPEG, PNG, WebP) are permitted' }) }
  ).optional().default('image/jpeg'),
  size: z
    .number()
    .int('File size must be an integer')
    .positive('File size must be positive')
    .max(10 * 1024 * 1024, 'File size exceeds maximum allowed limit of 10MB')
    .optional()
    .default(1024),
  storagePath: z.string().min(1, 'Storage path is required').max(500, 'Storage path too long'),
}).strict();

export type UploadAttachmentInput = z.infer<typeof uploadAttachmentSchema>;

/**
 * POST /api/custom-orders/[id]/attachments
 * Records attachment reference for a bespoke custom order in Supabase Storage.
 *
 * Security Pipeline:
 * - Server-side authentication + ownership verification
 * - Strict storage path validation (custom-orders/{user.id}/ only, rejects traversal & null bytes)
 * - Server-side re-validation: metadata size <= 10MB, magic-byte allowlist, Sharp 40M pixel limit,
 *   EXIF metadata strip, and write to a new random UUID object name
 * - Atomic 5-image cap enforced inside transaction with row lock (SELECT ... FOR UPDATE)
 * - Deletes original upload object and cleans up on failure
 * - Audit logging
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id: customOrderId } = paramsSchema.parse(resolvedParams);

  const customOrder = await prisma.customOrder.findUnique({
    where: { id: customOrderId },
  });

  if (!customOrder) {
    throw new NotFoundError('Custom suit request');
  }

  assertOwnerOrAdmin(user, customOrder.profileId);

  const body = await req.json();
  const input = uploadAttachmentSchema.parse(body);

  // 1. Strict storage path validation
  validateCustomOrderStoragePath(user, input.storagePath, customOrder.profileId);

  // 2. Server-side re-validation and Sharp sanitization
  let sanitized: SanitizedAttachmentResult | null = null;
  try {
    sanitized = await revalidateAndSanitizeAttachment(
      user,
      input.storagePath,
      input.fileName,
      customOrder.profileId
    );

    // 3. Atomic 5-image cap inside a transaction with a row lock (SELECT ... FOR UPDATE)
    const attachment = await prisma.$transaction(
      async (tx) => {
        // Row lock on the custom order
        await tx.$queryRaw`SELECT id FROM custom_orders WHERE id = ${customOrderId} FOR UPDATE`;

        // Count current attachments under row lock
        const currentCount = await tx.customOrderAttachment.count({
          where: { customOrderId },
        });

        if (currentCount >= 5) {
          throw new BadRequestError('Cannot attach more than 5 reference images per custom suit request');
        }

        // Insert new attachment under lock
        return await tx.customOrderAttachment.create({
          data: {
            customOrderId,
            fileName: sanitized!.fileName,
            mimeType: sanitized!.mimeType,
            size: sanitized!.size,
            storagePath: sanitized!.storagePath,
          },
        });
      },
      {
        maxWait: 15000,
        timeout: 30000,
      }
    );

    await logAuditEventFromRequest(req, {
      actorId: user.id,
      action: 'CUSTOM_ORDER_ATTACHMENT_UPLOADED',
      entity: 'CustomOrderAttachment',
      entityId: attachment.id,
      metadata: {
        customOrderId,
        fileName: attachment.fileName,
        size: attachment.size,
        mimeType: attachment.mimeType,
        storagePath: attachment.storagePath,
      },
    });

    return successResponse(attachment, requestId, {}, 201);
  } catch (err) {
    // If database transaction failed (e.g. 5-image cap reached) or anything failed
    // AFTER the sanitized object was uploaded, delete that sanitized object from storage.
    if (sanitized?.storagePath) {
      try {
        const { error: removeErr } = await supabaseAdmin.storage
          .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
          .remove([sanitized.storagePath]);
        if (removeErr) {
          logger.warn('Failed to delete sanitized storage object after transaction failure', {
            storagePath: sanitized.storagePath,
            error: removeErr.message,
          });
        }
      } catch (cleanupErr) {
        logger.warn('Error during sanitized storage object deletion on failure', {
          storagePath: sanitized.storagePath,
          error: cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr),
        });
      }
    }
    throw err;
  }
});
