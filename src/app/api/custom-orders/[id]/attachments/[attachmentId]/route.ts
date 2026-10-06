import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { prisma } from '@/lib/db/prisma';
import { NotFoundError } from '@/lib/errors/api-error';
import { uuidSchema } from '@/lib/validation/zod-helpers';
import { storageService } from '@/lib/storage/storage-service';
import { STORAGE_BUCKETS } from '@/lib/storage/buckets';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

interface RouteContext {
  params: Promise<{ id: string; attachmentId: string }> | { id: string; attachmentId: string };
}

const paramsSchema = z
  .object({
    id: uuidSchema,
    attachmentId: uuidSchema,
  })
  .strict();

/**
 * GET /api/custom-orders/[id]/attachments/[attachmentId]
 * Generates a short-lived signed download URL for a bespoke custom order attachment.
 *
 * Security:
 * - Server-side authentication
 * - assertOwnerOrAdmin: strictly accessible only to order owner or ADMIN
 * - Short expiry (60s)
 * - Audit logged
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id: customOrderId, attachmentId } = paramsSchema.parse(resolvedParams);

  const customOrder = await prisma.customOrder.findUnique({
    where: { id: customOrderId },
    select: { id: true, profileId: true },
  });

  if (!customOrder) {
    throw new NotFoundError('Custom suit request');
  }

  // Enforce customer ownership or admin role
  assertOwnerOrAdmin(user, customOrder.profileId);

  const attachment = await prisma.customOrderAttachment.findUnique({
    where: { id: attachmentId, customOrderId },
  });

  if (!attachment) {
    throw new NotFoundError('Bespoke suit attachment');
  }

  // Generate short-lived signed download URL (60s)
  const { signedUrl, expiresIn } = await storageService.getSignedDownloadUrl(user, {
    bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
    storagePath: attachment.storagePath,
    expiresIn: 60,
    customOrderId,
    download: attachment.fileName || true,
  });

  await logAuditEventFromRequest(req, {
    actorId: user.id,
    action: 'CUSTOM_ORDER_ATTACHMENT_DOWNLOADED',
    entity: 'CustomOrderAttachment',
    entityId: attachment.id,
    metadata: {
      customOrderId,
      fileName: attachment.fileName,
      storagePath: attachment.storagePath,
      expiresIn,
    },
  });

  return successResponse(
    {
      ...attachment,
      signedUrl,
      expiresIn,
    },
    requestId
  );
});
