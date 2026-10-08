import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { uuidSchema } from '@/lib/validation/zod-helpers';
import { decryptPhone, decryptAddressFields } from '@/lib/crypto/field-encryption';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { NotFoundError } from '@/lib/errors/api-error';

interface RouteContext {
  params: Promise<{ id: string }>;
}

const paramsSchema = z
  .object({
    id: uuidSchema,
  })
  .strict();

/**
 * GET /api/admin/users/[id]
 * Customer detail route returning decrypted phone and address.
 * Measurements are strictly NOT exposed here.
 * EVERY call writes an audit entry recording admin and customer IDs (never decrypted values).
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = paramsSchema.parse(resolvedParams);

  const profile = await prisma.profile.findUnique({
    where: { id },
    include: {
      addresses: true,
    },
  });

  if (!profile) {
    throw new NotFoundError('Customer profile');
  }

  // Audit log: record which admin viewed which customer's data (IDs only, no decrypted values)
  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_CUSTOMER_VIEWED',
    entity: 'Profile',
    entityId: id,
    metadata: {
      targetUserId: id,
      viewedByAdminId: adminUser.id,
    },
  });

  const decryptedAddresses = profile.addresses.map((addr) =>
    decryptAddressFields({
      id: addr.id,
      recipientName: addr.recipientName,
      line1: addr.line1,
      line2: addr.line2,
      city: addr.city,
      state: addr.state,
      postalCode: addr.postalCode,
    })
  );

  const customerDetail = {
    id: profile.id,
    email: profile.email,
    name: profile.name,
    phone: decryptPhone(profile.phone),
    role: profile.role,
    addresses: decryptedAddresses,
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
  };

  return successResponse(customerDetail, requestId);
});
