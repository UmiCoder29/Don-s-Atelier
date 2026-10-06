import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { updateProfileSchema } from '@/lib/validation/auth-schemas';
import { encryptPhone, decryptPhone } from '@/lib/crypto/field-encryption';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

/**
 * GET /api/account/profile
 * Retrieves the authenticated user's profile and cart summary.
 * Protected by requireAuth(req) and Next.js middleware.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);

  const profile = await prisma.profile.findUnique({
    where: { id: user.id },
    include: {
      cart: {
        include: {
          items: true,
        },
      },
      orders: {
        take: 5,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          orderNumber: true,
          status: true,
          totalInCents: true,
          createdAt: true,
        },
      },
    },
  });

  return successResponse(
    {
      profile: {
        id: profile?.id,
        email: profile?.email,
        name: profile?.name,
        phone: decryptPhone(profile?.phone),
        role: profile?.role,
        createdAt: profile?.createdAt,
      },
      cartItemCount: profile?.cart?.items.reduce((acc, item) => acc + item.quantity, 0) ?? 0,
      recentOrders: profile?.orders ?? [],
    },
    requestId
  );
});

/**
 * PATCH /api/account/profile
 * Updates the authenticated user's own profile information.
 * Enforces server-side validation with Zod and field-level encryption for phone.
 */
export const PATCH = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const body = await req.json();
  const input = updateProfileSchema.parse(body);

  const updatedProfile = await prisma.profile.update({
    where: { id: user.id },
    data: {
      ...(input.name !== undefined && { name: input.name }),
      ...(input.phone !== undefined && { phone: encryptPhone(input.phone) }),
    },
  });

  await logAuditEventFromRequest(req, {
    actorId: user.id,
    action: 'USER_PROFILE_UPDATED',
    entity: 'Profile',
    entityId: user.id,
    metadata: {
      updatedFields: Object.keys(input),
    },
  });

  return successResponse(
    {
      id: updatedProfile.id,
      email: updatedProfile.email,
      name: updatedProfile.name,
      phone: decryptPhone(updatedProfile.phone),
      role: updatedProfile.role,
    },
    requestId
  );
});
