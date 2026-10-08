import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { Role } from '@prisma/client';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { orderService } from '@/services/order/order-service';
import { orderIdParamSchema } from '@/services/order/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/orders/[id]
 * Retrieves single order details. Enforces assertOwnerOrAdmin in service layer.
 * If accessed by an administrator who does not own the order, logs an ADMIN_ORDER_VIEWED
 * audit entry containing admin ID and order ID only (zero decrypted address text).
 * If accessed by the order owner, no ADMIN_ORDER_VIEWED audit entry is written.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const order = await orderService.getOrderById(user, id);

  if (user.role === Role.ADMIN && user.id !== order.profileId) {
    await logAuditEventFromRequest(req, {
      actorId: user.id,
      action: 'ADMIN_ORDER_VIEWED',
      entity: 'Order',
      entityId: id,
      metadata: {
        adminId: user.id,
        orderId: id,
      },
    });
  }

  return successResponse(order, requestId);
});
