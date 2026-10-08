import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { orderService } from '@/services/order/order-service';
import { orderIdParamSchema, adminUpdateOrderStatusSchema } from '@/services/order/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/admin/orders/[id]
 * Admin order detail view with decrypted shipping address and audit status history.
 * Logs ADMIN_ORDER_VIEWED audit entry containing only admin ID and order ID (zero decrypted data).
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const order = await orderService.adminGetOrderById(adminUser, id);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_ORDER_VIEWED',
    entity: 'Order',
    entityId: id,
    metadata: {
      adminId: adminUser.id,
      orderId: id,
    },
  });

  return successResponse(order, requestId);
});

/**
 * PATCH /api/admin/orders/[id]
 * Updates order status through central state machine.
 * Restocks inventory on CANCELLED or REFUNDED exactly once (idempotent under row lock).
 * Strict Zod rejects unknown fields (422) and requires reason for PENDING -> PAID.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = adminUpdateOrderStatusSchema.parse(body);
  const effectiveReason = input.reason || input.note;

  const updatedOrder = await orderService.adminUpdateOrderStatus(
    adminUser,
    id,
    input.status,
    effectiveReason
  );

  return successResponse(updatedOrder, requestId);
});
