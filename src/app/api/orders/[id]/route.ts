import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { orderService } from '@/services/order/order-service';
import { orderIdParamSchema, updateOrderStatusSchema } from '@/services/order/types';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * GET /api/orders/[id]
 * Retrieves single order details. Enforces assertOwnerOrAdmin in service layer.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const order = await orderService.getOrderById(user, id);
  return successResponse(order, requestId);
});

/**
 * PATCH /api/orders/[id]
 * Updates order status:
 * - If status is CANCELLED: allowed before PROCESSING, restoring inventory stock.
 * - If advancing to PROCESSING, SHIPPED, etc.: restricted to atelier administrators.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = updateOrderStatusSchema.parse(body);

  const updatedOrder = await orderService.updateOrderStatus(user, id, input.status);
  return successResponse(updatedOrder, requestId);
});

