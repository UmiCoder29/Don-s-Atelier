import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { orderService } from '@/services/order/order-service';
import { orderIdParamSchema } from '@/services/order/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * POST /api/orders/[id]/cancel
 * Customer order cancellation:
 * - Allowed ONLY before PROCESSING (i.e. PENDING or PAID).
 * - Restores inventory stock for all order items in an atomic transaction.
 * - Processes refund if payment was already captured.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = orderIdParamSchema.parse(resolvedParams);

  const order = await orderService.cancelOrder(user, id);
  return successResponse(order, requestId, {}, 200);
});
