import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, updateCustomOrderSchema, withdrawCustomOrderSchema, WithdrawCustomOrderInput } from '@/services/bespoke/types';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * GET /api/custom-orders/[id]
 * Retrieves details of a specific bespoke order. Enforces assertOwnerOrAdmin.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const order = await bespokeService.getCustomOrderById(user, id);
  return successResponse(order, requestId);
});

/**
 * PATCH /api/custom-orders/[id]
 * Updates status, notes, or quotes price. Price quotation strictly requires ADMIN role.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = updateCustomOrderSchema.parse(body);

  const updatedOrder = await bespokeService.updateCustomOrder(user, id, input);
  return successResponse(updatedOrder, requestId);
});

/**
 * DELETE /api/custom-orders/[id]
 * Withdraws a bespoke custom suit request before production.
 */
export const DELETE = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  let input: WithdrawCustomOrderInput | undefined;
  try {
    const raw = await req.json();
    input = withdrawCustomOrderSchema.parse(raw);
  } catch {
    // Body is optional for DELETE
  }

  const withdrawnOrder = await bespokeService.withdrawCustomOrder(user, id, input);
  return successResponse(withdrawnOrder, requestId);
});
