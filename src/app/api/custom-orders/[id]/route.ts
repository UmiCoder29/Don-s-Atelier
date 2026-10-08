import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, customerEditCustomOrderSchema } from '@/services/bespoke/types';

interface RouteContext {
  params: Promise<{ id: string }>;
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
 * Allows customer to edit non-status fields (e.g. description, preferences)
 * strictly while order is in SUBMITTED status.
 * All status, pricing, and administrative actions must use dedicated routes.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = customerEditCustomOrderSchema.parse(body);

  const updatedOrder = await bespokeService.customerEditCustomOrder(user, id, input);
  return successResponse(updatedOrder, requestId);
});
