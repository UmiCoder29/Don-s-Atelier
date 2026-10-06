import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, withdrawCustomOrderSchema, WithdrawCustomOrderInput } from '@/services/bespoke/types';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * POST /api/custom-orders/[id]/withdraw
 * Customer withdraws their bespoke custom suit request before production.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  let input: WithdrawCustomOrderInput | undefined;
  try {
    const body = await req.json();
    input = withdrawCustomOrderSchema.parse(body);
  } catch {
    // Body is optional for withdrawal
  }

  const withdrawnOrder = await bespokeService.withdrawCustomOrder(user, id, input);
  return successResponse(withdrawnOrder, requestId);
});
