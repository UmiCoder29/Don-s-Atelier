import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, acceptCustomOrderQuoteSchema, AcceptCustomOrderQuoteInput } from '@/services/bespoke/types';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * POST /api/custom-orders/[id]/accept
 * Customer accepts formal quotation for their bespoke suit request.
 *
 * Concurrency & Quote Safety:
 * - Uses row lock (FOR UPDATE).
 * - Compares expectedPriceInCents (if provided) against price on record.
 * - Rejects stale quotes with 409 Conflict if re-quoted concurrently.
 * - Administrators cannot call this on behalf of customers (403 Forbidden).
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const raw = await req.json().catch(() => ({}));
  const input = acceptCustomOrderQuoteSchema.parse(raw);

  const acceptedOrder = await bespokeService.acceptCustomOrderQuote(user, id, input);
  return successResponse(acceptedOrder, requestId);
});
