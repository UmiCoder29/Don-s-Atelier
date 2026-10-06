import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, addCustomOrderNoteSchema } from '@/services/bespoke/types';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * POST /api/custom-orders/[id]/messages
 * Customer adds a follow-up message or note to their bespoke custom suit request.
 * Encrypts note at field level and appends to status history audit trail.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = addCustomOrderNoteSchema.parse(body);

  const updatedOrder = await bespokeService.addNote(user, id, input);
  return successResponse(updatedOrder, requestId, {}, 200);
});
