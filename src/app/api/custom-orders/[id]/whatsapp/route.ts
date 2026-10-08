import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema } from '@/services/bespoke/types';
import { generateWhatsAppHandoffUrl } from '@/services/bespoke/whatsapp-handoff';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/custom-orders/[id]/whatsapp
 * Generates direct wa.me WhatsApp handoff link.
 *
 * Privacy & Security:
 * - Expose strictly to order owner and admins (assertOwnerOrAdmin).
 * - Pre-filled text contains ONLY the request reference code and fixed greeting.
 * - Business number configured in validated env.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const order = await bespokeService.getCustomOrderById(user, id);
  const whatsappUrl = generateWhatsAppHandoffUrl(order.orderNumber);

  return successResponse({
    orderNumber: order.orderNumber,
    whatsappUrl,
  }, requestId);
});
