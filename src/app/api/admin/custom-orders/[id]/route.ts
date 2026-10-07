import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { customOrderIdParamSchema, adminUpdateCustomOrderSchema } from '@/services/bespoke/types';
import { Role } from '@prisma/client';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * GET /api/admin/custom-orders/[id]
 * Retrieves full details of a specific bespoke request for atelier staff.
 * Includes decrypted internal notes and measurements.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole(req, Role.ADMIN);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const order = await bespokeService.getCustomOrderById(adminUser, id);
  return successResponse(order, requestId);
});

/**
 * PATCH /api/admin/custom-orders/[id]
 * Administrative action:
 * - Moves custom order status via Central State Machine.
 * - Sets or re-quotes quotedPriceInCents (integer cents, only allowed for QUOTED status).
 * - Appends encrypted internal notes (strictly hidden from customer).
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole(req, Role.ADMIN);
  const resolvedParams = await context.params;
  const { id } = customOrderIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = adminUpdateCustomOrderSchema.parse(body);

  const updatedOrder = await bespokeService.adminUpdateCustomOrder(adminUser, id, input);
  return successResponse(updatedOrder, requestId);
});
