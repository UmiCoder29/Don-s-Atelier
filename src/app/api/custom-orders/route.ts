import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { createCustomOrderSchema, listCustomOrdersQuerySchema } from '@/services/bespoke/types';
import { CustomOrderStatus } from '@prisma/client';

/**
 * GET /api/custom-orders
 * Lists bespoke custom suit requests for authenticated user (or all requests for ADMIN).
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const { searchParams } = new URL(req.url);

  const rawStatus = searchParams.get('status');
  const query = listCustomOrdersQuerySchema.parse({
    page: searchParams.get('page') ?? undefined,
    limit: searchParams.get('limit') ?? undefined,
    status: rawStatus ? (rawStatus as CustomOrderStatus) : undefined,
  });

  const result = await bespokeService.listCustomOrders(user, query);
  return successResponse(result.customOrders, requestId, { pagination: result.pagination });
});

/**
 * POST /api/custom-orders
 * Submits a new bespoke suit tailoring request.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const body = await req.json();
  const input = createCustomOrderSchema.parse(body);

  const customOrder = await bespokeService.createCustomOrder(user, input);
  return successResponse(customOrder, requestId, {}, 201);
});
