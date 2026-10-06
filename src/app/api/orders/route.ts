import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { orderService } from '@/services/order/order-service';
import { checkoutSchema, listOrdersQuerySchema } from '@/services/order/types';
import { OrderStatus } from '@prisma/client';

/**
 * GET /api/orders
 * Retrieves list of orders for the authenticated customer (or all orders for ADMIN).
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const { searchParams } = new URL(req.url);

  const rawStatus = searchParams.get('status');
  const query = listOrdersQuerySchema.parse({
    page: searchParams.get('page') ?? undefined,
    limit: searchParams.get('limit') ?? undefined,
    status: rawStatus ? (rawStatus as OrderStatus) : undefined,
  });

  const result = await orderService.listOrders(user, query);
  return successResponse(result.orders, requestId, { pagination: result.pagination });
});

/**
 * POST /api/orders
 * Executes checkout: computes totals strictly from DB, decrements stock, creates order & payment intent.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const body = await req.json();
  const input = checkoutSchema.parse(body);

  const result = await orderService.checkout(user, input);
  return successResponse(result, requestId, {}, 201);
});
