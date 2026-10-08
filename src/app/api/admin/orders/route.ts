import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { orderService } from '@/services/order/order-service';
import { adminListOrdersQuerySchema } from '@/services/order/types';

/**
 * GET /api/admin/orders
 * Admin list orders with filters (status, date range), search (orderNumber or email), and pagination.
 * Max limit capped at 100. Unknown query params rejected.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const rawQuery: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    rawQuery[key] = value;
  });

  const query = adminListOrdersQuerySchema.parse(rawQuery);

  const result = await orderService.adminListOrders(adminUser, {
    page: query.page,
    limit: query.limit,
    status: query.status,
    startDate: query.startDate,
    endDate: query.endDate,
    search: query.search,
  });

  return successResponse(result.orders, requestId, {
    pagination: result.pagination,
  });
});
