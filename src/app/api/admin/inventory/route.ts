import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { listInventoryQuerySchema } from '@/services/catalog/types';

/**
 * GET /api/admin/inventory
 * View stock per variant, with optional low-stock filter and search.
 * Hard limit of 100 on pagination.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const rawQuery: Record<string, string> = {};
  searchParams.forEach((val, key) => {
    rawQuery[key] = val;
  });

  const query = listInventoryQuerySchema.parse(rawQuery);

  const result = await catalogService.listInventory(adminUser, {
    page: query.page,
    limit: query.limit,
    lowStock: query.lowStock,
    search: query.search,
  });

  return successResponse(result.variants, requestId, {
    pagination: result.pagination,
  });
});
