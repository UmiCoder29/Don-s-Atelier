import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { catalogService } from '@/services/catalog/catalog-service';
import { listProductsQuerySchema } from '@/services/catalog/types';

/**
 * GET /api/products
 * Public endpoint to list active suits with capped pagination, whitelisted sorting,
 * multi-attribute filtering (category, size, color, price range, fabric, text search),
 * and concealed stock quantities (inStock / lowStock flags only).
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const { searchParams } = new URL(req.url);

  const rawParams: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    rawParams[key] = value;
  });

  const query = listProductsQuerySchema.parse(rawParams);

  const result = await catalogService.listProducts(query);
  return successResponse(result.products, requestId, { pagination: result.pagination });
});
