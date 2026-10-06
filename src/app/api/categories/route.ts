import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { catalogService } from '@/services/catalog/catalog-service';

/**
 * GET /api/categories
 * Public endpoint to list all luxury suit categories.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const categories = await catalogService.listCategories();
  return successResponse(categories, requestId);
});
