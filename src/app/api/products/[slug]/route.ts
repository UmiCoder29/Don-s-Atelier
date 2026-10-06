import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { catalogService } from '@/services/catalog/catalog-service';
import { productSlugParamSchema } from '@/services/catalog/types';

interface RouteContext {
  params: Promise<{ slug: string }> | { slug: string };
}

/**
 * GET /api/products/[slug]
 * Public endpoint to fetch full suit details and active variants by slug.
 */
export const GET = withErrorHandler<RouteContext>(async (_req: NextRequest, context, requestId) => {
  const resolvedParams = await context.params;
  const { slug } = productSlugParamSchema.parse(resolvedParams);

  const product = await catalogService.getProductBySlug(slug);
  return successResponse(product, requestId);
});
