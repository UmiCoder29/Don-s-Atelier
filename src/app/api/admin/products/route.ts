import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { createProductSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

/**
 * GET /api/admin/products
 * Admin endpoint to list all products (DRAFT, ACTIVE, ARCHIVED) with exact stock counts.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const page = searchParams.get('page') ? parseInt(searchParams.get('page')!, 10) : 1;
  const limit = searchParams.get('limit') ? parseInt(searchParams.get('limit')!, 10) : 20;
  const search = searchParams.get('search') ?? undefined;

  const result = await catalogService.adminListProducts({ page, limit, search });
  return successResponse(result.products, requestId, { pagination: result.pagination });
});

/**
 * POST /api/admin/products
 * Admin endpoint to create a new suit product in the catalog.
 * Validated with Zod strict schema and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const body = await req.json();
  const input = createProductSchema.parse(body);

  const product = await catalogService.createProduct(adminUser, input);

  // Record audit log for product creation
  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_PRODUCT_CREATED',
    entity: 'Product',
    entityId: product.id,
    metadata: {
      name: product.name,
      slug: product.slug,
      categoryId: product.categoryId,
      status: product.status,
    },
  });

  return successResponse(product, requestId, undefined, 201);
});
