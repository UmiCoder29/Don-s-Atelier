import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { productIdParamSchema, updateProductSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/admin/products/[id]
 * Admin endpoint to retrieve full product details with exact inventory counts.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = productIdParamSchema.parse(resolvedParams);

  const product = await catalogService.adminGetProductById(id);
  return successResponse(product, requestId);
});

/**
 * PATCH /api/admin/products/[id]
 * Admin endpoint to update suit product metadata.
 * Validated with Zod strict schema and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = productIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = updateProductSchema.parse(body);

  const updatedProduct = await catalogService.updateProduct(adminUser, id, input);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_PRODUCT_UPDATED',
    entity: 'Product',
    entityId: id,
    metadata: { ...input },
  });

  return successResponse(updatedProduct, requestId);
});

/**
 * DELETE /api/admin/products/[id]
 * Admin endpoint to archive a product (soft delete via ARCHIVED status).
 * Validated and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const DELETE = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = productIdParamSchema.parse(resolvedParams);

  const archivedProduct = await catalogService.archiveProduct(adminUser, id);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_PRODUCT_ARCHIVED',
    entity: 'Product',
    entityId: id,
    metadata: {
      archivedBy: adminUser.id,
      productName: archivedProduct.name,
      slug: archivedProduct.slug,
    },
  });

  return successResponse(archivedProduct, requestId);
});
