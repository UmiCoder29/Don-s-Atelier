import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { productIdParamSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * POST /api/admin/products/[id]/archive
 * Dedicated RPC endpoint to archive a product.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
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
