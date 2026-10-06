import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { productIdParamSchema, createVariantSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { prisma } from '@/lib/db/prisma';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * GET /api/admin/products/[id]/variants
 * Admin endpoint to list all variants of a product with exact stock counts.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = productIdParamSchema.parse(resolvedParams);

  const variants = await prisma.productVariant.findMany({
    where: { productId: id },
    orderBy: [{ size: 'asc' }, { color: 'asc' }],
  });

  return successResponse(variants, requestId);
});

/**
 * POST /api/admin/products/[id]/variants
 * Admin endpoint to create a new variant for a product.
 * Validated with Zod strict schema and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const POST = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = productIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = createVariantSchema.parse({ ...body, productId: id });

  const variant = await catalogService.createVariant(adminUser, id, input);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_VARIANT_CREATED',
    entity: 'ProductVariant',
    entityId: variant.id,
    metadata: {
      productId: id,
      sku: variant.sku,
      size: variant.size,
      color: variant.color,
      priceInCents: variant.priceInCents,
      stockQuantity: variant.stockQuantity,
    },
  });

  return successResponse(variant, requestId, undefined, 201);
});
