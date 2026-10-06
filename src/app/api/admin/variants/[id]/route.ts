import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { variantIdParamSchema, updateVariantSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';
import { prisma } from '@/lib/db/prisma';
import { NotFoundError } from '@/lib/errors/api-error';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * GET /api/admin/variants/[id]
 * Admin endpoint to retrieve variant details with exact stock count.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = variantIdParamSchema.parse(resolvedParams);

  const variant = await prisma.productVariant.findUnique({
    where: { id },
    include: { product: true },
  });

  if (!variant) {
    throw new NotFoundError(`Variant '${id}'`);
  }

  return successResponse(variant, requestId);
});

/**
 * PATCH /api/admin/variants/[id]
 * Admin endpoint to update variant attributes (size, color, sku, price, active state).
 * Validated with Zod strict schema and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = variantIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = updateVariantSchema.parse(body);

  const updatedVariant = await catalogService.updateVariant(adminUser, id, input);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_VARIANT_UPDATED',
    entity: 'ProductVariant',
    entityId: id,
    metadata: { ...input },
  });

  return successResponse(updatedVariant, requestId);
});
