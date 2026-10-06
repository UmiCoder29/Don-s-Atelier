import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { catalogService } from '@/services/catalog/catalog-service';
import { variantIdParamSchema, adjustStockSchema } from '@/services/catalog/types';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

/**
 * Handle stock adjustment for a variant.
 * Supports both delta adjustment ({ adjustment: +10 / -5 }) and absolute value ({ stockQuantity: 25 }).
 * Validated with Zod strict schema and audit-logged.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
async function handleStockAdjustment(req: NextRequest, context: RouteContext, requestId: string) {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = variantIdParamSchema.parse(resolvedParams);

  const body = await req.json();
  const input = adjustStockSchema.parse(body);

  const result = await catalogService.adjustStock(adminUser, id, input);

  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_STOCK_ADJUSTED',
    entity: 'ProductVariant',
    entityId: id,
    metadata: {
      variantId: id,
      previousStock: result.previousStock,
      newStock: result.newStock,
      adjustment: result.adjustment,
      reason: result.reason,
    },
  });

  return successResponse(result, requestId);
}

/**
 * POST /api/admin/variants/[id]/stock
 */
export const POST = withErrorHandler<RouteContext>(handleStockAdjustment);

/**
 * PATCH /api/admin/variants/[id]/stock
 */
export const PATCH = withErrorHandler<RouteContext>(handleStockAdjustment);
