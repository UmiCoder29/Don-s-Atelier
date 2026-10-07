import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { bespokeService } from '@/services/bespoke/bespoke-service';
import { listCustomOrdersQuerySchema } from '@/services/bespoke/types';
import { Role } from '@prisma/client';

/**
 * GET /api/admin/custom-orders
 * Lists and filters bespoke custom suit requests with pagination.
 * Exposes decrypted internal notes strictly to ADMIN role.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const adminUser = await requireRole(req, Role.ADMIN);

  const searchParams = req.nextUrl.searchParams;
  const rawQuery = {
    page: searchParams.get('page') ? Number(searchParams.get('page')) : undefined,
    limit: searchParams.get('limit') ? Number(searchParams.get('limit')) : undefined,
    status: searchParams.get('status') || undefined,
  };

  const validatedQuery = listCustomOrdersQuerySchema.parse(rawQuery);
  const result = await bespokeService.adminListCustomOrders(adminUser, validatedQuery);

  return successResponse(result.customOrders, requestId, { pagination: result.pagination });
});
