import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { OrderStatus, CustomOrderStatus, Prisma } from '@prisma/client';

const adminSummaryQuerySchema = z
  .object({
    startDate: z.string().optional(),
    endDate: z.string().optional(),
  })
  .strict();

/**
 * GET /api/admin/summary
 * Aggregate metrics dashboard for atelier administration:
 * - Total sales for PAID orders only (integer cents)
 * - Order counts by status
 * - Low-stock variant count (stock <= 3)
 * - Pending bespoke custom requests count (SUBMITTED)
 * Purely aggregated calculations: ZERO PII or personal data in response.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const rawQuery: Record<string, string> = {};
  searchParams.forEach((val, key) => {
    rawQuery[key] = val;
  });

  const query = adminSummaryQuerySchema.parse(rawQuery);

  const paidWhere: Prisma.OrderWhereInput = {
    status: OrderStatus.PAID,
  };

  if (query.startDate || query.endDate) {
    paidWhere.createdAt = {};
    if (query.startDate) {
      paidWhere.createdAt.gte = new Date(query.startDate);
    }
    if (query.endDate) {
      paidWhere.createdAt.lte = new Date(query.endDate);
    }
  }

  // 1. Sales total for PAID orders only
  const salesAggregate = await prisma.order.aggregate({
    where: paidWhere,
    _sum: {
      totalInCents: true,
    },
    _count: {
      id: true,
    },
  });

  // 2. Order counts by status (initializes all OrderStatus keys to 0)
  const ordersGrouped = await prisma.order.groupBy({
    by: ['status'],
    _count: {
      _all: true,
    },
  });

  const orderCountsByStatus: Record<OrderStatus, number> = {
    [OrderStatus.PENDING]: 0,
    [OrderStatus.PAID]: 0,
    [OrderStatus.PROCESSING]: 0,
    [OrderStatus.SHIPPED]: 0,
    [OrderStatus.DELIVERED]: 0,
    [OrderStatus.CANCELLED]: 0,
    [OrderStatus.REFUNDED]: 0,
  };

  for (const group of ordersGrouped) {
    orderCountsByStatus[group.status] = group._count._all;
  }

  // 3. Low-stock variant count (active variants with stock <= 3)
  const lowStockVariantCount = await prisma.productVariant.count({
    where: {
      stockQuantity: { lte: 3 },
      active: true,
    },
  });

  // 4. Count of pending bespoke custom requests (SUBMITTED)
  const pendingCustomRequestsCount = await prisma.customOrder.count({
    where: {
      status: CustomOrderStatus.SUBMITTED,
    },
  });

  const summary = {
    salesTotalInCents: salesAggregate._sum.totalInCents ?? 0,
    paidOrderCount: salesAggregate._count.id ?? 0,
    orderCountsByStatus,
    lowStockVariantCount,
    pendingCustomRequestsCount,
  };

  return successResponse(summary, requestId);
});
