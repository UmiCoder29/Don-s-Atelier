import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { Prisma } from '@prisma/client';

const listAuditLogsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1).optional(),
    limit: z.coerce.number().int().min(1).max(100, 'Page size cannot exceed 100').default(20).optional(),
    actorId: z.string().max(100).optional(),
    action: z.string().max(100).optional(),
    entity: z.string().max(100).optional(),
    startDate: z.string().optional(),
    endDate: z.string().optional(),
  })
  .strict();

/**
 * GET /api/admin/audit-logs
 * Read-only audit trail query for administrators.
 * Filters by actor, action, entity, date range.
 * Hard pagination limit of 100.
 * Immutable: No POST, PUT, PATCH, or DELETE endpoints exist for audit logs.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const rawQuery: Record<string, string> = {};
  searchParams.forEach((val, key) => {
    rawQuery[key] = val;
  });

  const query = listAuditLogsQuerySchema.parse(rawQuery);

  const page = query.page ?? 1;
  const limit = Math.min(100, query.limit ?? 20);
  const skip = (page - 1) * limit;

  const where: Prisma.AuditLogWhereInput = {};

  if (query.actorId) {
    where.actorId = query.actorId;
  }

  if (query.action) {
    where.action = query.action;
  }

  if (query.entity) {
    where.entity = query.entity;
  }

  if (query.startDate || query.endDate) {
    where.timestamp = {};
    if (query.startDate) {
      where.timestamp.gte = new Date(query.startDate);
    }
    if (query.endDate) {
      where.timestamp.lte = new Date(query.endDate);
    }
  }

  const [logs, totalCount] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      skip,
      take: limit,
      orderBy: { timestamp: 'desc' },
    }),
    prisma.auditLog.count({ where }),
  ]);

  return successResponse(logs, requestId, {
    pagination: {
      page,
      limit,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
    },
  });
});
