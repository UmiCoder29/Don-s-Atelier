import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { sanitizeText } from '@/lib/validation/sanitizer';

const listAdminUsersQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1).optional(),
    limit: z.coerce.number().int().min(1).max(100, 'Page size cannot exceed 100').default(20).optional(),
    search: z
      .string()
      .max(100, 'Search query cannot exceed 100 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict();

/**
 * GET /api/admin/users
 * Lists customer profiles with NON-sensitive fields only (no phone, no address, no measurements).
 * Search by email or name, paginated with hard max limit of 100.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const rawQuery: Record<string, string> = {};
  searchParams.forEach((val, key) => {
    rawQuery[key] = val;
  });

  const query = listAdminUsersQuerySchema.parse(rawQuery);

  const page = query.page ?? 1;
  const limit = Math.min(100, query.limit ?? 20);
  const search = query.search?.trim();
  const skip = (page - 1) * limit;

  const whereClause = search
    ? {
        OR: [
          { email: { contains: search, mode: 'insensitive' as const } },
          { name: { contains: search, mode: 'insensitive' as const } },
        ],
      }
    : {};

  const [users, totalCount] = await Promise.all([
    prisma.profile.findMany({
      where: whereClause,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.profile.count({ where: whereClause }),
  ]);

  return successResponse(users, requestId, {
    pagination: {
      page,
      limit,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
    },
  });
});
