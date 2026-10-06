import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { prisma } from '@/lib/db/prisma';
import { paginationSchema } from '@/lib/validation/zod-helpers';
import { sanitizeText } from '@/lib/validation/sanitizer';
import { decryptPhone } from '@/lib/crypto/field-encryption';

export const listAdminUsersQuerySchema = paginationSchema.extend({
  search: z
    .string()
    .max(100, 'Search query cannot exceed 100 characters')
    .optional()
    .transform((val) => (val ? sanitizeText(val) : undefined)),
}).strict();

/**
 * GET /api/admin/users
 * Lists user profiles for admin user management.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  await requireRole('ADMIN')(req);

  const { searchParams } = new URL(req.url);
  const query = listAdminUsersQuerySchema.parse({
    page: searchParams.get('page') ?? undefined,
    limit: searchParams.get('limit') ?? undefined,
    search: searchParams.get('search') ?? undefined,
  });

  const page = query.page;
  const limit = Math.min(50, query.limit);
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
        phone: true,
        role: true,
        createdAt: true,
      },
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.profile.count({ where: whereClause }),
  ]);

  const sanitizedUsers = users.map((u) => ({
    ...u,
    phone: decryptPhone(u.phone),
  }));

  return successResponse(sanitizedUsers, requestId, {
    pagination: {
      page,
      limit,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
    },
  });
});
