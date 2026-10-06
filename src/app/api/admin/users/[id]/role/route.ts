import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireRole } from '@/lib/auth/supabase-auth';
import { authService } from '@/services/auth/auth-service';
import { updateRoleSchema } from '@/lib/validation/auth-schemas';
import { uuidSchema } from '@/lib/validation/zod-helpers';
import { logAuditEventFromRequest } from '@/lib/audit/audit-logger';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

const paramsSchema = z.object({
  id: uuidSchema,
}).strict();

/**
 * PATCH /api/admin/users/[id]/role
 * Updates a user's role.
 * Non-negotiable constraint: Admin role can strictly only be set by an authenticated ADMIN.
 * Protected by requireRole('ADMIN') and Next.js middleware.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const adminUser = await requireRole('ADMIN')(req);
  const resolvedParams = await context.params;
  const { id } = paramsSchema.parse(resolvedParams);
  const body = await req.json();
  const input = updateRoleSchema.parse(body);

  const updatedUser = await authService.setUserRole(adminUser, id, input);

  // Record audit log for admin write
  await logAuditEventFromRequest(req, {
    actorId: adminUser.id,
    action: 'ADMIN_ROLE_UPDATED',
    entity: 'Profile',
    entityId: id,
    metadata: {
      newRole: input.role,
      assignedByAdminId: adminUser.id,
    },
  });

  return successResponse(updatedUser, requestId);
});
