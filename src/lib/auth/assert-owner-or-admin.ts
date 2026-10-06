import { Role } from '@prisma/client';
import { AuthenticatedUser } from './supabase-auth';
import { ForbiddenError, UnauthorizedError } from '@/lib/errors/api-error';

/**
 * Prisma connects with a server role that bypasses RLS, so every service function must also enforce ownership/role in code. Implement a reusable assertOwnerOrAdmin helper.
 *
 * Verifies that the authenticated user either owns the resource (user.id === resourceOwnerId)
 * or holds the ADMIN role. Throws ForbiddenError if neither condition is met.
 *
 * @param user The authenticated user object extracted from the request token
 * @param resourceOwnerId The user/profile ID that owns the target resource
 * @param customMessage Optional custom error message for access denial
 */
export function assertOwnerOrAdmin(
  user: AuthenticatedUser | null | undefined,
  resourceOwnerId: string,
  customMessage?: string
): asserts user is AuthenticatedUser {
  if (!user) {
    throw new UnauthorizedError('Authentication required to access this resource');
  }

  // Admins possess elevated privileges across all customer resources
  if (user.role === Role.ADMIN) {
    return;
  }

  // Customers are strictly isolated to their own records
  if (user.id === resourceOwnerId) {
    return;
  }

  throw new ForbiddenError(
    customMessage || 'You do not have permission to access or modify this resource'
  );
}
