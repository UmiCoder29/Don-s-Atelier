import { NextRequest } from 'next/server';
import { Role } from '@prisma/client';
import { supabaseAdmin } from '@/lib/db/supabase';
import { prisma } from '@/lib/db/prisma';
import { UnauthorizedError, ForbiddenError } from '@/lib/errors/api-error';
import { getAccessTokenFromRequest } from './cookies';

export { Role };

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: Role;
  name?: string | null;
  fullName?: string | null;
  emailConfirmed: boolean;
  emailConfirmedAt?: string | null;
}

export interface SessionData {
  user: AuthenticatedUser;
  token: string;
}

export type RoleInput = Role | 'ADMIN' | 'CUSTOMER';

/**
 * Extracts and verifies the authentication session from the request.
 * Checks both httpOnly cookie ('sb-access-token') and Authorization header ('Bearer <token>').
 * Returns the session and authenticated user profile, or null if unauthenticated.
 */
export async function getSession(req: NextRequest): Promise<SessionData | null> {
  const token = getAccessTokenFromRequest(req);
  if (!token) {
    return null;
  }

  // Verify JWT securely with Supabase Auth
  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !user || !user.email) {
    return null;
  }

  // Fetch or upsert corresponding profile from Postgres
  let profile = await prisma.profile.findUnique({
    where: { id: user.id },
  });

  if (!profile) {
    const displayName = (user.user_metadata?.full_name || user.user_metadata?.name || '') as string;
    profile = await prisma.profile.create({
      data: {
        id: user.id,
        email: user.email,
        name: displayName || null,
        role: Role.CUSTOMER, // Strict: Default signup role is always CUSTOMER
      },
    });
  }

  const authenticatedUser: AuthenticatedUser = {
    id: profile.id,
    email: profile.email,
    role: profile.role,
    name: profile.name,
    fullName: profile.name,
    emailConfirmed: Boolean(user.email_confirmed_at),
    emailConfirmedAt: user.email_confirmed_at,
  };

  return {
    user: authenticatedUser,
    token,
  };
}

/**
 * Backwards-compatible helper returning the AuthenticatedUser or null.
 */
export async function getAuthUser(req: NextRequest): Promise<AuthenticatedUser | null> {
  const session = await getSession(req);
  return session ? session.user : null;
}

/**
 * Enforces that the request comes from an authenticated user.
 * Throws UnauthorizedError (401) if authentication is missing, invalid, or expired.
 */
export async function requireAuth(req: NextRequest): Promise<AuthenticatedUser> {
  const session = await getSession(req);
  if (!session) {
    throw new UnauthorizedError('Authentication token is missing, expired, or invalid');
  }
  return session.user;
}

/**
 * Enforces role-based access control.
 * Supports both curried syntax: requireRole('ADMIN')(req)
 * and direct syntax: requireRole(req, 'ADMIN') or requireRole(req, [Role.ADMIN])
 */
export function requireRole(
  allowedRole: RoleInput | RoleInput[]
): (req: NextRequest) => Promise<AuthenticatedUser>;
export function requireRole(
  req: NextRequest,
  allowedRole: RoleInput | RoleInput[]
): Promise<AuthenticatedUser>;
export function requireRole(
  arg1: NextRequest | RoleInput | RoleInput[],
  arg2?: RoleInput | RoleInput[]
): ((req: NextRequest) => Promise<AuthenticatedUser>) | Promise<AuthenticatedUser> {
  // If first argument is NextRequest, execute directly
  if (arg1 instanceof NextRequest || (arg1 && typeof arg1 === 'object' && 'headers' in arg1)) {
    const req = arg1 as NextRequest;
    const allowed = Array.isArray(arg2) ? arg2 : [arg2!];
    return (async () => {
      const user = await requireAuth(req);
      const rolesList = allowed.map((r) => String(r));
      if (!rolesList.includes(String(user.role))) {
        throw new ForbiddenError(
          `Access denied. Requires one of roles: ${rolesList.join(', ')}`
        );
      }
      return user;
    })();
  }

  // Curried factory: returns async handler
  const allowed = Array.isArray(arg1) ? arg1 : [arg1];
  return async (req: NextRequest): Promise<AuthenticatedUser> => {
    const user = await requireAuth(req);
    const rolesList = allowed.map((r) => String(r));
    if (!rolesList.includes(String(user.role))) {
      throw new ForbiddenError(
        `Access denied. Requires one of roles: ${rolesList.join(', ')}`
      );
    }
    return user;
  };
}

/**
 * Enforces that the request comes from an authenticated user whose email is verified.
 * Throws ForbiddenError (403) if the email address is unverified.
 */
export async function requireVerifiedUser(req: NextRequest): Promise<AuthenticatedUser> {
  const user = await requireAuth(req);
  if (!user.emailConfirmed) {
    throw new ForbiddenError('Email address must be verified before checking out');
  }
  return user;
}
