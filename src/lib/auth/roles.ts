import { Role } from '@prisma/client';

export { Role };

/**
 * Role hierarchy for Don's Atelier:
 * - ADMIN has full system access.
 * - CUSTOMER has access to catalog, own orders, cart, and bespoke requests.
 */
export const ROLE_HIERARCHY: Record<Role, number> = {
  CUSTOMER: 1,
  ADMIN: 2,
};

export function hasMinimumRole(userRole: Role, requiredRole: Role): boolean {
  return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[requiredRole];
}

export function isRoleAllowed(userRole: Role, allowedRoles: Role[]): boolean {
  return allowedRoles.includes(userRole);
}
