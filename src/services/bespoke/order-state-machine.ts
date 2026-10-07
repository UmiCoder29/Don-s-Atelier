import { CustomOrderStatus, Role } from '@prisma/client';
import { ConflictError, ForbiddenError } from '@/lib/errors/api-error';

/**
 * Terminal states in the bespoke custom order lifecycle.
 * No outgoing transitions are permitted once an order reaches a terminal state.
 */
export const TERMINAL_STATUSES: ReadonlySet<CustomOrderStatus> = new Set([
  CustomOrderStatus.DELIVERED,
  CustomOrderStatus.REJECTED,
]);

/**
 * Allowed status transitions for Don's Atelier bespoke custom suit pipeline.
 * Maps current status to an array of valid target statuses.
 */
export const ALLOWED_TRANSITIONS: Readonly<Record<CustomOrderStatus, readonly CustomOrderStatus[]>> = {
  [CustomOrderStatus.SUBMITTED]: [
    CustomOrderStatus.IN_REVIEW,
    CustomOrderStatus.REJECTED,
  ],
  [CustomOrderStatus.IN_REVIEW]: [
    CustomOrderStatus.QUOTED,
    CustomOrderStatus.REJECTED,
  ],
  [CustomOrderStatus.QUOTED]: [
    CustomOrderStatus.ACCEPTED,
    CustomOrderStatus.REJECTED,
    CustomOrderStatus.QUOTED, // Re-quoting by Admin
  ],
  [CustomOrderStatus.ACCEPTED]: [
    CustomOrderStatus.IN_PRODUCTION,
    CustomOrderStatus.REJECTED, // Customer withdraw before production or Admin cancellation
  ],
  [CustomOrderStatus.IN_PRODUCTION]: [
    CustomOrderStatus.READY,
  ],
  [CustomOrderStatus.READY]: [
    CustomOrderStatus.DELIVERED,
  ],
  [CustomOrderStatus.DELIVERED]: [],
  [CustomOrderStatus.REJECTED]: [],
};

/**
 * Role permissions required for each valid transition.
 * Maps [fromStatus][toStatus] to the allowed roles.
 */
export const TRANSITION_ROLES: Readonly<
  Record<CustomOrderStatus, Partial<Record<CustomOrderStatus, readonly Role[]>>>
> = {
  [CustomOrderStatus.SUBMITTED]: {
    [CustomOrderStatus.IN_REVIEW]: [Role.ADMIN],
    [CustomOrderStatus.REJECTED]: [Role.CUSTOMER, Role.ADMIN],
  },
  [CustomOrderStatus.IN_REVIEW]: {
    [CustomOrderStatus.QUOTED]: [Role.ADMIN],
    [CustomOrderStatus.REJECTED]: [Role.CUSTOMER, Role.ADMIN],
  },
  [CustomOrderStatus.QUOTED]: {
    [CustomOrderStatus.ACCEPTED]: [Role.CUSTOMER], // Customer only! Admin cannot accept for customer
    [CustomOrderStatus.REJECTED]: [Role.CUSTOMER, Role.ADMIN], // Customer decline/withdraw or Admin cancel
    [CustomOrderStatus.QUOTED]: [Role.ADMIN], // Re-quote is Admin only
  },
  [CustomOrderStatus.ACCEPTED]: {
    [CustomOrderStatus.IN_PRODUCTION]: [Role.ADMIN],
    [CustomOrderStatus.REJECTED]: [Role.CUSTOMER, Role.ADMIN], // Customer withdraw before production
  },
  [CustomOrderStatus.IN_PRODUCTION]: {
    [CustomOrderStatus.READY]: [Role.ADMIN],
  },
  [CustomOrderStatus.READY]: {
    [CustomOrderStatus.DELIVERED]: [Role.ADMIN],
  },
  [CustomOrderStatus.DELIVERED]: {},
  [CustomOrderStatus.REJECTED]: {},
};

/**
 * Central State Machine Validator for bespoke custom order status transitions.
 *
 * Rules:
 * 1. Terminal states (DELIVERED, REJECTED) allow no outgoing transitions -> throws 409 Conflict.
 * 2. Any illegal jump not in ALLOWED_TRANSITIONS -> throws 409 Conflict.
 * 3. Role authorization rules:
 *    - Customer attempting an Admin transition -> throws 403 Forbidden.
 *    - Admin attempting to accept on behalf of a Customer -> throws 403 Forbidden.
 *
 * @param fromStatus The current status of the order in the database
 * @param toStatus The desired target status
 * @param role The role of the authenticated actor attempting the transition
 */
export function validateStatusTransition(
  fromStatus: CustomOrderStatus,
  toStatus: CustomOrderStatus,
  role: Role
): void {
  // 1. Terminal state check
  if (TERMINAL_STATUSES.has(fromStatus)) {
    throw new ConflictError(
      `Cannot transition custom order from terminal status: ${fromStatus}`
    );
  }

  // 2. Structural transition graph check
  const allowedTargets = ALLOWED_TRANSITIONS[fromStatus] || [];
  if (!allowedTargets.includes(toStatus)) {
    throw new ConflictError(
      `Invalid status transition from ${fromStatus} to ${toStatus}`
    );
  }

  // 3. Role authorization check
  const allowedRoles = TRANSITION_ROLES[fromStatus]?.[toStatus] || [];
  if (!allowedRoles.includes(role)) {
    if (role === Role.ADMIN) {
      throw new ForbiddenError(
        'Administrators cannot accept quotations on behalf of customers'
      );
    }
    throw new ForbiddenError(
      `Customers do not have permission to transition orders from ${fromStatus} to ${toStatus}`
    );
  }
}

/**
 * Helper to determine if a transition is structurally valid (regardless of role).
 */
export function isTransitionStructurallyValid(
  fromStatus: CustomOrderStatus,
  toStatus: CustomOrderStatus
): boolean {
  if (TERMINAL_STATUSES.has(fromStatus)) {
    return false;
  }
  const allowedTargets = ALLOWED_TRANSITIONS[fromStatus] || [];
  return allowedTargets.includes(toStatus);
}
