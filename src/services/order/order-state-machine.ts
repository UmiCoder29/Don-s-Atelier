import { OrderStatus, Role } from '@prisma/client';
import { ConflictError, ForbiddenError } from '@/lib/errors/api-error';

/**
 * Terminal statuses from which no outbound transitions are permitted.
 */
export const ORDER_TERMINAL_STATUSES: OrderStatus[] = [
  OrderStatus.CANCELLED,
  OrderStatus.REFUNDED,
];

/**
 * Legal transition graph for standard e-commerce orders.
 */
export const LEGAL_ORDER_TRANSITIONS: Record<OrderStatus, OrderStatus[]> = {
  [OrderStatus.PENDING]: [
    OrderStatus.PAID,
    OrderStatus.CANCELLED,
  ],
  [OrderStatus.PAID]: [
    OrderStatus.PROCESSING,
    OrderStatus.CANCELLED,
    OrderStatus.REFUNDED,
  ],
  [OrderStatus.PROCESSING]: [
    OrderStatus.SHIPPED,
    OrderStatus.CANCELLED,
    OrderStatus.REFUNDED,
  ],
  [OrderStatus.SHIPPED]: [
    OrderStatus.DELIVERED,
    OrderStatus.REFUNDED,
  ],
  [OrderStatus.DELIVERED]: [
    OrderStatus.REFUNDED,
  ],
  [OrderStatus.CANCELLED]: [],
  [OrderStatus.REFUNDED]: [],
};

/**
 * Role-based authorization matrix for standard order status transitions.
 */
export const ORDER_TRANSITION_PERMISSIONS: Record<
  OrderStatus,
  Partial<Record<OrderStatus, Role[]>>
> = {
  [OrderStatus.PENDING]: {
    [OrderStatus.PAID]: [Role.ADMIN],
    [OrderStatus.CANCELLED]: [Role.CUSTOMER, Role.ADMIN],
  },
  [OrderStatus.PAID]: {
    [OrderStatus.PROCESSING]: [Role.ADMIN],
    [OrderStatus.CANCELLED]: [Role.CUSTOMER, Role.ADMIN],
    [OrderStatus.REFUNDED]: [Role.ADMIN],
  },
  [OrderStatus.PROCESSING]: {
    [OrderStatus.SHIPPED]: [Role.ADMIN],
    [OrderStatus.CANCELLED]: [Role.ADMIN],
    [OrderStatus.REFUNDED]: [Role.ADMIN],
  },
  [OrderStatus.SHIPPED]: {
    [OrderStatus.DELIVERED]: [Role.ADMIN],
    [OrderStatus.REFUNDED]: [Role.ADMIN],
  },
  [OrderStatus.DELIVERED]: {
    [OrderStatus.REFUNDED]: [Role.ADMIN],
  },
  [OrderStatus.CANCELLED]: {},
  [OrderStatus.REFUNDED]: {},
};

/**
 * Validates whether a proposed order status transition is permissible under the central state machine.
 * Throws ConflictError (409) if transition is illegal or order is terminal.
 * Throws ForbiddenError (403) if caller's role is not authorized.
 * Idempotent no-op transitions for terminal states (CANCELLED -> CANCELLED, REFUNDED -> REFUNDED) are allowed.
 */
export function validateOrderStatusTransition(
  currentStatus: OrderStatus,
  targetStatus: OrderStatus,
  role: Role
): void {
  // Idempotency: re-cancelling or re-refunding
  if (currentStatus === targetStatus) {
    if (currentStatus === OrderStatus.CANCELLED || currentStatus === OrderStatus.REFUNDED) {
      return;
    }
    throw new ConflictError(
      `Order is already in status '${currentStatus}'`
    );
  }

  // Terminal state protection
  if (ORDER_TERMINAL_STATUSES.includes(currentStatus)) {
    throw new ConflictError(
      `Cannot transition order from terminal status: ${currentStatus}`
    );
  }

  // Legal transition check
  const allowedTargets = LEGAL_ORDER_TRANSITIONS[currentStatus] || [];
  if (!allowedTargets.includes(targetStatus)) {
    throw new ConflictError(
      `Invalid order status transition from ${currentStatus} to ${targetStatus}`
    );
  }

  // Role authorization check
  const allowedRoles = ORDER_TRANSITION_PERMISSIONS[currentStatus]?.[targetStatus] || [];
  if (!allowedRoles.includes(role)) {
    throw new ForbiddenError(
      `Role ${role} is not authorized to transition order from ${currentStatus} to ${targetStatus}`
    );
  }
}

/**
 * Determines whether inventory stock should be replenished when transitioning between order statuses.
 * Central restock rules:
 * - CANCELLED: Restocks inventory on transition to CANCELLED from any state that allows it
 *   (PENDING, PAID, PROCESSING).
 * - REFUNDED: Restocks inventory ONLY when the previous status was PAID or PROCESSING.
 *   REFUNDED from SHIPPED or DELIVERED must NOT restock (items have left warehouse or been delivered).
 * - Idempotent re-cancellation or re-refund (from terminal status) does NOT restock.
 */
export function shouldRestockOnTransition(
  fromStatus: OrderStatus,
  toStatus: OrderStatus
): boolean {
  if (toStatus === OrderStatus.CANCELLED) {
    return (
      fromStatus === OrderStatus.PENDING ||
      fromStatus === OrderStatus.PAID ||
      fromStatus === OrderStatus.PROCESSING
    );
  }

  if (toStatus === OrderStatus.REFUNDED) {
    return fromStatus === OrderStatus.PAID || fromStatus === OrderStatus.PROCESSING;
  }

  return false;
}
