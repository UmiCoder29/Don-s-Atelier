import { z } from 'zod';
import { paginationSchema, uuidSchema } from '@/lib/validation/zod-helpers';
import { OrderStatus } from '@prisma/client';

/**
 * Checkout request schema.
 * Only addressId from the authenticated user's address book is accepted.
 * Inline shippingAddress is intentionally removed — the server resolves,
 * decrypts, and snapshots the address itself, preventing address spoofing.
 */
export const checkoutSchema = z.object({
  /** UUID of a saved address belonging to the authenticated user. Required. */
  addressId: uuidSchema,
  /** Optional idempotency key (may also be supplied via Idempotency-Key header). */
  idempotencyKey: z.string().min(8, 'Idempotency key must be at least 8 characters').max(128, 'Idempotency key cannot exceed 128 characters').optional(),
}).strict();

export type CheckoutInput = z.infer<typeof checkoutSchema>;

export const listOrdersQuerySchema = paginationSchema.extend({
  status: z.nativeEnum(OrderStatus).optional(),
}).strict();

export type ListOrdersQuery = z.infer<typeof listOrdersQuerySchema>;

export const orderIdParamSchema = z.object({
  id: uuidSchema,
}).strict();

export const updateOrderStatusSchema = z.object({
  status: z.nativeEnum(OrderStatus),
}).strict();

export type UpdateOrderStatusInput = z.infer<typeof updateOrderStatusSchema>;
