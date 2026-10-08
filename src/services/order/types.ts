import { z } from 'zod';
import { paginationSchema, uuidSchema } from '@/lib/validation/zod-helpers';
import { OrderStatus } from '@prisma/client';
export { shippingAddressSchema, type ShippingAddress } from '@/lib/validation/zod-helpers';

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

export const adminListOrdersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1).optional(),
  limit: z.coerce.number().int().min(1).max(100, 'Page size cannot exceed 100').default(20).optional(),
  status: z.nativeEnum(OrderStatus).optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  search: z.string().max(100).optional(),
}).strict();

export type AdminListOrdersQuery = z.infer<typeof adminListOrdersQuerySchema>;

export const adminUpdateOrderStatusSchema = z
  .object({
    status: z.nativeEnum(OrderStatus),
    reason: z
      .string()
      .trim()
      .min(1, 'Reason cannot be empty')
      .max(500, 'Reason cannot exceed 500 characters')
      .optional(),
    note: z
      .string()
      .trim()
      .max(500, 'Note cannot exceed 500 characters')
      .optional(),
  })
  .strict()
  .refine(
    (data) => {
      if (data.status === OrderStatus.PAID) {
        const effectiveReason = (data.reason || data.note || '').trim();
        return effectiveReason.length > 0;
      }
      return true;
    },
    {
      message: 'Reason is required when moving order to PAID',
      path: ['reason'],
    }
  );

export type AdminUpdateOrderStatusInput = z.infer<typeof adminUpdateOrderStatusSchema>;

