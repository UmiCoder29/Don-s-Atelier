import { z } from 'zod';
import { uuidSchema } from '@/lib/validation/zod-helpers';

/**
 * Maximum quantity allowed per individual line item variant in the cart.
 */
export const MAX_LINE_ITEM_QUANTITY = 5;

/**
 * Maximum number of distinct line items allowed in a single customer cart.
 */
export const MAX_DISTINCT_CART_ITEMS = 10;

/**
 * Availability status for an individual line item in the customer's cart.
 * - OK: Variant is active, product is ACTIVE, and stock >= quantity.
 * - UNAVAILABLE: Variant is inactive or product status is not ACTIVE (e.g. ARCHIVED or DRAFT).
 * - INSUFFICIENT_STOCK: Product and variant are active, but available stock is less than quantity.
 */
export type CartItemStatus = 'OK' | 'UNAVAILABLE' | 'INSUFFICIENT_STOCK';

export const addToCartSchema = z
  .object({
    productVariantId: uuidSchema,
    quantity: z
      .number({ required_error: 'Quantity is required' })
      .int('Quantity must be an integer')
      .min(1, 'Quantity must be at least 1')
      .max(MAX_LINE_ITEM_QUANTITY, `Maximum ${MAX_LINE_ITEM_QUANTITY} items per variant`)
      .default(1),
  })
  .strict();

export type AddToCartInput = z.infer<typeof addToCartSchema>;

export const updateCartItemSchema = z
  .object({
    quantity: z
      .number({ required_error: 'Quantity is required' })
      .int('Quantity must be an integer')
      .min(0, 'Quantity cannot be negative')
      .max(MAX_LINE_ITEM_QUANTITY, `Maximum ${MAX_LINE_ITEM_QUANTITY} items per variant`),
  })
  .strict();

export type UpdateCartItemInput = z.infer<typeof updateCartItemSchema>;

