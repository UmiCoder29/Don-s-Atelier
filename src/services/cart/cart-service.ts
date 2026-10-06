import { prisma } from '@/lib/db/prisma';
import { ProductStatus } from '@prisma/client';
import {
  NotFoundError,
  BadRequestError,
  ForbiddenError,
  ValidationError,
} from '@/lib/errors/api-error';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import {
  AddToCartInput,
  UpdateCartItemInput,
  MAX_LINE_ITEM_QUANTITY,
  MAX_DISTINCT_CART_ITEMS,
  CartItemStatus,
} from './types';

/**
 * Service managing customer shopping carts and item computations.
 * Strict Rule: Prices, subtotals, and total sums are ALWAYS calculated
 * dynamically on the server from authoritative productVariant database records.
 *
 * Architecture Note on Guest / Merge Handling:
 * Don's Atelier requires authenticated customer accounts for all cart operations.
 * Guest carts are not supported; authentication is enforced at every route handler
 * via requireAuth(req). If unauthenticated requests are received, 401 Unauthorized
 * is returned.
 */
export class CartService {
  /**
   * Retrieves or creates the customer's cart, returning computed item subtotals and overall total.
   * Problematic items (inactive/archived or out-of-stock) are flagged with their status and
   * excluded from the subtotal.
   */
  async getCart(user: AuthenticatedUser) {
    let cart = await prisma.cart.findUnique({
      where: { profileId: user.id },
      include: {
        items: {
          include: {
            productVariant: {
              include: {
                product: {
                  select: { id: true, name: true, slug: true, brand: true, status: true },
                },
              },
            },
          },
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!cart) {
      cart = await prisma.cart.create({
        data: { profileId: user.id },
        include: {
          items: {
            include: {
              productVariant: {
                include: {
                  product: {
                    select: { id: true, name: true, slug: true, brand: true, status: true },
                  },
                },
              },
            },
          },
        },
      });
    }

    assertOwnerOrAdmin(user, cart.profileId);

    // Compute prices strictly from current database values
    let subtotalInCents = 0;
    const computedItems = cart.items.map((item) => {
      const unitPrice = item.productVariant.priceInCents;
      const itemSubtotal = unitPrice * item.quantity;

      const isVariantActive =
        item.productVariant.active && item.productVariant.product.status === ProductStatus.ACTIVE;
      const isStockSufficient = item.productVariant.stockQuantity >= item.quantity;

      let status: CartItemStatus = 'OK';
      if (!isVariantActive) {
        status = 'UNAVAILABLE';
      } else if (!isStockSufficient) {
        status = 'INSUFFICIENT_STOCK';
      }

      // Exclude non-OK lines from the subtotal
      if (status === 'OK') {
        subtotalInCents += itemSubtotal;
      }

      return {
        id: item.id,
        quantity: item.quantity,
        status,
        productVariant: {
          id: item.productVariant.id,
          size: item.productVariant.size,
          color: item.productVariant.color,
          sku: item.productVariant.sku,
          priceInCents: unitPrice,
          active: item.productVariant.active,
          inStock: status === 'OK',
          availableStock: item.productVariant.stockQuantity,
          product: item.productVariant.product,
        },
        unitPriceInCents: unitPrice,
        subtotalInCents: itemSubtotal,
      };
    });

    return {
      id: cart.id,
      profileId: cart.profileId,
      items: computedItems,
      itemCount: computedItems.reduce((acc, curr) => acc + curr.quantity, 0),
      subtotalInCents,
    };
  }

  /**
   * Adds a product variant to the customer's cart after validating catalog availability,
   * distinct line caps, per-line quantity caps, and available inventory.
   * Concurrency hardening: Serialized within a single transaction that first acquires an
   * exclusive row lock on the cart (SELECT ... FOR UPDATE). Distinct line-count check, per-line
   * cap check, and stock check are executed inside that lock before any write.
   * Decrement-after-the-fact pattern has been completely removed.
   */
  async addItem(user: AuthenticatedUser, input: AddToCartInput) {
    await prisma.$transaction(
      async (tx) => {
      // 1. Ensure cart exists for user
      let cart = await tx.cart.findUnique({
        where: { profileId: user.id },
      });

      if (!cart) {
        cart = await tx.cart.upsert({
          where: { profileId: user.id },
          create: { profileId: user.id },
          update: {},
        });
      }

      // 2. First lock the cart row exclusively (pessimistic lock)
      await tx.$queryRaw`SELECT id FROM carts WHERE id = ${cart.id} FOR UPDATE`;

      assertOwnerOrAdmin(user, cart.profileId);

      // 3. Verify variant exists and is active (both variant and product status)
      const variant = await tx.productVariant.findUnique({
        where: { id: input.productVariantId },
        include: { product: true },
      });

      if (!variant || !variant.active || variant.product.status !== ProductStatus.ACTIVE) {
        throw new NotFoundError('Suit variant');
      }

      // 4. Check existing item in cart
      const existingItem = await tx.cartItem.findUnique({
        where: {
          cartId_productVariantId: {
            cartId: cart.id,
            productVariantId: variant.id,
          },
        },
      });

      // 5. Line-count check inside lock before any write
      if (!existingItem) {
        const distinctCount = await tx.cartItem.count({
          where: { cartId: cart.id },
        });
        if (distinctCount >= MAX_DISTINCT_CART_ITEMS) {
          throw new ValidationError(
            [{ field: 'cart', message: `Cart cannot exceed ${MAX_DISTINCT_CART_ITEMS} distinct items` }],
            `Cart cannot exceed ${MAX_DISTINCT_CART_ITEMS} distinct line items`
          );
        }
      }

      // 6. Per-line cap check inside lock before any write
      const newQuantity = (existingItem?.quantity || 0) + input.quantity;
      if (newQuantity > MAX_LINE_ITEM_QUANTITY) {
        throw new BadRequestError(
          `Cannot exceed maximum limit of ${MAX_LINE_ITEM_QUANTITY} items per variant.`
        );
      }

      // 7. Stock check inside lock before any write
      if (variant.stockQuantity < newQuantity) {
        throw new BadRequestError(
          `Insufficient inventory. Requested ${newQuantity}, but only ${variant.stockQuantity} available.`
        );
      }

      // 8. Write item inside lock (no decrement-after-the-fact pattern)
      if (existingItem) {
        await tx.cartItem.update({
          where: { id: existingItem.id },
          data: { quantity: newQuantity },
        });
      } else {
        await tx.cartItem.create({
          data: {
            cartId: cart.id,
            productVariantId: variant.id,
            quantity: input.quantity,
          },
        });
      }
    },
    {
      maxWait: 15000,
      timeout: 30000,
    });

    return this.getCart(user);
  }

  /**
   * Updates an item's quantity in the customer's cart. If quantity is 0, removes the item.
   * Strict Rule: Must be owner-only, with no admin override allowed.
   */
  async updateItemQuantity(user: AuthenticatedUser, cartItemId: string, input: UpdateCartItemInput) {
    const item = await prisma.cartItem.findUnique({
      where: { id: cartItemId },
      include: {
        cart: true,
        productVariant: {
          include: { product: true },
        },
      },
    });

    if (!item) {
      throw new NotFoundError('Cart item');
    }

    // Strict owner-only check: no admin override permitted
    if (user.id !== item.cart.profileId) {
      throw new ForbiddenError('Only the cart owner may modify cart items');
    }

    if (input.quantity <= 0) {
      await prisma.cartItem.delete({ where: { id: cartItemId } });
      return this.getCart(user);
    }

    // Verify variant and product remain active
    if (!item.productVariant.active || item.productVariant.product.status !== ProductStatus.ACTIVE) {
      throw new BadRequestError('Suit variant is no longer active or available');
    }

    // Check stock
    if (item.productVariant.stockQuantity < input.quantity) {
      throw new BadRequestError(
        `Insufficient inventory. Requested ${input.quantity}, but only ${item.productVariant.stockQuantity} available.`
      );
    }

    await prisma.cartItem.update({
      where: { id: cartItemId },
      data: { quantity: input.quantity },
    });

    return this.getCart(user);
  }

  /**
   * Removes a single item from the customer's cart.
   * Strict Rule: Must be owner-only, with no admin override allowed.
   */
  async removeItem(user: AuthenticatedUser, cartItemId: string) {
    const item = await prisma.cartItem.findUnique({
      where: { id: cartItemId },
      include: { cart: true },
    });

    if (!item) {
      throw new NotFoundError('Cart item');
    }

    // Strict owner-only check: no admin override permitted
    if (user.id !== item.cart.profileId) {
      throw new ForbiddenError('Only the cart owner may remove cart items');
    }

    await prisma.cartItem.delete({ where: { id: cartItemId } });
    return this.getCart(user);
  }

  /**
   * Clears all items in the customer's cart.
   */
  async clearCart(user: AuthenticatedUser) {
    const cart = await prisma.cart.findUnique({
      where: { profileId: user.id },
    });

    if (cart) {
      assertOwnerOrAdmin(user, cart.profileId);
      await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
    }

    return this.getCart(user);
  }
}

export const cartService = new CartService();

