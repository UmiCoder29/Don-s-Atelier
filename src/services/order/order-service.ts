import { prisma } from '@/lib/db/prisma';
import { OrderStatus, PaymentStatus, Role, Prisma } from '@prisma/client';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { BadRequestError, NotFoundError, ForbiddenError, ConflictError } from '@/lib/errors/api-error';
import { generateOrderNumber } from '@/lib/crypto';
import { encryptAddressFields, decryptAddressFields } from '@/lib/crypto/field-encryption';
import { logAuditEvent } from '@/lib/audit/audit-logger';
import { logger } from '@/lib/api/logger';
import { paymentProvider as defaultPaymentProvider, PaymentProvider, WebhookEvent } from '@/services/payment';
import { CheckoutInput, ListOrdersQuery, ShippingAddress } from './types';
import { validateOrderStatusTransition, shouldRestockOnTransition } from './order-state-machine';
import { Actor, userActor, systemActor } from '@/lib/auth/actor';

function decryptOrderShippingAddress(addressJson: Prisma.JsonValue): ShippingAddress {
  if (addressJson && typeof addressJson === 'object' && !Array.isArray(addressJson)) {
    return decryptAddressFields(addressJson as Record<string, unknown>) as unknown as ShippingAddress;
  }
  return addressJson as unknown as ShippingAddress;
}

function encryptOrderShippingAddress(address: ShippingAddress): Prisma.InputJsonValue {
  return encryptAddressFields(address as unknown as Record<string, unknown>) as unknown as Prisma.InputJsonValue;
}

/**
 * Service managing customer checkout, server-side order calculation, and order tracking.
 *
 * Strict Security Principles:
 * 1. Prices, totals, discounts, and inventory stock are ALWAYS queried and computed
 *    directly from PostgreSQL database records on the server; client bodies are never trusted.
 * 2. Zero card details are ever received or persisted (PCI-DSS compliance via paymentProvider).
 * 3. In ONE database transaction: re-validates cart, locks/decrements stock, computes totals server-side,
 *    creates Order + OrderItem snapshots, creates Payment via PaymentProvider interface.
 * 4. Concurrency hardening: locks productVariant rows with SELECT ... FOR UPDATE in sorted order before decrementing stock.
 * 5. Customer cancel allowed only before PROCESSING, restoring inventory stock.
 */
export class OrderService {
  private paymentProvider: PaymentProvider;

  constructor(paymentProvider: PaymentProvider = defaultPaymentProvider) {
    this.paymentProvider = paymentProvider;
  }

  /**
   * Test-only dependency injection setter for payment provider.
   * Throws if invoked in production to guarantee that tests or external callers
   * cannot hijack or override the payment provider in production.
   */
  public setPaymentProvider(provider: PaymentProvider): void {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Cannot inject mock payment provider in production');
    }
    this.paymentProvider = provider;
  }

  public getPaymentProvider(): PaymentProvider {
    return this.paymentProvider;
  }
  /**
   * Executes atomic checkout for the authenticated user's cart in ONE database transaction:
   * - Requires email verification before checkout
   * - Checks and prevents duplicate orders via composite (profileId, idempotencyKey)
   * - Re-validates cart inside transaction; unavailable/inactive lines abort with 409
   * - Locks product_variants rows with SELECT ... FOR UPDATE in sorted order (no overselling!)
   * - Checks stock inside lock and decrements stock
   * - Computes subtotal, shipping, and total entirely server-side from DB records
   * - Creates Order and OrderItem snapshots with encrypted shipping address
   * - Creates Payment through PaymentProvider interface and records in database
   * - Handles payment failure simulation by restocking immediately and setting CANCELLED
   * - Clears customer cart and logs immutable audit trail
   */
  async checkout(user: AuthenticatedUser, input: CheckoutInput, idempotencyKeyHeader?: string) {
    // 0. Email verification required before checkout
    if (!user.emailConfirmed) {
      throw new ForbiddenError('Email verification is required before checkout. Please verify your email.');
    }

    const idempotencyKey = idempotencyKeyHeader || input.idempotencyKey;

    // 1. Idempotency Check (Fast-path replay scoped strictly to user.id)
    if (idempotencyKey) {
      const existingOrder = await prisma.order.findUnique({
        where: {
          profileId_idempotencyKey: {
            profileId: user.id,
            idempotencyKey,
          },
        },
        include: {
          items: true,
          payments: true,
        },
      });

      if (existingOrder) {
        return {
          order: {
            ...existingOrder,
            shippingAddress: decryptOrderShippingAddress(existingOrder.shippingAddress),
          },
          paymentIntent: existingOrder.payments[0]
            ? {
              id: existingOrder.payments[0].providerRef,
              clientSecret: `${existingOrder.payments[0].providerRef}_secret_replay`,
              amountInCents: existingOrder.payments[0].amountInCents,
              currency: existingOrder.payments[0].currency,
            }
            : null,
          paymentRecord: existingOrder.payments[0] || null,
          idempotentReplay: true,
        };
      }
    }

    // 2. Execute EVERYTHING inside ONE atomic database transaction
    try {
      const result = await prisma.$transaction(
        async (tx) => {
          // Double check idempotency under race conditions inside transaction
          if (idempotencyKey) {
            const existing = await tx.order.findUnique({
              where: {
                profileId_idempotencyKey: {
                  profileId: user.id,
                  idempotencyKey,
                },
              },
              include: { items: true, payments: true },
            });
            if (existing) {
              return {
                order: existing,
                paymentIntent: null,
                paymentRecord: existing.payments[0] || null,
                idempotentReplay: true,
              };
            }
          }

          // a. Re-validate cart inside the transaction
          const cart = await tx.cart.findUnique({
            where: { profileId: user.id },
            include: {
              items: {
                include: {
                  productVariant: {
                    include: { product: true },
                  },
                },
              },
            },
          });

          if (!cart || cart.items.length === 0) {
            throw new BadRequestError('Cannot checkout an empty shopping cart');
          }

          assertOwnerOrAdmin(user, cart.profileId);

          // b. Lock variant rows (SELECT ... FOR UPDATE) in sorted order to prevent deadlocks and overselling
          const variantIds = cart.items.map((i) => i.productVariantId);
          const sortedVariantIds = Array.from(new Set(variantIds)).sort();

          for (const vId of sortedVariantIds) {
            await tx.$queryRaw`SELECT id, "stockQuantity" FROM product_variants WHERE id = ${vId} FOR UPDATE`;
          }

          // Fetch fresh variant records under the exclusive row lock
          const lockedVariants = await tx.productVariant.findMany({
            where: { id: { in: sortedVariantIds } },
            include: { product: true },
          });
          const variantMap = new Map(lockedVariants.map((v) => [v.id, v]));

          // c. Check stock, availability, and compute totals server-side
          // Unavailable or inactive cart lines must abort checkout with 409 Conflict listing the problem lines
          const problemLines: Array<{
            productVariantId: string;
            sku?: string;
            name?: string;
            reason: 'inactive' | 'insufficient_stock' | 'not_found';
            requestedQuantity: number;
            availableStock: number;
          }> = [];

          let subtotalInCents = 0;
          const verifiedItems: Array<{
            variant: typeof lockedVariants[0];
            quantity: number;
            unitPriceInCents: number;
            itemSubtotalInCents: number;
          }> = [];

          for (const item of cart.items) {
            const variant = variantMap.get(item.productVariantId);
            if (!variant) {
              problemLines.push({
                productVariantId: item.productVariantId,
                reason: 'not_found',
                requestedQuantity: item.quantity,
                availableStock: 0,
              });
            } else if (!variant.active || variant.product.status !== 'ACTIVE') {
              problemLines.push({
                productVariantId: item.productVariantId,
                sku: variant.sku,
                name: variant.product.name,
                reason: 'inactive',
                requestedQuantity: item.quantity,
                availableStock: variant.stockQuantity,
              });
            } else if (variant.stockQuantity < item.quantity) {
              problemLines.push({
                productVariantId: item.productVariantId,
                sku: variant.sku,
                name: variant.product.name,
                reason: 'insufficient_stock',
                requestedQuantity: item.quantity,
                availableStock: variant.stockQuantity,
              });
            } else {
              const unitPrice = variant.priceInCents;
              const itemSubtotal = unitPrice * item.quantity;
              subtotalInCents += itemSubtotal;

              verifiedItems.push({
                variant,
                quantity: item.quantity,
                unitPriceInCents: unitPrice,
                itemSubtotalInCents: itemSubtotal,
              });
            }
          }

          // Abort with 409 Conflict if ANY line is unavailable or out of stock
          if (problemLines.length > 0) {
            throw new ConflictError(
              `Cannot complete checkout: ${problemLines.length} item(s) in your cart are unavailable or out of stock`,
              { problemLines }
            );
          }

          // d. Decrement stock for all items inside the lock
          for (const item of verifiedItems) {
            await tx.productVariant.update({
              where: { id: item.variant.id },
              data: {
                stockQuantity: {
                  decrement: item.quantity,
                },
              },
            });
          }

          // e. Server-computed shipping fee: Free shipping on orders >= $1,000 (100,000 cents), else $25 (2,500 cents)
          const shippingInCents = subtotalInCents >= 100000 ? 0 : 2500;
          const totalInCents = subtotalInCents + shippingInCents;
          const orderNumber = generateOrderNumber();

          // Resolve shipping address: addressId from the user's verified address book (only).
          // Inline shippingAddress is intentionally unsupported — clients cannot supply
          // addresses directly; the server resolves and snapshots from the address book.
          const address = await tx.address.findUnique({
            where: { id: input.addressId },
          });
          if (!address) {
            throw new NotFoundError('Address');
          }
          if (address.profileId !== user.id) {
            throw new ForbiddenError('Shipping address does not belong to the authenticated user');
          }
          const finalShippingAddress: ShippingAddress = {
            recipientName: address.recipientName,
            streetLine1: address.line1,
            streetLine2: address.line2 || undefined,
            city: address.city,
            stateOrProvince: address.state,
            postalCode: address.postalCode,
            country: address.country,
            phone: address.phone || '',
          };

          // f. Create Order + OrderItem snapshots
          const order = await tx.order.create({
            data: {
              orderNumber,
              profileId: user.id,
              status: OrderStatus.PENDING,
              subtotalInCents,
              shippingInCents,
              totalInCents,
              shippingAddress: encryptOrderShippingAddress(finalShippingAddress),
              idempotencyKey: idempotencyKey || null,
              items: {
                create: verifiedItems.map((item) => ({
                  productVariantId: item.variant.id,
                  name: item.variant.product.name,
                  size: item.variant.size,
                  color: item.variant.color,
                  unitPriceInCents: item.unitPriceInCents,
                  quantity: item.quantity,
                  subtotalInCents: item.itemSubtotalInCents,
                })),
              },
            },
            include: {
              items: true,
            },
          });

          // Record initial status history row
          await tx.orderStatusHistory.create({
            data: {
              orderId: order.id,
              fromStatus: null,
              toStatus: OrderStatus.PENDING,
              changedBy: user.id,
              note: 'Order created via checkout',
            },
          });

          // g. Create Payment via PaymentProvider interface inside the transaction
          const paymentIntent = await this.paymentProvider.createPaymentIntent({
            amountInCents: totalInCents,
            currency: 'usd',
            orderId: order.id,
            customerEmail: user.email,
            metadata: {
              orderNumber: order.orderNumber,
            },
          });

          // Payment simulation is strictly prohibited in production and requires explicit PAYMENT_MODE=mock flag.
          // Otherwise, checkout NEVER marks order PAID immediately and leaves it PENDING until a verified webhook arrives.
          const isSimulationAllowed =
            process.env.PAYMENT_MODE === 'mock' &&
            process.env.NODE_ENV !== 'production';

          const isPaymentSuccess = isSimulationAllowed && paymentIntent.status === 'succeeded';
          const isPaymentFailed = isSimulationAllowed && paymentIntent.status === 'failed';

          const paymentRecord = await tx.payment.create({
            data: {
              orderId: order.id,
              provider: this.paymentProvider.providerName,
              providerRef: paymentIntent.id,
              amountInCents: totalInCents,
              currency: 'usd',
              status: isPaymentSuccess
                ? PaymentStatus.SUCCEEDED
                : isPaymentFailed
                  ? PaymentStatus.FAILED
                  : PaymentStatus.PENDING,
            },
          });

          // If payment simulation succeeded immediately, mark order PAID
          if (isPaymentSuccess) {
            validateOrderStatusTransition(order.status, OrderStatus.PAID, systemActor('checkout_payment'));
            await tx.order.update({
              where: { id: order.id },
              data: { status: OrderStatus.PAID },
            });
            order.status = OrderStatus.PAID;

            await tx.orderStatusHistory.create({
              data: {
                orderId: order.id,
                fromStatus: OrderStatus.PENDING,
                toStatus: OrderStatus.PAID,
                changedBy: user.id,
                note: 'Immediate payment success simulation',
              },
            });
          } else if (isPaymentFailed) {
            validateOrderStatusTransition(order.status, OrderStatus.CANCELLED, systemActor('checkout_payment_failed'));
            // Payment failure: restock exactly once and set order to CANCELLED
            for (const item of verifiedItems) {
              await tx.productVariant.update({
                where: { id: item.variant.id },
                data: {
                  stockQuantity: {
                    increment: item.quantity,
                  },
                },
              });
            }

            await tx.order.update({
              where: { id: order.id },
              data: { status: OrderStatus.CANCELLED },
            });
            order.status = OrderStatus.CANCELLED;

            await tx.orderStatusHistory.create({
              data: {
                orderId: order.id,
                fromStatus: OrderStatus.PENDING,
                toStatus: OrderStatus.CANCELLED,
                changedBy: user.id,
                note: 'Order cancelled due to immediate payment failure',
              },
            });

            await logAuditEvent({
              tx,
              actorId: user.id,
              action: 'PAYMENT_FAILED_RESTOCKED',
              entity: 'Order',
              entityId: order.id,
              metadata: {
                orderNumber: order.orderNumber,
                providerRef: paymentIntent.id,
                reason: 'immediate_simulation_failure',
              },
            });
          }

          // h. Empty customer cart
          await tx.cartItem.deleteMany({
            where: { cartId: cart.id },
          });

          // i. Record immutable AuditLog
          await logAuditEvent({
            tx,
            actorId: user.id,
            action: isPaymentFailed ? 'ORDER_CHECKOUT_FAILED' : 'ORDER_CHECKOUT_COMPLETED',
            entity: 'Order',
            entityId: order.id,
            metadata: {
              orderNumber: order.orderNumber,
              totalInCents: order.totalInCents,
              itemCount: verifiedItems.length,
              status: order.status,
            },
          });

          return {
            order,
            paymentIntent,
            paymentRecord,
            idempotentReplay: false,
          };
        },
        {
          maxWait: 30000,
          timeout: 60000,
        }
      );

      return {
        order: {
          ...result.order,
          shippingAddress: decryptOrderShippingAddress(result.order.shippingAddress),
          payments: result.paymentRecord ? [result.paymentRecord] : [],
        },
        paymentIntent: result.paymentIntent
          ? {
            id: result.paymentIntent.id,
            clientSecret: result.paymentIntent.clientSecret,
            amountInCents: result.paymentIntent.amountInCents,
            currency: result.paymentIntent.currency,
          }
          : null,
        paymentRecord: result.paymentRecord,
        idempotentReplay: result.idempotentReplay,
      };
    } catch (err: any) {
      // Handle unique constraint race condition on (profileId, idempotencyKey)
      if (err?.code === 'P2002' && idempotencyKey) {
        const existing = await prisma.order.findUnique({
          where: {
            profileId_idempotencyKey: {
              profileId: user.id,
              idempotencyKey,
            },
          },
          include: { items: true, payments: true },
        });

        if (existing && existing.profileId === user.id) {
          return {
            order: {
              ...existing,
              shippingAddress: decryptOrderShippingAddress(existing.shippingAddress),
              payments: existing.payments,
            },
            paymentIntent: null,
            paymentRecord: existing.payments[0] || null,
            idempotentReplay: true,
          };
        }
      }
      throw err;
    }
  }

  /**
   * Internal shared function that executes atomic, idempotent order cancellation and stock restoration.
   * - Acquires exclusive row lock (SELECT ... FOR UPDATE) on the order.
   * - Verifies status is cancellable (PENDING or PAID). If already CANCELLED, returns idempotently as no-op.
   * - Restores stock for all order items in sorted order (to prevent lock cycles).
   * - If payment succeeded, processes refund.
   * - Updates status to CANCELLED.
   * - Writes OrderStatusHistory record.
   * - Writes AuditLog record.
   */
  async sharedCancelAndRestock(
    tx: Prisma.TransactionClient,
    orderId: string,
    actor: Actor,
    note: string
  ) {
    // 1. Lock the order row exclusively
    await tx.$queryRaw`SELECT id, status, "profileId" FROM orders WHERE id = ${orderId} FOR UPDATE`;

    const order = await tx.order.findUnique({
      where: { id: orderId },
      include: {
        items: true,
        payments: true,
      },
    });

    if (!order) {
      throw new NotFoundError('Order');
    }

    // 2. Idempotency check under row lock:
    // If already cancelled, return existing order without restocking a second time!
    if (order.status === OrderStatus.CANCELLED) {
      return { order, alreadyCancelled: true };
    }

    // Cancellation is allowed ONLY before PROCESSING (i.e. PENDING or PAID)
    const cancellableStatuses: OrderStatus[] = [OrderStatus.PENDING, OrderStatus.PAID];
    if (!cancellableStatuses.includes(order.status)) {
      throw new BadRequestError(
        `Order with status '${order.status}' cannot be cancelled. Cancellation is only allowed before processing.`
      );
    }

    // 3. Central state machine validation
    validateOrderStatusTransition(order.status, OrderStatus.CANCELLED, actor);

    // 4. Restore inventory stock for each item in the order according to central restock rules
    if (shouldRestockOnTransition(order.status, OrderStatus.CANCELLED)) {
      const sortedItems = [...order.items].sort((a, b) =>
        (a.productVariantId || '').localeCompare(b.productVariantId || '')
      );

      for (const item of sortedItems) {
        if (item.productVariantId) {
          await tx.productVariant.update({
            where: { id: item.productVariantId },
            data: {
              stockQuantity: {
                increment: item.quantity,
              },
            },
          });
        }
      }
    }

    // 5. If payment was made, process refund
    for (const payment of order.payments) {
      if (payment.status === PaymentStatus.SUCCEEDED) {
        await this.paymentProvider.refund({
          transactionId: payment.providerRef,
          amountInCents: payment.amountInCents,
          reason: note,
        });

        await tx.payment.update({
          where: { id: payment.id },
          data: { status: PaymentStatus.REFUNDED },
        });
      }
    }

    const previousStatus = order.status;

    // 6. Update order status to CANCELLED
    const cancelledOrder = await tx.order.update({
      where: { id: order.id },
      data: {
        status: OrderStatus.CANCELLED,
      },
      include: {
        items: true,
        payments: true,
      },
    });

    const changedBy = actor.kind === 'USER' ? actor.id : actor.name;

    // 7. Write OrderStatusHistory row
    await tx.orderStatusHistory.create({
      data: {
        orderId: order.id,
        fromStatus: previousStatus,
        toStatus: OrderStatus.CANCELLED,
        changedBy,
        note,
      },
    });

    // 8. Audit log (strictly no plaintext notes or sensitive data in metadata)
    await logAuditEvent({
      tx,
      actor,
      action: 'ORDER_CANCELLED',
      entity: 'Order',
      entityId: order.id,
      metadata: {
        orderNumber: order.orderNumber,
        previousStatus,
        restoredItemsCount: order.items.length,
      },
    });

    return { order: cancelledOrder, alreadyCancelled: false };
  }

  /**
   * Customer order cancellation allowed ONLY before PROCESSING, restoring inventory stock.
   * Strictly owner-only with NO admin override.
   */
  async cancelOrder(user: AuthenticatedUser, orderId: string) {
    const updatedOrder = await prisma.$transaction(
      async (tx) => {
        const order = await tx.order.findUnique({
          where: { id: orderId },
          select: { profileId: true },
        });

        if (!order) {
          throw new NotFoundError('Order');
        }

        // Strict: Owner-only, NO admin override on this route
        if (order.profileId !== user.id) {
          throw new ForbiddenError('Only the order owner may cancel this order via this endpoint');
        }

        const { order: cancelled } = await this.sharedCancelAndRestock(
          tx,
          orderId,
          userActor(user.id, user.role),
          'Customer cancelled order before processing'
        );
        return cancelled;
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return {
      ...updatedOrder,
      shippingAddress: decryptOrderShippingAddress(updatedOrder.shippingAddress),
    };
  }

  /**
   * Admin updates an order's status through the central order state machine.
   * - Enforces row lock (FOR UPDATE) within a transaction.
   * - Validates status transition through validateOrderStatusTransition.
   * - Restocks inventory on CANCELLED or REFUNDED exactly once (idempotent: subsequent cancel/refund does not double restock).
   * - Refund records payment status only, never calling payment providers or storing card data.
   * - Every change writes OrderStatusHistory and AuditLog inside the transaction.
   */
  async adminUpdateOrderStatus(
    adminUser: AuthenticatedUser,
    orderId: string,
    newStatus: OrderStatus,
    note?: string
  ) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only atelier administrators may advance order fulfillment status');
    }

    const updatedOrder = await prisma.$transaction(
      async (tx) => {
        // 1. Lock the order row exclusively
        const lockedRows = await tx.$queryRaw<
          Array<{ id: string; status: OrderStatus; profileId: string }>
        >`
          SELECT id, status, "profileId" FROM orders WHERE id = ${orderId} FOR UPDATE
        `;

        if (lockedRows.length === 0) {
          throw new NotFoundError('Order');
        }

        const current = lockedRows[0];

        // 2. Validate transition through central order state machine
        validateOrderStatusTransition(current.status, newStatus, adminUser.role);

        // Required reason enforcement when moving PENDING to PAID
        if (current.status === OrderStatus.PENDING && newStatus === OrderStatus.PAID) {
          if (!note || !note.trim()) {
            throw new BadRequestError('Reason is required when manually moving order from PENDING to PAID');
          }
        }

        // 3. Idempotent check: if target status matches current status (e.g. repeated cancel or refund)
        if (current.status === newStatus) {
          const existing = await tx.order.findUnique({
            where: { id: orderId },
            include: { items: true, payments: true, statusHistory: true },
          });
          return existing!;
        }

        // Restock inventory based on central restock rules:
        // - CANCELLED: restocks from any valid pre-cancellation state (PENDING, PAID, PROCESSING)
        // - REFUNDED: restocks ONLY if previous status was PAID or PROCESSING.
        //   REFUNDED from SHIPPED or DELIVERED must NOT restock.
        const mustRestock = shouldRestockOnTransition(current.status, newStatus);

        if (mustRestock) {
          const items = await tx.orderItem.findMany({
            where: { orderId },
          });

          // Sort variants to avoid deadlocks
          const sortedItems = [...items].sort((a, b) =>
            (a.productVariantId || '').localeCompare(b.productVariantId || '')
          );

          for (const item of sortedItems) {
            if (item.productVariantId) {
              await tx.productVariant.update({
                where: { id: item.productVariantId },
                data: {
                  stockQuantity: {
                    increment: item.quantity,
                  },
                },
              });
            }
          }
        }

        // If refund, record payment status as REFUNDED in DB without invoking payment provider
        if (newStatus === OrderStatus.REFUNDED) {
          await tx.payment.updateMany({
            where: { orderId, status: PaymentStatus.SUCCEEDED },
            data: { status: PaymentStatus.REFUNDED },
          });
        }

        // 4. Update order status
        const order = await tx.order.update({
          where: { id: orderId },
          data: { status: newStatus },
          include: { items: true, payments: true, statusHistory: true },
        });

        const historyNote = note || `Status updated to ${newStatus} by administrator`;

        // 5. Write OrderStatusHistory row
        await tx.orderStatusHistory.create({
          data: {
            orderId,
            fromStatus: current.status,
            toStatus: newStatus,
            changedBy: adminUser.id,
            note: historyNote,
          },
        });

        // 6. Write AuditLog row (strictly no plaintext sensitive data in metadata)
        const action =
          newStatus === OrderStatus.CANCELLED
            ? 'ORDER_CANCELLED'
            : newStatus === OrderStatus.REFUNDED
              ? 'ORDER_REFUNDED'
              : 'ORDER_STATUS_UPDATED';

        await logAuditEvent({
          tx,
          actor: userActor(adminUser.id, adminUser.role),
          action,
          entity: 'Order',
          entityId: orderId,
          metadata: {
            previousStatus: current.status,
            newStatus,
            ...(note ? { reason: note } : {}),
          },
        });

        return order;
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return {
      ...updatedOrder,
      shippingAddress: decryptOrderShippingAddress(updatedOrder.shippingAddress),
    };
  }

  /**
   * Lists orders for atelier administrators with filters, search, and pagination.
   * Encrypted fields (address, phone) are never searched.
   */
  async adminListOrders(
    adminUser: AuthenticatedUser,
    params: {
      page?: number;
      limit?: number;
      status?: OrderStatus;
      startDate?: Date | string;
      endDate?: Date | string;
      search?: string;
    }
  ) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only administrators can access this resource');
    }

    const page = Math.max(1, params.page || 1);
    const limit = Math.min(100, Math.max(1, params.limit || 20));
    const skip = (page - 1) * limit;

    const where: Prisma.OrderWhereInput = {};

    if (params.status) {
      where.status = params.status;
    }

    if (params.startDate || params.endDate) {
      where.createdAt = {};
      if (params.startDate) {
        where.createdAt.gte = new Date(params.startDate);
      }
      if (params.endDate) {
        where.createdAt.lte = new Date(params.endDate);
      }
    }

    if (params.search && params.search.trim()) {
      const q = params.search.trim();
      where.OR = [
        { orderNumber: { contains: q, mode: 'insensitive' } },
        { profile: { email: { contains: q, mode: 'insensitive' } } },
      ];
    }

    const [orders, totalCount] = await Promise.all([
      prisma.order.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          profile: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
          items: true,
          payments: true,
        },
      }),
      prisma.order.count({ where }),
    ]);

    const sanitizedOrders = orders.map((o) => ({
      ...o,
      shippingAddress: decryptOrderShippingAddress(o.shippingAddress),
    }));

    return {
      orders: sanitizedOrders,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    };
  }

  /**
   * Retrieves full details for a single order by ID for administrators.
   */
  async adminGetOrderById(adminUser: AuthenticatedUser, orderId: string) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only administrators can access this resource');
    }

    const order = await prisma.order.findUnique({
      where: { id: orderId },
      include: {
        profile: {
          select: {
            id: true,
            email: true,
            name: true,
          },
        },
        items: true,
        payments: true,
        statusHistory: {
          orderBy: { timestamp: 'asc' },
        },
      },
    });

    if (!order) {
      throw new NotFoundError('Order');
    }

    return {
      ...order,
      shippingAddress: decryptOrderShippingAddress(order.shippingAddress),
    };
  }

  /**
   * Scheduled-safe function that cancels PENDING orders older than N minutes and restocks them.
   * Runs each order in its own transaction with row lock, writing status history and audit log.
   */
  async cancelExpiredPendingOrders(olderThanMinutes: number = 30) {
    const cutoffDate = new Date(Date.now() - olderThanMinutes * 60 * 1000);

    const pendingOrders = await prisma.order.findMany({
      where: {
        status: OrderStatus.PENDING,
        createdAt: {
          lt: cutoffDate,
        },
      },
      select: {
        id: true,
        orderNumber: true,
      },
    });

    const results: Array<{ orderId: string; orderNumber: string; success: boolean; error?: string }> = [];

    for (const order of pendingOrders) {
      try {
        await prisma.$transaction(
          async (tx) => {
            await this.sharedCancelAndRestock(
              tx,
              order.id,
              systemActor('system_scheduler'),
              `Expired PENDING order cancelled automatically (older than ${olderThanMinutes} minutes)`
            );
          },
          { maxWait: 15000, timeout: 30000 }
        );
        results.push({ orderId: order.id, orderNumber: order.orderNumber, success: true });
      } catch (err: any) {
        results.push({
          orderId: order.id,
          orderNumber: order.orderNumber,
          success: false,
          error: err?.message || 'Unknown error',
        });
      }
    }

    return {
      totalFound: pendingOrders.length,
      cancelledCount: results.filter((r) => r.success).length,
      results,
    };
  }

  /**
   * Processes webhook confirmation from payment provider (e.g. Stripe).
   * - Dedupes by provider event ID using unique constraint so replayed event is a no-op
   * - Verifies event amount equals order total (wrong-amount events do nothing)
   * - Never trusts order status from payload; strictly derives status from event.type
   * - On failure, restocks exactly once via sharedCancelAndRestock and sets CANCELLED
   */
  async handlePaymentWebhook(event: WebhookEvent) {
    const object = event.data?.object;
    if (!object || !object.id) {
      throw new BadRequestError('Invalid webhook event payload: missing object or id');
    }

    const providerRef = object.id;

    return await prisma.$transaction(
      async (tx) => {
        // 1. Dedupe by (provider, eventId) using unique constraint so replayed event is a no-op
        try {
          await tx.processedWebhookEvent.create({
            data: {
              provider: 'mock_stripe',
              eventId: event.id,
              eventType: event.type,
            },
          });
        } catch (err: any) {
          if (err?.code === 'P2002') {
            logger.info(`Webhook event '${event.id}' has already been processed. Returning no-op.`, {
              eventId: event.id,
            });
            return { handled: true, status: 'replayed_no_op', eventId: event.id };
          }
          throw err;
        }

        // 2. Locate payment & associated order
        let payment = await tx.payment.findUnique({
          where: { providerRef },
          include: {
            order: {
              include: {
                items: true,
                payments: true,
              },
            },
          },
        });

        if (!payment && object.orderId) {
          payment = await tx.payment.findFirst({
            where: { orderId: object.orderId },
            include: {
              order: {
                include: {
                  items: true,
                  payments: true,
                },
              },
            },
          });
        }

        if (!payment) {
          throw new NotFoundError(`Payment with providerRef '${providerRef}'`);
        }

        const order = payment.order;

        // 3. Verify event amount equals order total! (Wrong-amount event does nothing)
        const eventAmount = object.amountInCents !== undefined ? object.amountInCents : object.amount;
        if (eventAmount !== undefined && eventAmount !== order.totalInCents) {
          logger.warn(
            `Webhook event amount (${eventAmount}) does not match order total (${order.totalInCents}). No-op.`,
            {
              eventId: event.id,
              eventAmount,
              orderTotal: order.totalInCents,
            }
          );
          return {
            handled: false,
            status: 'amount_mismatch_no_op',
            eventId: event.id,
            orderId: order.id,
          };
        }

        // 4. Never trust order status from the payload! Only derive from event.type
        if (event.type === 'payment_intent.succeeded' || event.type === 'payment.succeeded') {
          // Idempotency: if already paid, return without redundant update
          if (payment.status === PaymentStatus.SUCCEEDED && order.status === OrderStatus.PAID) {
            return { handled: true, status: 'already_processed', orderId: order.id };
          }

          // Case: succeeded on a CANCELLED order must NOT change status, and must write an audit log flagged NEEDS_REFUND
          if (order.status === OrderStatus.CANCELLED) {
            await tx.payment.update({
              where: { id: payment.id },
              data: { status: PaymentStatus.SUCCEEDED },
            });

            await logAuditEvent({
              tx,
              actorId: order.profileId,
              action: 'NEEDS_REFUND',
              entity: 'Order',
              entityId: order.id,
              metadata: {
                flag: 'NEEDS_REFUND',
                reason: 'Payment succeeded on already CANCELLED order',
                providerRef,
                amountInCents: order.totalInCents,
                eventId: event.id,
              },
            });

            return {
              handled: true,
              status: 'cancelled_order_needs_refund',
              orderId: order.id,
              flag: 'NEEDS_REFUND',
            };
          }

          await tx.payment.update({
            where: { id: payment.id },
            data: { status: PaymentStatus.SUCCEEDED },
          });

          if (order.status === OrderStatus.PENDING) {
            validateOrderStatusTransition(order.status, OrderStatus.PAID, systemActor('payment_webhook'));
            await tx.order.update({
              where: { id: order.id },
              data: { status: OrderStatus.PAID },
            });

            await tx.orderStatusHistory.create({
              data: {
                orderId: order.id,
                fromStatus: OrderStatus.PENDING,
                toStatus: OrderStatus.PAID,
                changedBy: 'system_payment_webhook',
                note: `Payment succeeded via webhook event ${event.id}`,
              },
            });
          }

          await logAuditEvent({
            tx,
            actor: systemActor('payment_webhook'),
            action: 'PAYMENT_CONFIRMED',
            entity: 'Order',
            entityId: order.id,
            metadata: {
              providerRef,
              amountInCents: order.totalInCents,
              eventId: event.id,
            },
          });

          return { handled: true, status: 'succeeded', orderId: order.id };
        } else if (event.type === 'payment_intent.payment_failed' || event.type === 'payment.failed') {
          // Case: failed on a PAID order must NOT cancel or restock
          if (order.status === OrderStatus.PAID) {
            logger.warn(
              `Payment failure webhook received for already PAID order ${order.id}. Ignoring failure without cancelling or restocking.`,
              {
                orderId: order.id,
                eventId: event.id,
              }
            );
            return {
              handled: true,
              status: 'already_paid_ignored',
              orderId: order.id,
            };
          }

          // Payment failure via webhook on non-PAID order: must restock exactly once and set order to CANCELLED
          await tx.payment.update({
            where: { id: payment.id },
            data: { status: PaymentStatus.FAILED },
          });

          const { order: cancelled, alreadyCancelled } = await this.sharedCancelAndRestock(
            tx,
            order.id,
            systemActor('payment_webhook'),
            `Payment failed via webhook event ${event.id}`
          );

          return {
            handled: true,
            status: 'failed',
            orderId: order.id,
            restocked: !alreadyCancelled,
          };
        }

        return { handled: false, status: 'unhandled_event_type', type: event.type };
      },
      {
        maxWait: 15000,
        timeout: 30000,
      }
    );
  }


  /**
   * Retrieves a single order by ID, enforcing ownership or ADMIN role server-side.
   */
  async getOrderById(user: AuthenticatedUser, orderId: string) {
    const order = await prisma.order.findUnique({
      where: { id: orderId },
      include: {
        items: true,
        payments: {
          select: {
            id: true,
            provider: true,
            providerRef: true,
            status: true,
            amountInCents: true,
            currency: true,
            createdAt: true,
          },
        },
      },
    });

    if (!order) {
      throw new NotFoundError('Order');
    }

    // Prisma connects with a server role that bypasses RLS, so every service function must also enforce ownership/role in code. Implement a reusable assertOwnerOrAdmin helper.
    assertOwnerOrAdmin(user, order.profileId);

    return {
      ...order,
      shippingAddress: decryptOrderShippingAddress(order.shippingAddress),
    };
  }

  /**
   * Lists orders for customer (isolated to own orders) or ADMIN (can view all).
   */
  async listOrders(user: AuthenticatedUser, query: ListOrdersQuery) {
    const page = query.page || 1;
    const limit = query.limit || 20;
    const skip = (page - 1) * limit;

    const whereClause: {
      profileId?: string;
      status?: OrderStatus;
    } = {};

    // Customer is strictly restricted to their own orders
    if (user.role !== Role.ADMIN) {
      whereClause.profileId = user.id;
    }

    if (query.status) {
      whereClause.status = query.status;
    }

    const [orders, totalCount] = await Promise.all([
      prisma.order.findMany({
        where: whereClause,
        include: {
          items: true,
          payments: {
            select: {
              id: true,
              provider: true,
              providerRef: true,
              status: true,
              amountInCents: true,
              currency: true,
            },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.order.count({ where: whereClause }),
    ]);

    const decryptedOrders = orders.map((o) => ({
      ...o,
      shippingAddress: decryptOrderShippingAddress(o.shippingAddress),
    }));

    return {
      orders: decryptedOrders,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    };
  }
}

export const orderService = new OrderService();
