import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';
import { POST as checkoutRoute } from '@/app/api/checkout/route';
import { POST as cancelOrderRoute } from '@/app/api/orders/[id]/cancel/route';
import { POST as webhookRoute } from '@/app/api/webhooks/payments/route';
import { orderService } from '@/services/order/order-service';
import { paymentProvider, MockStripePaymentProvider, DEFAULT_WEBHOOK_SECRET } from '@/services/payment';
import { OrderStatus, PaymentStatus, ProductStatus, Role } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { ErrorCode } from '@/lib/errors/error-codes';
import { ForbiddenError } from '@/lib/errors/api-error';
import * as authModule from '@/lib/auth/supabase-auth';
import type { AuthenticatedUser } from '@/lib/auth/supabase-auth';

describe('Checkout Hardening Acceptance Suite', { timeout: 120000 }, () => {
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';
  const adminEmail = 'admin@dons-atelier.com';

  const testUserEmails = [
    'harden.user1@example.com',
    'harden.user2@example.com',
    'harden.user3@example.com',
    'harden.user4@example.com',
    'harden.user5@example.com',
  ];
  const testUsers: Array<{ id: string; email: string; token: string; addressId: string }> = [];

  let adminToken: string;
  let testProductId: string;
  const createdOrderIds: string[] = [];
  const createdVariantIds: string[] = [];

  const validAddress = {
    recipientName: 'Lord Alistair Sterling',
    streetLine1: '14 Savile Row',
    city: 'London',
    stateOrProvince: 'Greater London',
    postalCode: 'W1S 3PB',
    country: 'GB',
    phone: '+442079460992',
  };

  async function clearCart(profileId: string) {
    const cart = await prisma.cart.findUnique({ where: { profileId } });
    if (cart) {
      await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
    }
  }

  async function addToCartDirect(profileId: string, variantId: string, quantity: number) {
    const cart = await prisma.cart.upsert({
      where: { profileId },
      create: { profileId },
      update: {},
    });
    await prisma.cartItem.upsert({
      where: {
        cartId_productVariantId: {
          cartId: cart.id,
          productVariantId: variantId,
        },
      },
      create: {
        cartId: cart.id,
        productVariantId: variantId,
        quantity,
      },
      update: {
        quantity,
      },
    });
  }

  beforeEach(() => {
    rateLimiter.reset();
  });

  afterEach(() => {
    orderService.setPaymentProvider(new MockStripePaymentProvider());
  });

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Locate an active product
    const product = await prisma.product.findFirst({
      where: { status: ProductStatus.ACTIVE },
    });
    if (!product) throw new Error('No active product found');
    testProductId = product.id;

    // 2. Provision 5 verified test users
    for (const email of testUserEmails) {
      const { data: userList } = await supabaseAdmin.auth.admin.listUsers();
      let authUser = userList?.users?.find((u) => u.email === email);

      if (!authUser) {
        const { data: created, error } = await supabaseAdmin.auth.admin.createUser({
          email,
          password: customerPassword,
          email_confirm: true,
          user_metadata: { name: `Harden Tester ${email}` },
        });
        if (error) throw error;
        authUser = created.user;
      }

      await prisma.profile.upsert({
        where: { id: authUser.id },
        create: { id: authUser.id, email, name: `Harden Tester ${email}`, role: Role.CUSTOMER },
        update: { email, role: Role.CUSTOMER },
      });

      const { data: signin } = await createSupabaseUserClient().auth.signInWithPassword({
        email,
        password: customerPassword,
      });

      const existingAddr = await prisma.address.findFirst({ where: { profileId: authUser.id } });
      const addressId = existingAddr
        ? existingAddr.id
        : (
            await prisma.address.create({
              data: {
                profileId: authUser.id,
                recipientName: `Tester ${email}`,
                line1: '14 Savile Row',
                city: 'London',
                state: 'Greater London',
                postalCode: 'W1S 3PB',
                country: 'GB',
                phone: '+442079460992',
              },
            })
          ).id;

      testUsers.push({
        id: authUser.id,
        email,
        token: signin.session!.access_token,
        addressId,
      });
    }

    // 3. Admin signin
    const { data: adminSignin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    adminToken = adminSignin.session!.access_token;
  });

  afterAll(async () => {
    // Clean up created test orders
    if (createdOrderIds.length > 0) {
      await prisma.orderStatusHistory.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.payment.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.orderItem.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.order.deleteMany({ where: { id: { in: createdOrderIds } } });
    }

    // Clean up created test variants
    if (createdVariantIds.length > 0) {
      await prisma.cartItem.deleteMany({ where: { productVariantId: { in: createdVariantIds } } });
      await prisma.productVariant.deleteMany({ where: { id: { in: createdVariantIds } } });
    }

    // Clean user carts
    for (const u of testUsers) {
      await clearCart(u.id);
    }
  }, 60000);

  // ----------------------------------------------------------------------------
  // Test (a): 5 concurrent checkouts by different users for stock 3
  // ----------------------------------------------------------------------------
  describe('(a) 5 Concurrent Checkouts for Stock = 3', () => {
    it('allows exactly 3 checkouts to succeed, rejects 2 with 409, and variant stock is never below 0', async () => {
      // 1. Create a dedicated variant with exactly 3 stock
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-CONCUR5-STK3-${Date.now()}`,
          size: '40R',
          color: 'Royal Midnight Navy',
          priceInCents: 120000,
          stockQuantity: 3, // EXACTLY 3 IN STOCK
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      // 2. Put 1 item in cart for all 5 users
      for (const u of testUsers) {
        await clearCart(u.id);
        await addToCartDirect(u.id, variant.id, 1);
      }

      // 3. Dispatch 5 simultaneous checkouts
      const promises = testUsers.map((u, i) => {
        const req = new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${u.token}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': `idemp-concur5-user-${i}-${Date.now()}`,
          },
          body: JSON.stringify({ addressId: u.addressId }),
        });
        return checkoutRoute(req, {} as never);
      });

      const responses = await Promise.all(promises);

      // Extract status codes
      const statuses = responses.map((r) => r.status);
      const successCount = statuses.filter((s) => s === 201).length;
      const conflictCount = statuses.filter((s) => s === 409).length;

      expect(successCount).toBe(3);
      expect(conflictCount).toBe(2);

      // Collect order IDs from winners
      for (const res of responses) {
        if (res.status === 201) {
          const body = await res.json();
          createdOrderIds.push(body.data.order.id);
        }
      }

      // 4. Verify inventory stock in database: EXACTLY 0 (Never negative!)
      const finalVariant = await prisma.productVariant.findUnique({
        where: { id: variant.id },
      });
      expect(finalVariant!.stockQuantity).toBe(0);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (b): 5 concurrent double-submits with the same key create exactly one order
  // ----------------------------------------------------------------------------
  describe('(b) 5 Concurrent Double-Submits With the Same Idempotency Key', () => {
    it('creates exactly ONE database order without double-decrements or duplicate rows', async () => {
      const user = testUsers[0];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-IDEMP5-${Date.now()}`,
          size: '42L',
          color: 'Charcoal Grey',
          priceInCents: 95000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 2);

      const sharedKey = `idemp-concur-race-key-${Date.now()}`;

      // Dispatch 5 concurrent requests with identical key from the same user
      const promises = Array.from({ length: 5 }, () => {
        const req = new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${user.token}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': sharedKey,
          },
          body: JSON.stringify({ addressId: user.addressId }),
        });
        return checkoutRoute(req, {} as never);
      });

      const responses = await Promise.all(promises);

      // All 5 must succeed with 201
      for (const res of responses) {
        expect(res.status).toBe(201);
      }

      const bodies = await Promise.all(responses.map((r) => r.json()));
      const orderIds = bodies.map((b) => b.data.order.id);

      // Crucial: ALL 5 responses return the exact same Order ID!
      const uniqueOrderIds = Array.from(new Set(orderIds));
      expect(uniqueOrderIds).toHaveLength(1);
      createdOrderIds.push(uniqueOrderIds[0]);

      // Exactly ONE order exists in database for this key
      const count = await prisma.order.count({
        where: { profileId: user.id, idempotencyKey: sharedKey },
      });
      expect(count).toBe(1);

      // Stock was decremented by 2, NOT by 10 (10 - 2 = 8)
      const freshVariant = await prisma.productVariant.findUnique({
        where: { id: variant.id },
      });
      expect(freshVariant!.stockQuantity).toBe(8);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (c): Cross-user key reuse
  // ----------------------------------------------------------------------------
  describe('(c) Cross-User Key Reuse', () => {
    it('(c) cross-user key reuse: user B submitting user A key creates B own separate order with no 409 and no leak of A data', async () => {
      const userA = testUsers[1];
      const userB = testUsers[2];

      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-CROSSKEY-${Date.now()}`,
          size: '38R',
          color: 'Pearl White',
          priceInCents: 110000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(userA.id);
      await clearCart(userB.id);

      await addToCartDirect(userA.id, variant.id, 1);
      await addToCartDirect(userB.id, variant.id, 1);

      const crossUserKey = `shared-idemp-key-both-users-${Date.now()}`;

      // 1. User A checks out with this key
      const reqA = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${userA.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': crossUserKey,
        },
        body: JSON.stringify({ addressId: userA.addressId }),
      });

      const resA = await checkoutRoute(reqA, {} as never);
      expect(resA.status).toBe(201);
      const bodyA = await resA.json();
      const orderAId = bodyA.data.order.id;
      createdOrderIds.push(orderAId);
      expect(bodyA.data.order.profileId).toBe(userA.id);

      // 2. User B checks out with the EXACT SAME KEY
      const reqB = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${userB.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': crossUserKey,
        },
        body: JSON.stringify({ addressId: userB.addressId }),
      });

      const resB = await checkoutRoute(reqB, {} as never);
      expect(resB.status).toBe(201);
      const bodyB = await resB.json();
      const orderBId = bodyB.data.order.id;
      createdOrderIds.push(orderBId);

      // Crucial: User B gets their OWN order with no 409 and no leak of User A data!
      expect(orderBId).not.toBe(orderAId);
      expect(bodyB.data.order.profileId).toBe(userB.id);
      expect(bodyB.data.order.shippingAddress.recipientName).not.toBe(bodyA.data.order.shippingAddress.recipientName);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (d): Unverified email rejected
  // ----------------------------------------------------------------------------
  describe('(d) Unverified Email Rejection', () => {
    it('rejects checkout with 403 Forbidden when user email is not verified', async () => {
      // 1. Service-level check: an AuthenticatedUser with emailConfirmed: false is rejected
      const unverifiedCustomer: AuthenticatedUser = {
        id: testUsers[0].id,
        email: testUsers[0].email,
        role: Role.CUSTOMER,
        emailConfirmed: false,
      };

      await expect(
        orderService.checkout(unverifiedCustomer, {
          addressId: testUsers[0].addressId,
        })
      ).rejects.toThrow('Email verification is required before checkout. Please verify your email.');

      // 2. Route-level check: when user has unverified email in Supabase Auth, checkout returns 403
      const spyGetUser = vi.spyOn(supabaseAdmin.auth, 'getUser').mockResolvedValueOnce({
        data: {
          user: {
            id: testUsers[0].id,
            email: testUsers[0].email,
            email_confirmed_at: null, // Unverified email!
            app_metadata: {},
            user_metadata: { name: 'Harden Tester' },
            aud: 'authenticated',
            created_at: new Date().toISOString(),
          } as never,
        },
        error: null,
      });

      try {
        const req = new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${testUsers[0].token}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': `idemp-unverified-${Date.now()}`,
          },
          body: JSON.stringify({ addressId: testUsers[0].addressId }),
        });

        const res = await checkoutRoute(req, {} as never);
        expect(res.status).toBe(403);

        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
        expect(body.error.message).toContain('verified');
      } finally {
        spyGetUser.mockRestore();
      }
    });
  });

  // ----------------------------------------------------------------------------
  // Test (e): Unavailable line gives a 409 with nothing created
  // ----------------------------------------------------------------------------
  describe('(e) Unavailable Line Gives 409 With Nothing Created', () => {
    it('aborts checkout with 409 Conflict listing problem lines, creating no orders and preserving stock', async () => {
      const user = testUsers[3];

      // 1. Create an out-of-stock variant
      const outOfStockVariant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-OUTOFSTOCK-${Date.now()}`,
          size: '44R',
          color: 'Midnight Silk',
          priceInCents: 150000,
          stockQuantity: 0, // OUT OF STOCK
          active: true,
        },
      });
      createdVariantIds.push(outOfStockVariant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, outOfStockVariant.id, 1);

      const ordersCountBefore = await prisma.order.count({ where: { profileId: user.id } });

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-unavailable-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: user.addressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(409);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.CONFLICT);
      expect(body.error.details.problemLines).toBeDefined();
      expect(body.error.details.problemLines[0].productVariantId).toBe(outOfStockVariant.id);

      // Verify no order was created
      const ordersCountAfter = await prisma.order.count({ where: { profileId: user.id } });
      expect(ordersCountAfter).toBe(ordersCountBefore);

      // Verify stock remained unchanged
      const freshVariant = await prisma.productVariant.findUnique({
        where: { id: outOfStockVariant.id },
      });
      expect(freshVariant!.stockQuantity).toBe(0);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (f): Payment failure restocks
  // ----------------------------------------------------------------------------
  describe('(f) Payment Failure Restocks Exactly Once', () => {
    it('restocks inventory and marks order CANCELLED upon immediate payment simulation failure', async () => {
      const user = testUsers[4];

      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-FAIL-SIM-${Date.now()}`,
          size: '42R',
          color: 'Cobalt Blue',
          priceInCents: 85000,
          stockQuantity: 5,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 2);

      const mockFailProvider = new MockStripePaymentProvider();
      mockFailProvider.setSimulation('failed');
      orderService.setPaymentProvider(mockFailProvider);

      try {
        const req = new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${user.token}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': `idemp-fail-sim-${Date.now()}`,
          },
          body: JSON.stringify({
            addressId: user.addressId,
          }),
        });

        const res = await checkoutRoute(req, {} as never);
        expect(res.status).toBe(201);
        const body = await res.json();
        const order = body.data.order;
        createdOrderIds.push(order.id);

        // Status must be CANCELLED and payment FAILED
        expect(order.status).toBe(OrderStatus.CANCELLED);
        expect(body.data.paymentRecord.status).toBe(PaymentStatus.FAILED);

        // Inventory stock must have been restored back to 5!
        const freshVariant = await prisma.productVariant.findUnique({
          where: { id: variant.id },
        });
        expect(freshVariant!.stockQuantity).toBe(5);

        // Status history row must be written
        const history = await prisma.orderStatusHistory.findMany({
          where: { orderId: order.id },
        });
        expect(history.length).toBeGreaterThanOrEqual(1);
        expect(history.some((h) => h.toStatus === OrderStatus.CANCELLED)).toBe(true);
      } finally {
        orderService.setPaymentProvider(new MockStripePaymentProvider());
      }
    });

    it('rejects checkout request body containing paymentSimulation with 422 Unprocessable Entity', async () => {
      const user = testUsers[0];
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-reject-sim-hardening-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: user.addressId,
          paymentSimulation: 'failed',
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('throws error when trying to inject mock payment provider in production environment', () => {
      const originalEnv = process.env.NODE_ENV;
      try {
        (process.env as any).NODE_ENV = 'production';
        const mockProvider = new MockStripePaymentProvider();
        expect(() => orderService.setPaymentProvider(mockProvider)).toThrow(
          'Cannot inject mock payment provider in production'
        );
      } finally {
        (process.env as any).NODE_ENV = originalEnv;
      }
    });

    it('restocks inventory exactly once when payment failure arrives via webhook', async () => {
      const user = testUsers[0];

      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-FAIL-HOOK-${Date.now()}`,
          size: '40L',
          color: 'Charcoal Pinstripe',
          priceInCents: 115000,
          stockQuantity: 4,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 1);

      // Create pending order
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-fail-hook-prep-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: user.addressId,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      const body = await res.json();
      const orderId = body.data.order.id;
      const paymentRef = body.data.paymentIntent.id;
      createdOrderIds.push(orderId);

      // Stock was decremented to 3
      const afterCheckout = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(afterCheckout!.stockQuantity).toBe(3);

      // Dispatch failure webhook
      const webhookPayload = JSON.stringify({
        id: `evt_fail_test_${Date.now()}`,
        type: 'payment_intent.payment_failed',
        data: {
          object: {
            id: paymentRef,
            orderId,
            amountInCents: 115000,
            currency: 'usd',
            status: 'failed',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const sig = paymentProvider.generateWebhookSignature(webhookPayload, DEFAULT_WEBHOOK_SECRET);

      const hookReq = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': sig,
        },
        body: webhookPayload,
      });

      const hookRes = await webhookRoute(hookReq, {} as never);
      expect(hookRes.status).toBe(200);

      // Stock must be restored to 4 (+1)
      const afterWebhook = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(afterWebhook!.stockQuantity).toBe(4);

      // Order status is CANCELLED
      const updatedOrder = await prisma.order.findUnique({ where: { id: orderId } });
      expect(updatedOrder!.status).toBe(OrderStatus.CANCELLED);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (g): 2 concurrent cancels restock once
  // ----------------------------------------------------------------------------
  describe('(g) 2 Concurrent Cancels Restock Exactly Once', () => {
    it('(g) 2 concurrent cancels restock once', async () => {
      const user = testUsers[1];

      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-2CONCUR-CANCEL-${Date.now()}`,
          size: '42R',
          color: 'Dark Navy',
          priceInCents: 90000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 2);

      // Checkout 2 units -> Stock becomes 8
      const checkoutReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-2cancel-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: user.addressId }),
      });

      const checkoutRes = await checkoutRoute(checkoutReq, {} as never);
      const checkoutBody = await checkoutRes.json();
      const orderId = checkoutBody.data.order.id;
      createdOrderIds.push(orderId);

      const stockAfterCheckout = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(stockAfterCheckout!.stockQuantity).toBe(8);

      // Dispatch 2 concurrent cancel requests
      const cancelReq1 = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${user.token}` },
      });
      const cancelReq2 = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${user.token}` },
      });

      const [res1, res2] = await Promise.all([
        cancelOrderRoute(cancelReq1, { params: Promise.resolve({ id: orderId }) }),
        cancelOrderRoute(cancelReq2, { params: Promise.resolve({ id: orderId }) }),
      ]);

      // Both requests should conclude safely with 200
      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);

      // Crucial: Stock must be restored to 10 (+2), NOT 12 (+4)!
      const stockAfterCancels = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(stockAfterCancels!.stockQuantity).toBe(10);
    });

    it('enforces owner-only policy on POST /api/orders/[id]/cancel with no admin override', async () => {
      const user = testUsers[2];

      const variant = await prisma.productVariant.findFirst({
        where: { active: true, product: { status: ProductStatus.ACTIVE } },
      });

      await clearCart(user.id);
      await addToCartDirect(user.id, variant!.id, 1);

      // Create order for user
      const checkoutResult = await orderService.checkout(
        { id: user.id, email: user.email, role: Role.CUSTOMER, emailConfirmed: true },
        { addressId: user.addressId },
        `idemp-admin-cancel-check-${Date.now()}`
      );
      const orderId = checkoutResult.order.id;
      createdOrderIds.push(orderId);

      // Admin attempts to cancel Customer's order via POST /api/orders/[id]/cancel
      const adminCancelReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      const adminCancelRes = await cancelOrderRoute(adminCancelReq, { params: Promise.resolve({ id: orderId }) });
      // Must be 403 Forbidden!
      expect(adminCancelRes.status).toBe(403);
      const body = await adminCancelRes.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('owner');
    });
  });

  // ----------------------------------------------------------------------------
  // Test (h): Replayed webhook event and wrong-amount event do nothing
  // ----------------------------------------------------------------------------
  describe('(h) Replayed Webhook & Wrong-Amount Event Protections', () => {
    let webhookOrderId: string;
    let webhookPaymentRef: string;
    let expectedTotal: number;

    beforeAll(async () => {
      const user = testUsers[3];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `SKU-TEST-HOOK-H-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          size: '40R',
          color: 'Charcoal',
          priceInCents: 150000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-hook-h-prep-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: user.addressId,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      const body = await res.json();
      webhookOrderId = body.data.order.id;
      webhookPaymentRef = body.data.paymentIntent.id;
      expectedTotal = body.data.order.totalInCents;
      createdOrderIds.push(webhookOrderId);
    });

    it('does nothing when a webhook event has a wrong/mismatched amount', async () => {
      const wrongAmountPayload = JSON.stringify({
        id: `evt_wrong_amount_${Date.now()}`,
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: webhookPaymentRef,
            orderId: webhookOrderId,
            amountInCents: expectedTotal - 5000, // Mismatched amount! ($50 less)
            currency: 'usd',
            status: 'succeeded',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const sig = paymentProvider.generateWebhookSignature(wrongAmountPayload, DEFAULT_WEBHOOK_SECRET);

      const req = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': sig,
        },
        body: wrongAmountPayload,
      });

      const res = await webhookRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.data.status).toBe('amount_mismatch_no_op');

      // Order must REMAIN in PENDING status! (NOT updated to PAID!)
      const order = await prisma.order.findUnique({ where: { id: webhookOrderId } });
      expect(order!.status).toBe(OrderStatus.PENDING);
    });

    it('treats a replayed webhook event ID as an idempotent no-op', async () => {
      const replayEventId = `evt_dedupe_test_${Date.now()}`;

      const payload = JSON.stringify({
        id: replayEventId,
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: webhookPaymentRef,
            orderId: webhookOrderId,
            amountInCents: expectedTotal,
            currency: 'usd',
            status: 'succeeded',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const sig = paymentProvider.generateWebhookSignature(payload, DEFAULT_WEBHOOK_SECRET);

      const makeReq = () =>
        new NextRequest('http://localhost:3000/api/webhooks/payments', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Stripe-Signature': sig,
          },
          body: payload,
        });

      // First delivery: transitions order to PAID
      const res1 = await webhookRoute(makeReq(), {} as never);
      expect(res1.status).toBe(200);
      const body1 = await res1.json();
      expect(body1.data.status).toBe('succeeded');

      const historyCountAfterFirst = await prisma.orderStatusHistory.count({
        where: { orderId: webhookOrderId },
      });

      // Second delivery (Replay): must be a no-op!
      const res2 = await webhookRoute(makeReq(), {} as never);
      expect(res2.status).toBe(200);
      const body2 = await res2.json();
      expect(body2.data.status).toBe('replayed_no_op');

      // Crucial: No extra status history row written
      const historyCountAfterSecond = await prisma.orderStatusHistory.count({
        where: { orderId: webhookOrderId },
      });
      expect(historyCountAfterSecond).toBe(historyCountAfterFirst);
    });
  });

  // ----------------------------------------------------------------------------
  // Test (6): Scheduled-Safe Cancellation Function
  // ----------------------------------------------------------------------------
  describe('(6) Scheduled-Safe Pending Order Cancellation Function', () => {
    it('cancels PENDING orders older than N minutes and restocks inventory with audit trail', async () => {
      const user = testUsers[4];

      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-EXPIRE-CRON-${Date.now()}`,
          size: '38S',
          color: 'Charcoal Tweed',
          priceInCents: 105000,
          stockQuantity: 5,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 2);

      // 1. Checkout an order (stock decrements from 5 to 3)
      const checkoutReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${user.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-expire-test-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: user.addressId }),
      });

      const checkoutRes = await checkoutRoute(checkoutReq, {} as never);
      const checkoutBody = await checkoutRes.json();
      const expiredOrderId = checkoutBody.data.order.id;
      createdOrderIds.push(expiredOrderId);

      // Verify stock decremented to 3
      const stockAfterOrder = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(stockAfterOrder!.stockQuantity).toBe(3);

      // 2. Backdate the order's createdAt by 45 minutes
      const fortyFiveMinutesAgo = new Date(Date.now() - 45 * 60 * 1000);
      await prisma.order.update({
        where: { id: expiredOrderId },
        data: { createdAt: fortyFiveMinutesAgo },
      });

      // 3. Execute scheduled cleanup function for orders older than 30 minutes
      const result = await orderService.cancelExpiredPendingOrders(30);
      expect(result.totalFound).toBeGreaterThanOrEqual(1);
      expect(result.cancelledCount).toBeGreaterThanOrEqual(1);

      const ourOrderResult = result.results.find((r) => r.orderId === expiredOrderId);
      expect(ourOrderResult).toBeDefined();
      expect(ourOrderResult!.success).toBe(true);

      // 4. Verify order is now CANCELLED in database
      const finalOrder = await prisma.order.findUnique({ where: { id: expiredOrderId } });
      expect(finalOrder!.status).toBe(OrderStatus.CANCELLED);

      // 5. Verify stock was restored (+2) back to 5!
      const finalStock = await prisma.productVariant.findUnique({ where: { id: variant.id } });
      expect(finalStock!.stockQuantity).toBe(5);

      // 6. Verify status history row was recorded with changedBy: 'system_scheduler'
      const history = await prisma.orderStatusHistory.findMany({
        where: { orderId: expiredOrderId, changedBy: 'system_scheduler' },
      });
      expect(history.length).toBe(1);
      expect(history[0].toStatus).toBe(OrderStatus.CANCELLED);
    });
  });

  // ----------------------------------------------------------------------------
  // Item 2: Checkout with addressId & ownership verification
  // ----------------------------------------------------------------------------
  describe('Checkout with addressId & Ownership Verification', () => {
    let userAAddressId: string;
    let userBAddressId: string;

    beforeAll(async () => {
      // Create address for User 0
      const addrA = await prisma.address.create({
        data: {
          profileId: testUsers[0].id,
          recipientName: 'Lord Harrington',
          line1: '12 Savile Row',
          city: 'London',
          state: 'London',
          postalCode: 'W1S 3PB',
          country: 'GB',
          phone: '+442079460001',
        },
      });
      userAAddressId = addrA.id;

      // Create address for User 1
      const addrB = await prisma.address.create({
        data: {
          profileId: testUsers[1].id,
          recipientName: 'Baroness Beaumont',
          line1: '88 Jermyn Street',
          city: 'London',
          state: 'London',
          postalCode: 'SW1Y 6JD',
          country: 'GB',
          phone: '+442079460002',
        },
      });
      userBAddressId = addrB.id;
    });

    afterAll(async () => {
      await prisma.address.deleteMany({
        where: { id: { in: [userAAddressId, userBAddressId].filter(Boolean) } },
      });
    });

    it('rejects checkout with 403 Forbidden when using another user addressId', async () => {
      const userA = testUsers[0];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `SKU-TEST-FORBID-ADDR-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          size: '42R',
          color: 'Navy',
          priceInCents: 160000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(userA.id);
      await addToCartDirect(userA.id, variant.id, 1);

      // User A attempts to checkout using User B's addressId!
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${userA.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-forbidden-addr-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: userBAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('not belong');
    });

    it('successfully checks out with valid owned addressId and snapshots encrypted fields', async () => {
      const userA = testUsers[0];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `SKU-TEST-OWNED-ADDR-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          size: '42L',
          color: 'Black',
          priceInCents: 170000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(userA.id);
      await addToCartDirect(userA.id, variant.id, 1);

      // User A checks out using their OWN addressId
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${userA.token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-owned-addr-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: userAAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(201);
      const body = await res.json();
      const order = body.data.order;
      createdOrderIds.push(order.id);

      // Verify decrypted address matches the address book record
      expect(order.shippingAddress.recipientName).toBe('Lord Harrington');
      expect(order.shippingAddress.streetLine1).toBe('12 Savile Row');

      // Verify database stored address is encrypted at rest
      const rawOrder = await prisma.order.findUnique({ where: { id: order.id } });
      const rawAddress = rawOrder!.shippingAddress as any;
      expect(rawAddress.streetLine1).toContain(':'); // encrypted iv:ciphertext:tag format
    });
  });

  // ----------------------------------------------------------------------------
  // Item 3: Webhook State Edge Cases: Cancelled & Paid Orders
  // ----------------------------------------------------------------------------
  describe('Webhook State Edge Cases: Cancelled & Paid Orders', () => {
    it('succeeded webhook on a CANCELLED order does not change status and writes NEEDS_REFUND audit log', async () => {
      const user = testUsers[3];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `SKU-TEST-CAN-HOOK-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          size: '40S',
          color: 'Midnight',
          priceInCents: 180000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 1);

      // 1. Create a pending order
      const checkoutResult = await orderService.checkout(
        { id: user.id, email: user.email, role: Role.CUSTOMER, emailConfirmed: true },
        { addressId: user.addressId },
        `idemp-cancel-refund-hook-${Date.now()}`
      );
      const orderId = checkoutResult.order.id;
      const paymentRef = checkoutResult.paymentIntent!.id;
      createdOrderIds.push(orderId);

      // 2. Cancel the order before payment arrives
      await orderService.cancelOrder(
        { id: user.id, email: user.email, role: Role.CUSTOMER, emailConfirmed: true },
        orderId
      );

      const orderBeforeHook = await prisma.order.findUnique({ where: { id: orderId } });
      expect(orderBeforeHook!.status).toBe(OrderStatus.CANCELLED);

      // 3. Webhook delivery: payment succeeded on this CANCELLED order
      const payload = JSON.stringify({
        id: `evt_succeed_on_cancelled_${Date.now()}`,
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: paymentRef,
            orderId,
            amountInCents: checkoutResult.order.totalInCents,
            currency: 'usd',
            status: 'succeeded',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const sig = paymentProvider.generateWebhookSignature(payload, DEFAULT_WEBHOOK_SECRET);
      const hookReq = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': sig,
        },
        body: payload,
      });

      const hookRes = await webhookRoute(hookReq, {} as never);
      expect(hookRes.status).toBe(200);
      const hookBody = await hookRes.json();
      expect(hookBody.data.flag).toBe('NEEDS_REFUND');

      // Crucial: Order status must REMAIN CANCELLED (never updated to PAID!)
      const orderAfterHook = await prisma.order.findUnique({ where: { id: orderId } });
      expect(orderAfterHook!.status).toBe(OrderStatus.CANCELLED);

      // Crucial: Audit log flagged NEEDS_REFUND must be recorded
      const auditLog = await prisma.auditLog.findFirst({
        where: {
          entityId: orderId,
          action: 'NEEDS_REFUND',
        },
      });
      expect(auditLog).toBeDefined();
      expect((auditLog!.metadata as any).flag).toBe('NEEDS_REFUND');
    });

    it('failed webhook on a PAID order does not cancel order or restock inventory', async () => {
      const user = testUsers[4];
      const variant = await prisma.productVariant.create({
        data: {
          productId: testProductId,
          sku: `DA-PAID-FAIL-HOOK-${Date.now()}`,
          size: '42L',
          color: 'Lapis Blue',
          priceInCents: 95000,
          stockQuantity: 10,
          active: true,
        },
      });
      createdVariantIds.push(variant.id);

      await clearCart(user.id);
      await addToCartDirect(user.id, variant.id, 2);

      const mockSuccessProvider = new MockStripePaymentProvider();
      mockSuccessProvider.setSimulation('succeeded');
      orderService.setPaymentProvider(mockSuccessProvider);

      try {
        // 1. Create a paid order (Stock decrements from 10 to 8)
        const checkoutResult = await orderService.checkout(
          { id: user.id, email: user.email, role: Role.CUSTOMER, emailConfirmed: true },
          { addressId: user.addressId },
          `idemp-paid-fail-hook-${Date.now()}`
        );
        const orderId = checkoutResult.order.id;
        const paymentRef = checkoutResult.paymentIntent!.id;
        createdOrderIds.push(orderId);

        const orderBeforeHook = await prisma.order.findUnique({ where: { id: orderId } });
        expect(orderBeforeHook!.status).toBe(OrderStatus.PAID);

        const stockBeforeHook = await prisma.productVariant.findUnique({ where: { id: variant.id } });
        expect(stockBeforeHook!.stockQuantity).toBe(8);

        // 2. Deliver late payment_failed webhook on already PAID order
        const payload = JSON.stringify({
          id: `evt_failed_on_paid_${Date.now()}`,
          type: 'payment_intent.payment_failed',
          data: {
            object: {
              id: paymentRef,
              orderId,
              amountInCents: checkoutResult.order.totalInCents,
              currency: 'usd',
              status: 'failed',
            },
          },
          created: Math.floor(Date.now() / 1000),
        });

        const sig = paymentProvider.generateWebhookSignature(payload, DEFAULT_WEBHOOK_SECRET);
        const hookReq = new NextRequest('http://localhost:3000/api/webhooks/payments', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Stripe-Signature': sig,
          },
          body: payload,
        });

        const hookRes = await webhookRoute(hookReq, {} as never);
        expect(hookRes.status).toBe(200);
        const hookBody = await hookRes.json();
        expect(hookBody.data.status).toBe('already_paid_ignored');

        // Crucial: Order status must REMAIN PAID! (NOT cancelled)
        const orderAfterHook = await prisma.order.findUnique({ where: { id: orderId } });
        expect(orderAfterHook!.status).toBe(OrderStatus.PAID);

        // Crucial: Stock must NOT be restocked (remains 8, NOT 10!)
        const stockAfterHook = await prisma.productVariant.findUnique({ where: { id: variant.id } });
        expect(stockAfterHook!.stockQuantity).toBe(8);
      } finally {
        orderService.setPaymentProvider(new MockStripePaymentProvider());
      }
    });
  });
});
