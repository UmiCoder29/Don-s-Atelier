import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { POST as checkoutRoute } from '@/app/api/checkout/route';
import { POST as cancelOrderRoute } from '@/app/api/orders/[id]/cancel/route';
import { GET as getOrderById } from '@/app/api/orders/[id]/route';
import { PATCH as adminPatchOrderRoute } from '@/app/api/admin/orders/[id]/route';
import { GET as listOrders } from '@/app/api/orders/route';
import { POST as webhookRoute } from '@/app/api/webhooks/payments/route';
import { paymentProvider, MockStripePaymentProvider, DEFAULT_WEBHOOK_SECRET } from '@/services/payment';
import { orderService } from '@/services/order/order-service';
import { OrderStatus, PaymentStatus, ProductStatus } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { ErrorCode } from '@/lib/errors/error-codes';

describe('Checkout, Concurrency Hardening & Webhook Confirmation Suite', { timeout: 60000 }, () => {
  beforeEach(() => {
    rateLimiter.reset();
  });

  afterEach(() => {
    orderService.setPaymentProvider(new MockStripePaymentProvider());
  });
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;
  let customerAId: string;
  let customerBId: string;

  let testProductVariantId: string;
  let testVariantPrice: number;
  let createdOrderIds: string[] = [];
  let customerAAddressId: string;
  let customerBAddressId: string;

  const validShippingAddress = {
    recipientName: 'James Harrington',
    streetLine1: '10 Savile Row',
    city: 'London',
    stateOrProvince: 'Greater London',
    postalCode: 'W1S 3PB',
    country: 'GB',
    phone: '+442079460991',
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

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Sign in Customer A
    const { data: authA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    customerAToken = authA.session!.access_token;
    customerAId = authA.user!.id;

    // 2. Sign in Customer B
    const { data: authB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    customerBToken = authB.session!.access_token;
    customerBId = authB.user!.id;

    // 3. Sign in Admin
    const { data: authAdmin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    adminToken = authAdmin.session!.access_token;

    // 4. Provision address for Customer A and Customer B
    const addrA = await prisma.address.findFirst({ where: { profileId: customerAId } });
    customerAAddressId = addrA
      ? addrA.id
      : (
          await prisma.address.create({
            data: {
              profileId: customerAId,
              recipientName: 'James Harrington',
              line1: '10 Savile Row',
              city: 'London',
              state: 'Greater London',
              postalCode: 'W1S 3PB',
              country: 'GB',
              phone: '+442079460991',
            },
          })
        ).id;

    const addrB = await prisma.address.findFirst({ where: { profileId: customerBId } });
    customerBAddressId = addrB
      ? addrB.id
      : (
          await prisma.address.create({
            data: {
              profileId: customerBId,
              recipientName: 'Clara Beaumont',
              line1: '25 Place Vendome',
              city: 'Paris',
              state: 'Ile-de-France',
              postalCode: '75001',
              country: 'FR',
              phone: '+33142685500',
            },
          })
        ).id;

    // 5. Find active variant and ensure plenty of stock
    const variant = await prisma.productVariant.findFirst({
      where: { active: true, product: { status: ProductStatus.ACTIVE } },
    });
    if (!variant) throw new Error('No active test variant available');
    await prisma.productVariant.update({
      where: { id: variant.id },
      data: { stockQuantity: 50 },
    });
    testProductVariantId = variant.id;
    testVariantPrice = variant.priceInCents;
  });

  afterAll(async () => {
    // Cleanup any created test orders in batch
    if (createdOrderIds.length > 0) {
      await prisma.orderStatusHistory.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.payment.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.orderItem.deleteMany({ where: { orderId: { in: createdOrderIds } } });
      await prisma.order.deleteMany({ where: { id: { in: createdOrderIds } } });
    }
    // Clean customer carts
    await clearCart(customerAId);
    await clearCart(customerBId);
  }, 60000);

  describe('1. POST /api/checkout Security & Validation', () => {
    it('rejects unauthenticated requests with 401 Unauthorized', async () => {
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idemp-unauth-test-12345',
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(401);
    });

    it('rejects requests missing the Idempotency-Key header with 400 Bad Request', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          // No Idempotency-Key header!
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Idempotency-Key');
    });

    it('rejects checkout on an empty shopping bag with 400 Bad Request', async () => {
      await clearCart(customerAId);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idemp-empty-cart-test-12345',
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('empty shopping cart');
    });

    it('rejects invalid addressId with 422 ValidationError', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idemp-invalid-addr-test-12345',
        },
        body: JSON.stringify({
          addressId: 'not-a-valid-uuid',
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });

  describe('2. ACCEPTANCE: Tampered-Price Test', () => {
    it('rejects client-supplied price or discount fields with 422 ValidationError (Strict Zod Schema)', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idemp-tamper-price-12345',
        },
        body: JSON.stringify({
          addressId: customerAAddressId,
          priceInCents: 100, // Malicious client attempt: $1.00 suit!
          totalInCents: 100,
          subtotalInCents: 100,
          discountAmount: 90000,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('computes subtotal, shipping, and total strictly from database values, ignoring client bodies', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 2);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-authoritative-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: customerAAddressId,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);

      const order = body.data.order;
      createdOrderIds.push(order.id);

      const expectedSubtotal = testVariantPrice * 2;
      const expectedShipping = expectedSubtotal >= 100000 ? 0 : 2500;
      const expectedTotal = expectedSubtotal + expectedShipping;

      expect(order.subtotalInCents).toBe(expectedSubtotal);
      expect(order.shippingInCents).toBe(expectedShipping);
      expect(order.totalInCents).toBe(expectedTotal);
    });
  });

  describe('3. ACCEPTANCE: Duplicate-Submit Test', () => {
    it('replays identical order without duplicate database records or double stock decrements', async () => {
      // 1. Prepare Cart
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const initialVariant = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      const stockBefore = initialVariant!.stockQuantity;

      const idempotencyKey = `idemp-dup-submit-${Date.now()}`;

      const makeReq = () =>
        new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': idempotencyKey,
          },
          body: JSON.stringify({
            addressId: customerAAddressId,
          }),
        });

      // First submit
      const res1 = await checkoutRoute(makeReq(), {} as never);
      expect(res1.status).toBe(201);
      const body1 = await res1.json();
      expect(body1.success).toBe(true);
      const orderId1 = body1.data.order.id;
      createdOrderIds.push(orderId1);

      // Stock should have decremented by 1
      const stockAfterFirst = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      expect(stockAfterFirst!.stockQuantity).toBe(stockBefore - 1);

      // Duplicate submit with identical idempotency key
      const res2 = await checkoutRoute(makeReq(), {} as never);
      expect(res2.status).toBe(201);
      const body2 = await res2.json();
      expect(body2.success).toBe(true);
      expect(body2.data.order.id).toBe(orderId1);
      expect(body2.data.idempotentReplay).toBe(true);

      // Crucial: Stock must NOT have decremented a second time!
      const stockAfterSecond = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      expect(stockAfterSecond!.stockQuantity).toBe(stockBefore - 1);

      // Ensure exactly ONE order exists with this idempotency key
      const orderCount = await prisma.order.count({ where: { idempotencyKey } });
      expect(orderCount).toBe(1);
    });
  });

  describe('4. ACCEPTANCE: Concurrency Test (Two Buyers, Last Item)', () => {
    it('prevents overselling when two buyers concurrently checkout the very last item in stock', async () => {
      // 1. Create a dedicated variant with exactly 1 unit of stock
      const activeProduct = await prisma.product.findFirst({
        where: { status: ProductStatus.ACTIVE },
      });
      const uniqueSku = `DA-TEST-CONCUR-${Date.now()}`;

      const singleStockVariant = await prisma.productVariant.create({
        data: {
          productId: activeProduct!.id,
          sku: uniqueSku,
          size: `42R-${Date.now()}`,
          color: `Charcoal Black ${Date.now()}`,
          priceInCents: 85000,
          stockQuantity: 1, // EXACTLY 1 IN STOCK
          active: true,
        },
      });

      // 2. Both Customer A and Customer B put this last item in their carts
      await clearCart(customerAId);
      await clearCart(customerBId);

      await addToCartDirect(customerAId, singleStockVariant.id, 1);
      await addToCartDirect(customerBId, singleStockVariant.id, 1);

      // 3. Prepare simultaneous checkout requests
      const reqA = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-concur-A-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const reqB = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-concur-B-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerBAddressId }),
      });

      // 4. Fire both checkouts simultaneously
      const [resA, resB] = await Promise.all([
        checkoutRoute(reqA, {} as never),
        checkoutRoute(reqB, {} as never),
      ]);

      // Exactly ONE request must succeed (201) and ONE must fail with 409 Conflict
      const statuses = [resA.status, resB.status].sort();
      expect(statuses).toEqual([201, 409]);

      const winningRes = resA.status === 201 ? resA : resB;
      const losingRes = resA.status === 409 ? resA : resB;

      const winningBody = await winningRes.json();
      expect(winningBody.success).toBe(true);
      createdOrderIds.push(winningBody.data.order.id);

      const losingBody = await losingRes.json();
      expect(losingBody.success).toBe(false);
      expect(losingBody.error.code).toBe(ErrorCode.CONFLICT);
      expect(losingBody.error.message).toContain('unavailable or out of stock');

      // 5. Verify database stock: Must be exactly 0 (NOT -1)
      const finalVariant = await prisma.productVariant.findUnique({
        where: { id: singleStockVariant.id },
      });
      expect(finalVariant!.stockQuantity).toBe(0);

      // Clean up test variant
      await prisma.productVariant.delete({ where: { id: singleStockVariant.id } });
    });
  });

  describe('5. MockPaymentProvider Simulation', () => {
    it('creates PaymentIntent and Payment record in ONE single transaction', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-payment-test-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: customerAAddressId,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      const order = body.data.order;
      createdOrderIds.push(order.id);

      expect(order.payments).toHaveLength(1);
      expect(order.payments[0].provider).toBe('mock_stripe');
      expect(order.payments[0].status).toBe(PaymentStatus.PENDING);
      expect(body.data.paymentIntent.id).toMatch(/^pi_mock_/);
    });

    it('supports immediate payment success simulation via injected provider', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const mockSuccessProvider = new MockStripePaymentProvider();
      mockSuccessProvider.setSimulation('succeeded');
      orderService.setPaymentProvider(mockSuccessProvider);

      try {
        const req = new NextRequest('http://localhost:3000/api/checkout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': `idemp-sim-succ-${Date.now()}`,
          },
          body: JSON.stringify({
            addressId: customerAAddressId,
          }),
        });

        const res = await checkoutRoute(req, {} as never);
        expect(res.status).toBe(201);

        const body = await res.json();
        const order = body.data.order;
        createdOrderIds.push(order.id);

        expect(order.status).toBe(OrderStatus.PAID);
        expect(order.payments[0].status).toBe(PaymentStatus.SUCCEEDED);
      } finally {
        orderService.setPaymentProvider(new MockStripePaymentProvider());
      }
    });

    it('rejects a body containing paymentSimulation with 422 Unprocessable Entity', async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-reject-sim-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: customerAAddressId,
          paymentSimulation: 'succeeded',
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('throws error when attempting to inject mock payment provider in production environment', () => {
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
  });

  describe('6. Webhook-Style Confirmation Route with Signature Verification', () => {
    let webhookOrderId: string;
    let webhookPaymentRef: string;
    let webhookOrderTotal: number;

    beforeAll(async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-webhook-prep-${Date.now()}`,
        },
        body: JSON.stringify({
          addressId: customerAAddressId,
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      const body = await res.json();
      webhookOrderId = body.data.order.id;
      webhookPaymentRef = body.data.paymentIntent.id;
      webhookOrderTotal = body.data.order.totalInCents;
      createdOrderIds.push(webhookOrderId);
    });

    it('rejects webhooks missing the signature header with 400 Bad Request', async () => {
      const payload = JSON.stringify({
        id: 'evt_test_1',
        type: 'payment_intent.succeeded',
        data: { object: { id: webhookPaymentRef } },
        created: Math.floor(Date.now() / 1000),
      });

      const req = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
      });

      const res = await webhookRoute(req, {} as never);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.error.message).toContain('Missing payment provider webhook signature');
    });

    it('rejects webhooks with an invalid/forged signature with 400 Bad Request', async () => {
      const payload = JSON.stringify({
        id: 'evt_test_2',
        type: 'payment_intent.succeeded',
        data: { object: { id: webhookPaymentRef } },
        created: Math.floor(Date.now() / 1000),
      });

      const req = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': 't=12345,v1=bad_forged_signature_hex_0000000000000000000000000000000000000000',
        },
        body: payload,
      });

      const res = await webhookRoute(req, {} as never);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.error.message).toContain('Invalid payment provider webhook signature');
    });

    it('verifies valid HMAC signature and transitions Order status from PENDING to PAID', async () => {
      const payload = JSON.stringify({
        id: `evt_${Date.now()}`,
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: webhookPaymentRef,
            orderId: webhookOrderId,
            amountInCents: webhookOrderTotal,
            currency: 'usd',
            status: 'succeeded',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const validSig = paymentProvider.generateWebhookSignature(payload, DEFAULT_WEBHOOK_SECRET);

      const req = new NextRequest('http://localhost:3000/api/webhooks/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': validSig,
        },
        body: payload,
      });

      const res = await webhookRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('succeeded');

      // Verify order status in database is now PAID
      const updatedOrder = await prisma.order.findUnique({
        where: { id: webhookOrderId },
        include: { payments: true },
      });
      expect(updatedOrder!.status).toBe(OrderStatus.PAID);
      expect(updatedOrder!.payments[0].status).toBe(PaymentStatus.SUCCEEDED);
    });
  });

  describe('7. Order History & Detail Routes (Owner or Admin Only)', () => {
    let customerAOrderId: string;

    beforeAll(async () => {
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-hist-prep-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const res = await checkoutRoute(req, {} as never);
      const body = await res.json();
      customerAOrderId = body.data.order.id;
      createdOrderIds.push(customerAOrderId);
    });

    it('allows Customer A to view their own order detail via GET /api/orders/[id]', async () => {
      const req = new NextRequest(`http://localhost:3000/api/orders/${customerAOrderId}`, {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });

      const res = await getOrderById(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe(customerAOrderId);
    });

    it('denies Customer B from viewing Customer A order with 403 Forbidden', async () => {
      const req = new NextRequest(`http://localhost:3000/api/orders/${customerAOrderId}`, {
        headers: { Authorization: `Bearer ${customerBToken}` },
      });

      const res = await getOrderById(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    it('allows ADMIN to view Customer A order detail via GET /api/orders/[id]', async () => {
      const req = new NextRequest(`http://localhost:3000/api/orders/${customerAOrderId}`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      const res = await getOrderById(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe(customerAOrderId);
    });

    it('lists orders filtered to the authenticated customer on GET /api/orders', async () => {
      const req = new NextRequest('http://localhost:3000/api/orders', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });

      const res = await listOrders(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      for (const order of body.data) {
        expect(order.profileId).toBe(customerAId);
      }
    });
  });

  describe('8. Customer Cancellation & Stock Restoration', () => {
    it('allows customer to cancel order before PROCESSING and restores inventory stock', async () => {
      // 1. Checkout an item
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 2);

      const variantBefore = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      const stockBeforeCheckout = variantBefore!.stockQuantity;

      const checkoutReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-cancel-test-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const checkoutRes = await checkoutRoute(checkoutReq, {} as never);
      const checkoutBody = await checkoutRes.json();
      const orderId = checkoutBody.data.order.id;
      createdOrderIds.push(orderId);

      // Verify stock decremented by 2
      const stockAfterCheckout = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      expect(stockAfterCheckout!.stockQuantity).toBe(stockBeforeCheckout - 2);

      // 2. Customer cancels order via POST /api/orders/[id]/cancel
      const cancelReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });

      const cancelRes = await cancelOrderRoute(cancelReq, { params: Promise.resolve({ id: orderId }) });
      expect(cancelRes.status).toBe(200);

      const cancelBody = await cancelRes.json();
      expect(cancelBody.success).toBe(true);
      expect(cancelBody.data.status).toBe(OrderStatus.CANCELLED);

      // 3. Crucial: Verify inventory stock is restored (+2)
      const stockAfterCancel = await prisma.productVariant.findUnique({
        where: { id: testProductVariantId },
      });
      expect(stockAfterCancel!.stockQuantity).toBe(stockBeforeCheckout);
    });

    it('rejects customer cancellation once order enters PROCESSING', async () => {
      // 1. Checkout an item
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const checkoutReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-proc-cancel-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const checkoutRes = await checkoutRoute(checkoutReq, {} as never);
      const checkoutBody = await checkoutRes.json();
      const orderId = checkoutBody.data.order.id;
      createdOrderIds.push(orderId);

      // 2. Admin advances order from PENDING to PAID, then to PROCESSING
      const adminPaidReq = new NextRequest(`http://localhost:3000/api/admin/orders/${orderId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: OrderStatus.PAID, reason: 'Manual payment verification' }),
      });
      const paidRes = await adminPatchOrderRoute(adminPaidReq, { params: Promise.resolve({ id: orderId }) });
      expect(paidRes.status).toBe(200);

      const adminPatchReq = new NextRequest(`http://localhost:3000/api/admin/orders/${orderId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: OrderStatus.PROCESSING }),
      });

      const patchRes = await adminPatchOrderRoute(adminPatchReq, { params: Promise.resolve({ id: orderId }) });
      expect(patchRes.status).toBe(200);

      // 3. Customer attempts to cancel order -> Must be REJECTED!
      const cancelReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });

      const cancelRes = await cancelOrderRoute(cancelReq, { params: Promise.resolve({ id: orderId }) });
      expect(cancelRes.status).toBe(400);

      const cancelBody = await cancelRes.json();
      expect(cancelBody.success).toBe(false);
      expect(cancelBody.error.message).toContain('only allowed before processing');
    });

    it('denies Customer B from cancelling Customer A order with 403 Forbidden', async () => {
      // 1. Checkout an item for Customer A
      await clearCart(customerAId);
      await addToCartDirect(customerAId, testProductVariantId, 1);

      const checkoutReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-cross-cancel-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: customerAAddressId }),
      });

      const checkoutRes = await checkoutRoute(checkoutReq, {} as never);
      const checkoutBody = await checkoutRes.json();
      const orderId = checkoutBody.data.order.id;
      createdOrderIds.push(orderId);

      // 2. Customer B attempts to cancel Customer A's order -> 403 Forbidden
      const cancelReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });

      const cancelRes = await cancelOrderRoute(cancelReq, { params: Promise.resolve({ id: orderId }) });
      expect(cancelRes.status).toBe(403);

      const cancelBody = await cancelRes.json();
      expect(cancelBody.success).toBe(false);
      expect(cancelBody.error.code).toBe(ErrorCode.FORBIDDEN);
    });
  });
});
