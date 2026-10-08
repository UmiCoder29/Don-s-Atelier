import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { GET as listOrders } from '@/app/api/orders/route';
import { POST as checkoutOrder } from '@/app/api/checkout/route';
import { GET as getOrderById } from '@/app/api/orders/[id]/route';
import { ErrorCode } from '@/lib/errors/error-codes';
import { rateLimiter } from '@/lib/security/rate-limiter';

describe('Order & Checkout API Routes', { timeout: 60000 }, () => {
  beforeEach(() => {
    rateLimiter.reset();
  });
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;
  let adminId: string;
  let customerAId: string;
  let customerAAddressId: string;
  let testVariantId: string;
  let initialStock: number;
  let variantPriceInCents: number;
  let createdOrderId: string;
  const testIdempotencyKey = `idemp-test-checkout-${Date.now()}`;

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Auth Customer A
    const { data: authA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    customerAToken = authA.session!.access_token;
    customerAId = authA.user!.id;

    // 2. Auth Customer B
    const { data: authB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    customerBToken = authB.session!.access_token;

    // 3. Auth Admin
    const { data: authAdmin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    adminToken = authAdmin.session!.access_token;
    adminId = authAdmin.user!.id;

    // 4. Select a variant for checkout test
    const variant = await prisma.productVariant.findFirst({
      where: { active: true, stockQuantity: { gte: 10 } },
    });
    if (!variant) throw new Error('No test variant available');
    testVariantId = variant.id;
    initialStock = variant.stockQuantity;
    variantPriceInCents = variant.priceInCents;

    // 5. Provision address for Customer A
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
  });

  afterAll(async () => {
    if (createdOrderId) {
      await prisma.auditLog.deleteMany({ where: { entityId: createdOrderId } }).catch(() => {});
      await prisma.orderStatusHistory.deleteMany({ where: { orderId: createdOrderId } }).catch(() => {});
      await prisma.payment.deleteMany({ where: { orderId: createdOrderId } }).catch(() => {});
      await prisma.orderItem.deleteMany({ where: { orderId: createdOrderId } }).catch(() => {});
      await prisma.order.deleteMany({ where: { id: createdOrderId } }).catch(() => {});
    }
    // Restore stock if needed
    if (testVariantId) {
      await prisma.productVariant.update({
        where: { id: testVariantId },
        data: { stockQuantity: initialStock },
      }).catch(() => {});
    }
  });

  it('rejects checkout on an empty shopping cart with 400 BadRequestError', async () => {
    // Ensure cart is empty
    const cart = await prisma.cart.findUnique({ where: { profileId: customerAId } });
    if (cart) {
      await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
    }

    const req = new NextRequest('http://localhost:3000/api/checkout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': 'idemp-empty-cart-test',
      },
      body: JSON.stringify({
        addressId: customerAAddressId,
      }),
    });

    const res = await checkoutOrder(req, { params: Promise.resolve({}) });
    expect(res.status).toBe(400);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.BAD_REQUEST);
    expect(body.error.message).toContain('empty shopping cart');
  });

  it('executes checkout: computes totals from DB, decrements stock, creates order and payment intent', async () => {
    // 1. Put items in Customer A's cart directly in DB
    const cart = await prisma.cart.upsert({
      where: { profileId: customerAId },
      create: { profileId: customerAId },
      update: {},
    });

    await prisma.cartItem.create({
      data: {
        cartId: cart.id,
        productVariantId: testVariantId,
        quantity: 2,
      },
    });

    const currentVariant = await prisma.productVariant.findUnique({ where: { id: testVariantId } });
    initialStock = currentVariant!.stockQuantity;

    // 2. Execute checkout POST
    const req = new NextRequest('http://localhost:3000/api/checkout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': testIdempotencyKey,
      },
      // Note: Request body contains ZERO prices or totals!
      body: JSON.stringify({
        addressId: customerAAddressId,
        idempotencyKey: testIdempotencyKey,
      }),
    });

    const res = await checkoutOrder(req, { params: Promise.resolve({}) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);

    const order = body.data.order;
    createdOrderId = order.id;

    // Verify server-side computations
    const expectedSubtotal = variantPriceInCents * 2;
    const expectedShipping = expectedSubtotal >= 100000 ? 0 : 2500;
    const expectedTotal = expectedSubtotal + expectedShipping;

    expect(order.subtotalInCents).toBe(expectedSubtotal);
    expect(order.shippingInCents).toBe(expectedShipping);
    expect(order.totalInCents).toBe(expectedTotal);
    expect(order.orderNumber).toMatch(/^DA-\d{4}-[0-9A-F]{6}$/);

    // Verify stock decrement in database
    const updatedVariant = await prisma.productVariant.findUnique({ where: { id: testVariantId } });
    expect(updatedVariant?.stockQuantity).toBe(initialStock - 2);

    // Verify Payment Intent from mock provider
    const paymentIntent = body.data.paymentIntent;
    expect(paymentIntent.id).toMatch(/^pi_mock_/);
    expect(paymentIntent.amountInCents).toBe(expectedTotal);

    // Verify zero card data
    expect('cardLast4' in body.data).toBe(false);
    expect('cardBrand' in body.data).toBe(false);
  });

  it('replays identical order on duplicate idempotencyKey', async () => {
    const req = new NextRequest('http://localhost:3000/api/checkout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': testIdempotencyKey,
      },
      body: JSON.stringify({
        addressId: customerAAddressId,
        idempotencyKey: testIdempotencyKey,
      }),
    });

    const res = await checkoutOrder(req, { params: Promise.resolve({}) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.data.order.id).toBe(createdOrderId);
    expect(body.data.idempotentReplay).toBe(true);
  });

  it('enforces assertOwnerOrAdmin: Customer B is denied access to Customer A order with 403 Forbidden', async () => {
    const req = new NextRequest(`http://localhost:3000/api/orders/${createdOrderId}`, {
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
      },
    });

    const res = await getOrderById(req, { params: Promise.resolve({ id: createdOrderId }) });
    expect(res.status).toBe(403);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
  });

  it('allows Customer A to view their own order via /api/orders/[id] and writes NO ADMIN_ORDER_VIEWED audit entry', async () => {
    // Delete any previous audit entries for this order
    await prisma.auditLog.deleteMany({ where: { entityId: createdOrderId } });

    const req = new NextRequest(`http://localhost:3000/api/orders/${createdOrderId}`, {
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
      },
    });

    const res = await getOrderById(req, { params: Promise.resolve({ id: createdOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(createdOrderId);

    // Verify: owner opening their own order writes NO ADMIN_ORDER_VIEWED row
    const ownerAudit = await prisma.auditLog.findFirst({
      where: { entityId: createdOrderId, action: 'ADMIN_ORDER_VIEWED' },
    });
    expect(ownerAudit).toBeNull();
  });

  it('allows ADMIN to view Customer A order via /api/orders/[id] and writes ADMIN_ORDER_VIEWED audit entry with no address text', async () => {
    const req = new NextRequest(`http://localhost:3000/api/orders/${createdOrderId}`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
      },
    });

    const res = await getOrderById(req, { params: Promise.resolve({ id: createdOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(createdOrderId);
    // Response contains decrypted shipping address for admin
    expect(body.data.shippingAddress).toBeDefined();
    expect(body.data.shippingAddress.streetLine1 || body.data.shippingAddress.line1).toBe('10 Savile Row');

    // Verify: admin viewing customer order writes ADMIN_ORDER_VIEWED audit row
    const adminAudit = await prisma.auditLog.findFirst({
      where: { entityId: createdOrderId, action: 'ADMIN_ORDER_VIEWED' },
      orderBy: { timestamp: 'desc' },
    });
    expect(adminAudit).toBeDefined();
    expect(adminAudit?.actorId).toBe(adminId);
    const meta = adminAudit?.metadata as any;
    expect(meta).toEqual({
      adminId,
      orderId: createdOrderId,
    });

    // Assert row contains zero address text
    const fullLogString = JSON.stringify(adminAudit);
    expect(fullLogString).not.toContain('10 Savile Row');
    expect(fullLogString).not.toContain('Savile Row');
    expect(fullLogString).not.toContain('Harrington');
    expect(fullLogString).not.toContain('W1S 3PB');
  });

  it('lists orders isolated to authenticated customer on /api/orders', async () => {
    const req = new NextRequest('http://localhost:3000/api/orders', {
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
      },
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
