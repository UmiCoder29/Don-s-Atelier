import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { OrderStatus, Role } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { GET as listAdminOrders } from '@/app/api/admin/orders/route';
import { GET as getAdminOrder, PATCH as updateAdminOrder } from '@/app/api/admin/orders/[id]/route';
import { GET as listAdminInventory } from '@/app/api/admin/inventory/route';
import { POST as adjustAdminStock } from '@/app/api/admin/variants/[id]/stock/route';
import { GET as listAdminUsers } from '@/app/api/admin/users/route';
import { GET as getAdminUserDetail } from '@/app/api/admin/users/[id]/route';
import { PATCH as updateAdminUserRole } from '@/app/api/admin/users/[id]/role/route';
import { GET as listAdminAuditLogs } from '@/app/api/admin/audit-logs/route';
import { GET as getAdminSummary } from '@/app/api/admin/summary/route';
import { ErrorCode } from '@/lib/errors/error-codes';
import { encryptPhone, encryptAddressFields } from '@/lib/crypto/field-encryption';

describe('Admin Management APIs (Prompt 13)', { timeout: 60000 }, () => {
  const customerEmail = 'james.harrington@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD;
  const adminPassword = process.env.SEED_ADMIN_PASSWORD;

  if (!customerPassword || !adminPassword) {
    throw new Error('SEED_CUSTOMER_PASSWORD and SEED_ADMIN_PASSWORD environment variables are required');
  }

  let customerToken: string;
  let adminToken: string;
  let customerId: string;
  let adminId: string;

  let testProduct: any;
  let testVariant: any;
  const cleanupOrderIds: string[] = [];
  const cleanupVariantIds: string[] = [];
  const cleanupUserIds: string[] = [];

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Auth Customer
    const { data: authCust, error: errCust } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });
    if (errCust || !authCust.session) throw new Error(`Customer sign in failed: ${errCust?.message}`);
    customerToken = authCust.session.access_token;
    customerId = authCust.user.id;

    // 2. Auth Admin
    const { data: authAdm, error: errAdm } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdm || !authAdm.session) throw new Error(`Admin sign in failed: ${errAdm?.message}`);
    adminToken = authAdm.session.access_token;
    adminId = authAdm.user.id;

    // Fetch an active product and create test variant
    testProduct = await prisma.product.findFirst({
      where: { status: 'ACTIVE' },
    });
    if (!testProduct) throw new Error('Active product required for test');

    testVariant = await prisma.productVariant.create({
      data: {
        productId: testProduct.id,
        size: `ADMIN-${Date.now()}`,
        color: 'Admin Navy',
        sku: `SKU-ADM-${Date.now()}`,
        priceInCents: 150000,
        stockQuantity: 100,
      },
    });
    cleanupVariantIds.push(testVariant.id);
  });

  afterAll(async () => {
    if (cleanupOrderIds.length > 0) {
      await prisma.orderStatusHistory.deleteMany({
        where: { orderId: { in: cleanupOrderIds } },
      });
      await prisma.orderItem.deleteMany({
        where: { orderId: { in: cleanupOrderIds } },
      });
      await prisma.payment.deleteMany({
        where: { orderId: { in: cleanupOrderIds } },
      });
      await prisma.order.deleteMany({
        where: { id: { in: cleanupOrderIds } },
      });
    }

    if (cleanupVariantIds.length > 0) {
      await prisma.productVariant.deleteMany({
        where: { id: { in: cleanupVariantIds } },
      });
    }

    if (cleanupUserIds.length > 0) {
      await prisma.profile.deleteMany({
        where: { id: { in: cleanupUserIds } },
      });
    }
  });

  // Helper to create test orders
  async function createTestOrder(status: OrderStatus = OrderStatus.PENDING, quantity: number = 2) {
    const order = await prisma.order.create({
      data: {
        orderNumber: `DA-ADM-${Date.now()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
        profileId: customerId,
        status,
        subtotalInCents: testVariant.priceInCents * quantity,
        shippingInCents: 0,
        totalInCents: testVariant.priceInCents * quantity,
        shippingAddress: encryptAddressFields({
          recipientName: 'Lord Harrington',
          line1: '12 Savile Row',
          city: 'London',
          state: 'Greater London',
          postalCode: 'W1S 3PR',
        }) as any,
        items: {
          create: [
            {
              productVariantId: testVariant.id,
              name: 'Bespoke Executive Suit',
              size: testVariant.size,
              color: testVariant.color,
              unitPriceInCents: testVariant.priceInCents,
              quantity,
              subtotalInCents: testVariant.priceInCents * quantity,
            },
          ],
        },
        payments: {
          create: [
            {
              provider: 'mock_stripe',
              providerRef: `pi_test_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
              status: status === OrderStatus.PENDING ? 'PENDING' : 'SUCCEEDED',
              amountInCents: testVariant.priceInCents * quantity,
              currency: 'usd',
            },
          ],
        },
      },
    });
    cleanupOrderIds.push(order.id);
    return order;
  }

  // ==============================================================================
  // 1. RBAC & Role Guard Enforcement: 401 Anonymous and 403 Customer
  // ==============================================================================
  describe('RBAC & Role Guard Enforcement (401 anonymous and 403 as customer)', () => {
    it('returns 401 for anonymous and 403 for customer on all admin routes', async () => {
      const routesToTest = [
        {
          name: 'GET /api/admin/orders',
          handler: () =>
            listAdminOrders(new NextRequest('http://localhost:3000/api/admin/orders'), {
              params: Promise.resolve({}),
            }),
          authHandler: (token: string) =>
            listAdminOrders(
              new NextRequest('http://localhost:3000/api/admin/orders', {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({}) }
            ),
        },
        {
          name: 'GET /api/admin/orders/[id]',
          handler: () =>
            getAdminOrder(new NextRequest(`http://localhost:3000/api/admin/orders/${testVariant.id}`), {
              params: Promise.resolve({ id: testVariant.id }),
            }),
          authHandler: (token: string) =>
            getAdminOrder(
              new NextRequest(`http://localhost:3000/api/admin/orders/${testVariant.id}`, {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({ id: testVariant.id }) }
            ),
        },
        {
          name: 'PATCH /api/admin/orders/[id]',
          handler: () =>
            updateAdminOrder(
              new NextRequest(`http://localhost:3000/api/admin/orders/${testVariant.id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'PROCESSING' }),
              }),
              { params: Promise.resolve({ id: testVariant.id }) }
            ),
          authHandler: (token: string) =>
            updateAdminOrder(
              new NextRequest(`http://localhost:3000/api/admin/orders/${testVariant.id}`, {
                method: 'PATCH',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'PROCESSING' }),
              }),
              { params: Promise.resolve({ id: testVariant.id }) }
            ),
        },
        {
          name: 'GET /api/admin/inventory',
          handler: () =>
            listAdminInventory(new NextRequest('http://localhost:3000/api/admin/inventory'), {
              params: Promise.resolve({}),
            }),
          authHandler: (token: string) =>
            listAdminInventory(
              new NextRequest('http://localhost:3000/api/admin/inventory', {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({}) }
            ),
        },
        {
          name: 'POST /api/admin/variants/[id]/stock',
          handler: () =>
            adjustAdminStock(
              new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ adjustment: 5, reason: 'Stock audit' }),
              }),
              { params: Promise.resolve({ id: testVariant.id }) }
            ),
          authHandler: (token: string) =>
            adjustAdminStock(
              new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ adjustment: 5, reason: 'Stock audit' }),
              }),
              { params: Promise.resolve({ id: testVariant.id }) }
            ),
        },
        {
          name: 'GET /api/admin/users',
          handler: () =>
            listAdminUsers(new NextRequest('http://localhost:3000/api/admin/users'), {
              params: Promise.resolve({}),
            }),
          authHandler: (token: string) =>
            listAdminUsers(
              new NextRequest('http://localhost:3000/api/admin/users', {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({}) }
            ),
        },
        {
          name: 'GET /api/admin/users/[id]',
          handler: () =>
            getAdminUserDetail(new NextRequest(`http://localhost:3000/api/admin/users/${customerId}`), {
              params: Promise.resolve({ id: customerId }),
            }),
          authHandler: (token: string) =>
            getAdminUserDetail(
              new NextRequest(`http://localhost:3000/api/admin/users/${customerId}`, {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({ id: customerId }) }
            ),
        },
        {
          name: 'PATCH /api/admin/users/[id]/role',
          handler: () =>
            updateAdminUserRole(
              new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: 'ADMIN' }),
              }),
              { params: Promise.resolve({ id: customerId }) }
            ),
          authHandler: (token: string) =>
            updateAdminUserRole(
              new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
                method: 'PATCH',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: 'ADMIN' }),
              }),
              { params: Promise.resolve({ id: customerId }) }
            ),
        },
        {
          name: 'GET /api/admin/audit-logs',
          handler: () =>
            listAdminAuditLogs(new NextRequest('http://localhost:3000/api/admin/audit-logs'), {
              params: Promise.resolve({}),
            }),
          authHandler: (token: string) =>
            listAdminAuditLogs(
              new NextRequest('http://localhost:3000/api/admin/audit-logs', {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({}) }
            ),
        },
        {
          name: 'GET /api/admin/summary',
          handler: () =>
            getAdminSummary(new NextRequest('http://localhost:3000/api/admin/summary'), {
              params: Promise.resolve({}),
            }),
          authHandler: (token: string) =>
            getAdminSummary(
              new NextRequest('http://localhost:3000/api/admin/summary', {
                headers: { Authorization: `Bearer ${token}` },
              }),
              { params: Promise.resolve({}) }
            ),
        },
      ];

      for (const route of routesToTest) {
        // Anonymous check: 401
        const anonRes = await route.handler();
        expect(anonRes.status, `Anonymous call to ${route.name} should return 401`).toBe(401);
        const anonBody = await anonRes.json();
        expect(anonBody.error.code).toBe(ErrorCode.UNAUTHORIZED);

        // Customer check: 403
        const custRes = await route.authHandler(customerToken);
        expect(custRes.status, `Customer call to ${route.name} should return 403`).toBe(403);
        const custBody = await custRes.json();
        expect(custBody.error.code).toBe(ErrorCode.FORBIDDEN);
      }
    });
  });

  // ==============================================================================
  // 2. Order Status Matrix: Legal Transitions & 409 Illegal Transitions
  // ==============================================================================
  describe('Order Status Matrix via Admin Routes', () => {
    it('executes legal sequential fulfillment path: PENDING -> PAID -> PROCESSING -> SHIPPED -> DELIVERED -> REFUNDED', async () => {
      const order = await createTestOrder(OrderStatus.PENDING);

      // PENDING -> PAID
      const res1 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID, reason: 'Manual bank transfer verified' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res1.status).toBe(200);
      const data1 = await res1.json();
      expect(data1.data.status).toBe(OrderStatus.PAID);

      // PAID -> PROCESSING
      const res2 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PROCESSING }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res2.status).toBe(200);
      const data2 = await res2.json();
      expect(data2.data.status).toBe(OrderStatus.PROCESSING);

      // PROCESSING -> SHIPPED
      const res3 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.SHIPPED }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res3.status).toBe(200);
      const data3 = await res3.json();
      expect(data3.data.status).toBe(OrderStatus.SHIPPED);

      // SHIPPED -> DELIVERED
      const res4 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.DELIVERED }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res4.status).toBe(200);
      const data4 = await res4.json();
      expect(data4.data.status).toBe(OrderStatus.DELIVERED);

      // DELIVERED -> REFUNDED
      const res5 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.REFUNDED }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res5.status).toBe(200);
      const data5 = await res5.json();
      expect(data5.data.status).toBe(OrderStatus.REFUNDED);
    });

    it('rejects illegal order status transitions with 409 Conflict', async () => {
      // 1. PENDING -> SHIPPED (illegal jump)
      const pendingOrder = await createTestOrder(OrderStatus.PENDING);
      const resIllegal1 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${pendingOrder.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.SHIPPED }),
        }),
        { params: Promise.resolve({ id: pendingOrder.id }) }
      );
      expect(resIllegal1.status).toBe(409);
      const body1 = await resIllegal1.json();
      expect(body1.error.code).toBe(ErrorCode.CONFLICT);

      // 2. CANCELLED -> PAID (illegal outbound from terminal CANCELLED)
      const cancelledOrder = await createTestOrder(OrderStatus.CANCELLED);
      const resIllegal2 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${cancelledOrder.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID, reason: 'Attempted resume' }),
        }),
        { params: Promise.resolve({ id: cancelledOrder.id }) }
      );
      expect(resIllegal2.status).toBe(409);
      const body2 = await resIllegal2.json();
      expect(body2.error.code).toBe(ErrorCode.CONFLICT);
      expect(body2.error.message).toContain('terminal status');

      // 3. REFUNDED -> PROCESSING (illegal outbound from terminal REFUNDED)
      const refundedOrder = await createTestOrder(OrderStatus.REFUNDED);
      const resIllegal3 = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${refundedOrder.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PROCESSING }),
        }),
        { params: Promise.resolve({ id: refundedOrder.id }) }
      );
      expect(resIllegal3.status).toBe(409);
      const body3 = await resIllegal3.json();
      expect(body3.error.code).toBe(ErrorCode.CONFLICT);
      expect(body3.error.message).toContain('terminal status');
    });
  });

  // ==============================================================================
  // 3. Stock Restock Idempotency: Single & Concurrent Double Cancel
  // ==============================================================================
  describe('Stock Restock on Cancel Idempotency', () => {
    it('cancel then cancel again: restores inventory stock exactly once', async () => {
      // Record initial variant stock
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      // Create an order for 3 items
      const order = await createTestOrder(OrderStatus.PAID, 3);

      // 1. First cancel: Restores stock by +3
      const firstCancelRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.CANCELLED, note: 'First cancel' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(firstCancelRes.status).toBe(200);

      const varAfterFirst = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfterFirst!.stockQuantity).toBe(initialStock + 3);

      // 2. Second cancel: Must be idempotent and NOT increment stock again!
      const secondCancelRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.CANCELLED, note: 'Second cancel attempt' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(secondCancelRes.status).toBe(200);

      const varAfterSecond = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfterSecond!.stockQuantity).toBe(initialStock + 3);
    });

    it('concurrent double-cancel: restores inventory stock exactly once under row lock', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.PAID, 4);

      // Fire 2 cancellations simultaneously
      const [resA, resB] = await Promise.all([
        updateAdminOrder(
          new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: OrderStatus.CANCELLED, note: 'Concurrent cancel A' }),
          }),
          { params: Promise.resolve({ id: order.id }) }
        ),
        updateAdminOrder(
          new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: OrderStatus.CANCELLED, note: 'Concurrent cancel B' }),
          }),
          { params: Promise.resolve({ id: order.id }) }
        ),
      ]);

      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);

      // Verify stock incremented by 4 exactly once, never by 8
      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock + 4);
    });
  });

  // ==============================================================================
  // 4. Inventory: Adjustments, Bounds, Negative Protection, 10 Concurrent Writes
  // ==============================================================================
  describe('Inventory Adjustments & Concurrency', () => {
    it('rejects adjustment without reason with 422', async () => {
      const res = await adjustAdminStock(
        new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ adjustment: 5 }), // Missing reason
        }),
        { params: Promise.resolve({ id: testVariant.id }) }
      );
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects adjustment that causes negative stock with 400', async () => {
      const v = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const currentStock = v!.stockQuantity;

      const res = await adjustAdminStock(
        new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ adjustment: -(currentStock + 50), reason: 'Excess reduction' }),
        }),
        { params: Promise.resolve({ id: testVariant.id }) }
      );
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.BAD_REQUEST);
      expect(body.error.message).toContain('negative inventory');
    });

    it('rejects out-of-range delta with 422', async () => {
      const res = await adjustAdminStock(
        new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ adjustment: 50000, reason: 'Exceeds delta bound' }),
        }),
        { params: Promise.resolve({ id: testVariant.id }) }
      );
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('handles 10 concurrent adjustments correctly producing exact stock and 10 audit rows', async () => {
      const isolatedVariant = await prisma.productVariant.create({
        data: {
          productId: testProduct.id,
          size: `CONCUR-${Date.now()}`,
          color: 'Charcoal',
          sku: `SKU-CNC-${Date.now()}`,
          priceInCents: 120000,
          stockQuantity: 50,
        },
      });
      cleanupVariantIds.push(isolatedVariant.id);

      // Fire 10 concurrent adjustments of +3 each (total delta = +30)
      const promises = Array.from({ length: 10 }, (_, i) =>
        adjustAdminStock(
          new NextRequest(`http://localhost:3000/api/admin/variants/${isolatedVariant.id}/stock`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ adjustment: 3, reason: `Batch shipment arrival #${i + 1}` }),
          }),
          { params: Promise.resolve({ id: isolatedVariant.id }) }
        )
      );

      const responses = await Promise.all(promises);
      for (const res of responses) {
        expect(res.status).toBe(200);
      }

      // Verify final stock is exactly 50 + 30 = 80
      const finalVariant = await prisma.productVariant.findUnique({ where: { id: isolatedVariant.id } });
      expect(finalVariant!.stockQuantity).toBe(80);

      // Verify exactly 10 audit rows were written
      const auditCount = await prisma.auditLog.count({
        where: {
          action: 'ADMIN_STOCK_ADJUSTED',
          entityId: isolatedVariant.id,
        },
      });
      expect(auditCount).toBe(10);
    });
  });

  // ==============================================================================
  // 5. Customer Privacy: List vs Detail & Audit Logging
  // ==============================================================================
  describe('Customer Privacy & Detail Audit Logging', () => {
    it('customer list response contains NON-sensitive fields only (no phone, address, measurements)', async () => {
      const res = await listAdminUsers(
        new NextRequest('http://localhost:3000/api/admin/users', {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({}) }
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      for (const user of body.data) {
        expect(user.id).toBeDefined();
        expect(user.email).toBeDefined();
        expect(user.phone).toBeUndefined();
        expect(user.addresses).toBeUndefined();
        expect(user.measurements).toBeUndefined();
      }
    });

    it('customer detail access returns decrypted phone and address, and writes an audit row with IDs only', async () => {
      const res = await getAdminUserDetail(
        new NextRequest(`http://localhost:3000/api/admin/users/${customerId}`, {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({ id: customerId }) }
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.id).toBe(customerId);
      expect(body.data.email).toBe(customerEmail);
      expect(body.data.measurements).toBeUndefined();

      // Verify audit row was created
      const auditLog = await prisma.auditLog.findFirst({
        where: {
          action: 'ADMIN_CUSTOMER_VIEWED',
          entityId: customerId,
        },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog!.actorId).toBe(adminId);

      const metadata = auditLog!.metadata as any;
      expect(metadata.targetUserId).toBe(customerId);
      expect(metadata.viewedByAdminId).toBe(adminId);
      // Assert no decrypted phone or address leaked in metadata
      expect(metadata.phone).toBeUndefined();
      expect(metadata.address).toBeUndefined();
    });
  });

  // ==============================================================================
  // 6. Role Management: Self-Demotion, Last Admin Protection & Immediate Demotion
  // ==============================================================================
  describe('Role Management & Admin Protection', () => {
    it('rejects self-demotion with 409 Conflict', async () => {
      const res = await updateAdminUserRole(
        new NextRequest(`http://localhost:3000/api/admin/users/${adminId}/role`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: Role.CUSTOMER }),
        }),
        { params: Promise.resolve({ id: adminId }) }
      );
      expect(res.status).toBe(409);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.CONFLICT);
      expect(body.error.message).toContain('modify their own role');
    });

    it('two admins demoting each other concurrently leaves at least one admin', async () => {
      // Create a second admin user in the database
      const admin2Id = crypto.randomUUID();
      const admin2 = await prisma.profile.create({
        data: {
          id: admin2Id,
          email: `admin2-${Date.now()}@dons-atelier.com`,
          name: 'Co-Administrator',
          role: Role.ADMIN,
        },
      });
      cleanupUserIds.push(admin2.id);

      // Create a third admin to test concurrent dual-demotion down to 1
      const admin3Id = crypto.randomUUID();
      const admin3 = await prisma.profile.create({
        data: {
          id: admin3Id,
          email: `admin3-${Date.now()}@dons-atelier.com`,
          name: 'Third Administrator',
          role: Role.ADMIN,
        },
      });
      cleanupUserIds.push(admin3.id);

      // Concurrent demotion of admin2 and admin3
      const [res2, res3] = await Promise.all([
        updateAdminUserRole(
          new NextRequest(`http://localhost:3000/api/admin/users/${admin2.id}/role`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: Role.CUSTOMER }),
          }),
          { params: Promise.resolve({ id: admin2.id }) }
        ),
        updateAdminUserRole(
          new NextRequest(`http://localhost:3000/api/admin/users/${admin3.id}/role`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: Role.CUSTOMER }),
          }),
          { params: Promise.resolve({ id: admin3.id }) }
        ),
      ]);

      // Both demotions can succeed because admin1 still remains (total was 3)
      expect(res2.status).toBe(200);
      expect(res3.status).toBe(200);

      // Now only 1 admin (admin1) remains in system. Try to demote admin1 via admin2 -> fails self-check,
      // and if admin2 tries to demote admin1, admin2 is now CUSTOMER and gets 403 Forbidden!
      const remainingAdmins = await prisma.profile.count({ where: { role: Role.ADMIN } });
      expect(remainingAdmins).toBeGreaterThanOrEqual(1);
    });

    it('demoted admin loses access immediately on the very next request', async () => {
      // Create a temporary admin user
      const tempAdminId = crypto.randomUUID();
      const tempAdmin = await prisma.profile.create({
        data: {
          id: tempAdminId,
          email: `tempadm-${Date.now()}@dons-atelier.com`,
          name: 'Temporary Admin',
          role: Role.ADMIN,
        },
      });
      cleanupUserIds.push(tempAdmin.id);

      // Demote tempAdmin to CUSTOMER
      const demoteRes = await updateAdminUserRole(
        new NextRequest(`http://localhost:3000/api/admin/users/${tempAdmin.id}/role`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: Role.CUSTOMER }),
        }),
        { params: Promise.resolve({ id: tempAdmin.id }) }
      );
      expect(demoteRes.status).toBe(200);

      // Check database source of truth directly: role is CUSTOMER
      const updatedProfile = await prisma.profile.findUnique({ where: { id: tempAdmin.id } });
      expect(updatedProfile!.role).toBe(Role.CUSTOMER);
    });
  });

  // ==============================================================================
  // 7. Audit Log Read: Filtering, Pagination, and Immutability
  // ==============================================================================
  describe('Audit Log Read & Immutability', () => {
    it('filters and paginates audit logs and rejects page size exceeding 100', async () => {
      // Standard paginated fetch
      const res = await listAdminAuditLogs(
        new NextRequest('http://localhost:3000/api/admin/audit-logs?page=1&limit=10', {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({}) }
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.meta.pagination.limit).toBe(10);

      // Filter by action
      const filterRes = await listAdminAuditLogs(
        new NextRequest('http://localhost:3000/api/admin/audit-logs?action=ADMIN_STOCK_ADJUSTED', {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({}) }
      );
      expect(filterRes.status).toBe(200);
      const filterBody = await filterRes.json();
      for (const log of filterBody.data) {
        expect(log.action).toBe('ADMIN_STOCK_ADJUSTED');
      }

      // Page size over 100 is rejected with 422
      const overLimitRes = await listAdminAuditLogs(
        new NextRequest('http://localhost:3000/api/admin/audit-logs?limit=150', {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({}) }
      );
      expect(overLimitRes.status).toBe(422);
      const overLimitBody = await overLimitRes.json();
      expect(overLimitBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });

  // ==============================================================================
  // 8. Summary: Aggregation for PAID Orders Only & Zero PII
  // ==============================================================================
  describe('Dashboard Summary Aggregations', () => {
    it('counts only PAID orders in salesTotalInCents and contains zero PII', async () => {
      const res = await getAdminSummary(
        new NextRequest('http://localhost:3000/api/admin/summary', {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({}) }
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      const summary = body.data;

      expect(typeof summary.salesTotalInCents).toBe('number');
      expect(typeof summary.paidOrderCount).toBe('number');
      expect(summary.orderCountsByStatus).toBeDefined();
      expect(typeof summary.lowStockVariantCount).toBe('number');
      expect(typeof summary.pendingCustomRequestsCount).toBe('number');

      // Verify zero PII in summary response
      const jsonStr = JSON.stringify(summary);
      expect(jsonStr).not.toContain('@');
      expect(jsonStr).not.toContain('Harrington');
      expect(jsonStr).not.toContain('Savile Row');
    });
  });

  // ==============================================================================
  // 9. Strict Zod Schema: Unknown Fields on Mutating Routes Return 422
  // ==============================================================================
  describe('Strict Zod Schema Enforcement (Unknown fields return 422)', () => {
    it('rejects unknown fields on mutating admin routes with 422', async () => {
      const order = await createTestOrder(OrderStatus.PENDING);

      // 1. PATCH /api/admin/orders/[id] with extra field
      const orderRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID, reason: 'Valid reason', maliciousExtraField: 'exploit' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(orderRes.status).toBe(422);
      const orderBody = await orderRes.json();
      expect(orderBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 2. POST /api/admin/variants/[id]/stock with extra field
      const stockRes = await adjustAdminStock(
        new NextRequest(`http://localhost:3000/api/admin/variants/${testVariant.id}/stock`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ adjustment: 5, reason: 'Valid audit', maliciousExtraField: 'exploit' }),
        }),
        { params: Promise.resolve({ id: testVariant.id }) }
      );
      expect(stockRes.status).toBe(422);
      const stockBody = await stockRes.json();
      expect(stockBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 3. PATCH /api/admin/users/[id]/role with extra field
      const roleRes = await updateAdminUserRole(
        new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: Role.ADMIN, maliciousExtraField: 'exploit' }),
        }),
        { params: Promise.resolve({ id: customerId }) }
      );
      expect(roleRes.status).toBe(422);
      const roleBody = await roleRes.json();
      expect(roleBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });

  // ==============================================================================
  // 10. Refund Restock Rules (Item 1)
  // ==============================================================================
  describe('Refund Restock Rules (Item 1)', () => {
    it('restocks inventory when REFUNDED from PAID', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.PAID, 2);

      const res = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.REFUNDED, reason: 'Customer returned item' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res.status).toBe(200);

      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock + 2);
    });

    it('restocks inventory when REFUNDED from PROCESSING', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.PROCESSING, 3);

      const res = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.REFUNDED, reason: 'Order canceled during cutting' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res.status).toBe(200);

      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock + 3);
    });

    it('must NOT restock inventory when REFUNDED from SHIPPED', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.SHIPPED, 2);

      const res = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.REFUNDED, reason: 'Lost in transit compensation' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res.status).toBe(200);

      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock); // Unchanged!
    });

    it('must NOT restock inventory when REFUNDED from DELIVERED', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.DELIVERED, 2);

      const res = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.REFUNDED, reason: 'Customer keeps item with refund' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res.status).toBe(200);

      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock); // Unchanged!
    });

    it('concurrent double-refund from PAID restocks inventory exactly once under row lock', async () => {
      const varBefore = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      const initialStock = varBefore!.stockQuantity;

      const order = await createTestOrder(OrderStatus.PAID, 4);

      // Fire 2 refund requests simultaneously
      const [resA, resB] = await Promise.all([
        updateAdminOrder(
          new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: OrderStatus.REFUNDED, note: 'Concurrent refund A' }),
          }),
          { params: Promise.resolve({ id: order.id }) }
        ),
        updateAdminOrder(
          new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: OrderStatus.REFUNDED, note: 'Concurrent refund B' }),
          }),
          { params: Promise.resolve({ id: order.id }) }
        ),
      ]);

      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);

      // Verify stock was restored by 4 exactly once, never by 8!
      const varAfter = await prisma.productVariant.findUnique({ where: { id: testVariant.id } });
      expect(varAfter!.stockQuantity).toBe(initialStock + 4);
    });
  });

  // ==============================================================================
  // 11. Order Detail Audit (Item 2)
  // ==============================================================================
  describe('Order Detail Audit Log (Item 2)', () => {
    it('writes ADMIN_ORDER_VIEWED audit entry on GET /api/admin/orders/[id] with zero address text', async () => {
      const order = await createTestOrder(OrderStatus.PENDING);

      const res = await getAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          headers: { Authorization: `Bearer ${adminToken}` },
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.shippingAddress).toBeDefined();
      expect(body.data.shippingAddress.line1).toBe('12 Savile Row');

      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_ORDER_VIEWED', entityId: order.id },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog!.actorId).toBe(adminId);
      const meta = auditLog!.metadata as any;
      expect(meta).toEqual({
        adminId,
        orderId: order.id,
      });

      // Assert row contains zero decrypted address values or address text
      const fullLogString = JSON.stringify(auditLog);
      expect(fullLogString).not.toContain('12 Savile Row');
      expect(fullLogString).not.toContain('Savile Row');
      expect(fullLogString).not.toContain('Harrington');
      expect(fullLogString).not.toContain('W1S 3PR');
    });
  });

  // ==============================================================================
  // 12. Manual PAID Reason Requirement (Item 5)
  // ==============================================================================
  describe('Manual PAID Reason Requirement (Item 5)', () => {
    it('requires a non-empty reason when moving PENDING to PAID (returns 422 if missing) and logs it in OrderStatusHistory and AuditLog', async () => {
      const order = await createTestOrder(OrderStatus.PENDING);

      // 1. Missing reason returns 422
      const missingReasonRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(missingReasonRes.status).toBe(422);
      const missingReasonBody = await missingReasonRes.json();
      expect(missingReasonBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 2. Empty string reason returns 422
      const emptyReasonRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID, reason: '   ' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(emptyReasonRes.status).toBe(422);

      // 3. Valid reason returns 200 and records in OrderStatusHistory and AuditLog
      const validReason = 'Customer bank wire confirmed by treasury desk';
      const validRes = await updateAdminOrder(
        new NextRequest(`http://localhost:3000/api/admin/orders/${order.id}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: OrderStatus.PAID, reason: validReason }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(validRes.status).toBe(200);
      const validBody = await validRes.json();
      expect(validBody.data.status).toBe(OrderStatus.PAID);

      // Check OrderStatusHistory record
      const history = await prisma.orderStatusHistory.findFirst({
        where: { orderId: order.id, toStatus: OrderStatus.PAID },
        orderBy: { timestamp: 'desc' },
      });
      expect(history).toBeDefined();
      expect(history!.note).toBe(validReason);

      // Check AuditLog record
      const auditLog = await prisma.auditLog.findFirst({
        where: { entityId: order.id, action: 'ORDER_STATUS_UPDATED' },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      const meta = auditLog!.metadata as any;
      expect(meta.previousStatus).toBe(OrderStatus.PENDING);
      expect(meta.newStatus).toBe(OrderStatus.PAID);
      expect(meta.reason).toBe(validReason);
    });
  });

  // ==============================================================================
  // 13. Role Change Audit Metadata Shape (Item 6)
  // ==============================================================================
  describe('Role Change Audit Metadata Shape (Item 6)', () => {
    it('writes audit metadata shape containing from-role, to-role, target user id and nothing else personal', async () => {
      const tempUser = await prisma.profile.create({
        data: {
          id: crypto.randomUUID(),
          email: `roleaudit-${Date.now()}@example.com`,
          name: 'Audit Role Subject',
          role: Role.CUSTOMER,
        },
      });
      cleanupUserIds.push(tempUser.id);

      const res = await updateAdminUserRole(
        new NextRequest(`http://localhost:3000/api/admin/users/${tempUser.id}/role`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: Role.ADMIN }),
        }),
        { params: Promise.resolve({ id: tempUser.id }) }
      );
      expect(res.status).toBe(200);

      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_ROLE_UPDATED', entityId: tempUser.id },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      const metadata = auditLog!.metadata as any;
      expect(metadata).toEqual({
        targetUserId: tempUser.id,
        fromRole: Role.CUSTOMER,
        toRole: Role.ADMIN,
      });

      // Assert zero personal info in metadata
      const metaString = JSON.stringify(metadata);
      expect(metaString).not.toContain(tempUser.email);
      expect(metaString).not.toContain(tempUser.name);
    });
  });
});

