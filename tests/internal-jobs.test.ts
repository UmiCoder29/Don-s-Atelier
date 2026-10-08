import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as cancelExpiredOrdersRoute, GET as getRoute } from '@/app/api/internal/jobs/cancel-expired-orders/route';
import { prisma } from '@/lib/db/prisma';
import { OrderStatus, ProductStatus, Role } from '@prisma/client';
import { orderService } from '@/services/order/order-service';
import { findOrphanedCustomOrderUploads } from '@/services/bespoke/attachment-sanitizer';
import { AUTH_ACCESS_COOKIE } from '@/lib/auth/cookies';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';

describe('Scheduled Internal Jobs API (tests/internal-jobs.test.ts)', { timeout: 60000 }, () => {
  const TEST_VALID_CRON_SECRET = 'this_is_a_very_secure_test_cron_secret_32_chars_long!';
  const originalCronSecret = process.env.CRON_SECRET;

  const customerEmail = 'job.test.customer@example.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  let customerId: string;
  let customerToken: string;
  let testProductId: string;
  let testVariantId: string;

  const createdOrderIds: string[] = [];
  const createdVariantIds: string[] = [];

  beforeAll(async () => {
    // 1. Authenticate test customer
    const client = createSupabaseUserClient();
    const { data: authData, error: authError } = await client.auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });

    if (authError || !authData.session) {
      // Find or create customer
      const existing = await prisma.profile.findFirst({ where: { role: Role.CUSTOMER } });
      if (!existing) throw new Error('No test customer found');
      customerId = existing.id;
      customerToken = 'test-token-placeholder';
    } else {
      customerToken = authData.session.access_token;
      const profile = await prisma.profile.findUniqueOrThrow({ where: { id: authData.user.id } });
      customerId = profile.id;
    }

    // 2. Locate active product
    const product = await prisma.product.findFirst({
      where: { status: ProductStatus.ACTIVE },
    });
    if (!product) throw new Error('No active product found for test');
    testProductId = product.id;

    // 3. Create test variant with known stock
    const variant = await prisma.productVariant.create({
      data: {
        productId: testProductId,
        sku: `VAR-JOB-TEST-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        size: '42R',
        color: 'Navy',
        priceInCents: 150000,
        stockQuantity: 10,
        active: true,
      },
    });
    testVariantId = variant.id;
    createdVariantIds.push(variant.id);
  });

  afterAll(async () => {
    // Cleanup created orders and variants
    for (const orderId of createdOrderIds) {
      await prisma.auditLog.deleteMany({ where: { entityId: orderId } });
      await prisma.orderStatusHistory.deleteMany({ where: { orderId } });
      await prisma.orderItem.deleteMany({ where: { orderId } });
      await prisma.payment.deleteMany({ where: { orderId } });
      await prisma.order.deleteMany({ where: { id: orderId } });
    }
    for (const varId of createdVariantIds) {
      await prisma.productVariant.deleteMany({ where: { id: varId } });
    }
    // Restore original env
    if (originalCronSecret !== undefined) {
      process.env.CRON_SECRET = originalCronSecret;
    } else {
      delete process.env.CRON_SECRET;
    }
  });

  beforeEach(() => {
    process.env.CRON_SECRET = TEST_VALID_CRON_SECRET;
  });

  it('no header -> rejects with 401 Unauthorized', async () => {
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error).toBeDefined();
  });

  it('wrong secret -> rejects with 401 Unauthorized', async () => {
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer wrong_secret_that_is_long_enough_32_characters_here!',
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('CRON_SECRET unset in env -> rejects with 503 Service Unavailable and cancels nothing', async () => {
    delete process.env.CRON_SECRET;

    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TEST_VALID_CRON_SECRET}`,
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(503);

    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('CRON_SECRET too short (<32 chars) -> rejects with 503 Service Unavailable', async () => {
    process.env.CRON_SECRET = 'short_secret_under_32_chars';

    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer short_secret_under_32_chars',
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(503);

    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('valid CUSTOMER or ADMIN session cookie without Bearer secret -> rejects with 401 Unauthorized', async () => {
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Cookie: `${AUTH_ACCESS_COOKIE}=${customerToken}`,
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('GET method -> rejects with 405 Method Not Allowed', async () => {
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${TEST_VALID_CRON_SECRET}`,
      },
    });

    const res = await getRoute(req, {} as never);
    expect(res.status).toBe(405);

    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('right secret runs successfully: cancels expired orders, restores stock, and returns counts only', async () => {
    // 1. Create a dummy expired order (PENDING and createdAt backdated by 45 minutes)
    const fortyFiveMinutesAgo = new Date(Date.now() - 45 * 60 * 1000);
    const expiredOrder = await prisma.order.create({
      data: {
        orderNumber: `DA-EXPIRE-${Date.now()}`,
        profileId: customerId,
        status: OrderStatus.PENDING,
        subtotalInCents: 300000,
        shippingInCents: 0,
        totalInCents: 300000,
        shippingAddress: { country: 'GB', city: 'London', streetLine1: 'Savile Row' },
        createdAt: fortyFiveMinutesAgo,
        items: {
          create: [
            {
              productVariantId: testVariantId,
              name: 'Test Suit for Expiry',
              size: '42R',
              color: 'Navy',
              quantity: 2,
              unitPriceInCents: 150000,
              subtotalInCents: 300000,
            },
          ],
        },
      },
    });
    createdOrderIds.push(expiredOrder.id);

    // Initial variant stock is 10
    const stockBefore = await prisma.productVariant.findUniqueOrThrow({ where: { id: testVariantId } });
    expect(stockBefore.stockQuantity).toBe(10);

    // 2. Call the scheduled job endpoint with valid Bearer CRON_SECRET
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TEST_VALID_CRON_SECRET}`,
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    // Response contains COUNTS only:
    expect(body.data).toBeDefined();
    expect(body.data.cancelledCount).toBeGreaterThanOrEqual(1);
    expect(body.data.orderId).toBeUndefined();
    expect(body.data.orderNumber).toBeUndefined();
    expect(body.data.orders).toBeUndefined();

    // 3. Verify stock was restored (+2 quantity restored)
    const stockAfter = await prisma.productVariant.findUniqueOrThrow({ where: { id: testVariantId } });
    expect(stockAfter.stockQuantity).toBe(12);

    // 4. Verify order is now CANCELLED in DB
    const finalOrder = await prisma.order.findUniqueOrThrow({ where: { id: expiredOrder.id } });
    expect(finalOrder.status).toBe(OrderStatus.CANCELLED);

    // 5. Verify audit log entry was written with actorKind SYSTEM
    const auditLogs = await prisma.auditLog.findMany({
      where: {
        action: 'SCHEDULED_CANCEL_EXPIRED_ORDERS',
        entityId: 'system_batch',
      },
      orderBy: { timestamp: 'desc' },
      take: 1,
    });
    expect(auditLogs.length).toBe(1);
    const meta = auditLogs[0].metadata as Record<string, unknown>;
    expect(meta.actorKind).toBe('SYSTEM');
    expect(meta.cancelledCount).toBeDefined();
  });

  it('idempotency: a second run immediately after cancels 0 additional orders', async () => {
    const req = new NextRequest('http://localhost:3000/api/internal/jobs/cancel-expired-orders', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TEST_VALID_CRON_SECRET}`,
      },
    });

    const res = await cancelExpiredOrdersRoute(req, {} as never);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.cancelledCount).toBe(0);
  });

  describe('Orphaned Uploads Inspection (findOrphanedCustomOrderUploads)', () => {
    it('correctly identifies untracked storage objects older than 24h and ignores recent or tracked objects with fakes', async () => {
      const now = Date.now();
      const twentyFiveHoursAgo = new Date(now - 25 * 60 * 60 * 1000);
      const twoHoursAgo = new Date(now - 2 * 60 * 60 * 1000);

      // Fake storage objects
      const fakeStorage = {
        storage: {
          from: () => ({
            list: async (prefix: string) => {
              if (prefix === 'custom-orders') {
                return { data: [{ name: 'user-alpha' }, { name: 'user-beta' }], error: null };
              }
              if (prefix === 'custom-orders/user-alpha') {
                return {
                  data: [
                    // Older than 24h, unreferenced -> should be identified as orphaned
                    { name: 'orphan-1.jpg', created_at: twentyFiveHoursAgo.toISOString(), metadata: { size: 1024 } },
                    // Recent (<24h), unreferenced -> should NOT be flagged
                    { name: 'recent-upload.jpg', created_at: twoHoursAgo.toISOString(), metadata: { size: 2048 } },
                    // Older than 24h, but tracked in DB -> should NOT be flagged
                    { name: 'tracked-file.jpg', created_at: twentyFiveHoursAgo.toISOString(), metadata: { size: 4096 } },
                  ],
                  error: null,
                };
              }
              if (prefix === 'custom-orders/user-beta') {
                return {
                  data: [
                    // Older than 24h, unreferenced -> should be identified
                    { name: 'orphan-2.png', created_at: twentyFiveHoursAgo.toISOString(), metadata: { size: 3000 } },
                  ],
                  error: null,
                };
              }
              return { data: [], error: null };
            },
          }),
        },
      };

      // Fake DB tracking only 'custom-orders/user-alpha/tracked-file.jpg'
      const fakeDb = {
        customOrderAttachment: {
          findMany: async () => [
            { storagePath: 'custom-orders/user-alpha/tracked-file.jpg' },
          ],
        },
      };

      const orphaned = await findOrphanedCustomOrderUploads({
        olderThanHours: 24,
        storageClient: fakeStorage as unknown as typeof supabaseAdmin,
        dbClient: fakeDb as unknown as typeof prisma,
      });

      expect(orphaned).toHaveLength(2);
      expect(orphaned.map((o) => o.storagePath).sort()).toEqual([
        'custom-orders/user-alpha/orphan-1.jpg',
        'custom-orders/user-beta/orphan-2.png',
      ].sort());

      expect(orphaned.find((o) => o.name === 'orphan-1.jpg')?.size).toBe(1024);
      expect(orphaned.find((o) => o.name === 'orphan-2.png')?.size).toBe(3000);
    });
  });
});
