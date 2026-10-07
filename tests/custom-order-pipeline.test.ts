import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { CustomOrderStatus, Role } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';
import {
  validateStatusTransition,
  ALLOWED_TRANSITIONS,
  TERMINAL_STATUSES,
} from '@/services/bespoke/order-state-machine';
import { generateWhatsAppHandoffUrl } from '@/services/bespoke/whatsapp-handoff';
import { notificationService } from '@/services/notifications/notification-service';
import { GET as getCustomOrderById, PATCH as updateCustomOrder } from '@/app/api/custom-orders/[id]/route';
import { GET as listCustomOrders } from '@/app/api/custom-orders/route';
import { POST as acceptCustomOrderQuote } from '@/app/api/custom-orders/[id]/accept/route';
import { GET as getWhatsAppLink } from '@/app/api/custom-orders/[id]/whatsapp/route';
import { POST as withdrawCustomOrder } from '@/app/api/custom-orders/[id]/withdraw/route';
import { GET as adminListCustomOrders } from '@/app/api/admin/custom-orders/route';
import { GET as adminGetCustomOrder, PATCH as adminUpdateCustomOrder } from '@/app/api/admin/custom-orders/[id]/route';
import { ErrorCode } from '@/lib/errors/error-codes';
import { ConflictError, ForbiddenError } from '@/lib/errors/api-error';

describe('Custom Order Pipeline, State Machine & WhatsApp Handoff (Prompt 12)', () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD;
  const adminPassword = process.env.SEED_ADMIN_PASSWORD;

  if (!customerPassword || !adminPassword) {
    throw new Error('SEED_CUSTOMER_PASSWORD and SEED_ADMIN_PASSWORD environment variables are required');
  }

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;
  let customerAId: string;
  let customerBId: string;
  const cleanupOrderIds: string[] = [];

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Auth Customer A
    const { data: authA, error: errA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    if (errA || !authA.session) throw new Error(`Customer A sign in failed: ${errA?.message}`);
    customerAToken = authA.session.access_token;
    customerAId = authA.user.id;

    // 2. Auth Customer B
    const { data: authB, error: errB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    if (errB || !authB.session) throw new Error(`Customer B sign in failed: ${errB?.message}`);
    customerBToken = authB.session.access_token;
    customerBId = authB.user.id;

    // 3. Auth Admin
    const { data: authAdmin, error: errAdmin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdmin || !authAdmin.session) throw new Error(`Admin sign in failed: ${errAdmin?.message}`);
    adminToken = authAdmin.session.access_token;
  });

  afterAll(async () => {
    if (cleanupOrderIds.length > 0) {
      await prisma.customOrder.deleteMany({
        where: { id: { in: cleanupOrderIds } },
      });
    }
  });

  // Helper to create an order in a specific status for testing
  async function createTestOrder(status: CustomOrderStatus = CustomOrderStatus.SUBMITTED, profileId = customerAId) {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
        profileId,
        description: 'Bespoke navy flannel test suit with peak lapels',
        status,
        quotedPriceInCents: status === CustomOrderStatus.QUOTED || status === CustomOrderStatus.ACCEPTED ? 250000 : null,
      },
    });
    cleanupOrderIds.push(order.id);
    return order;
  }

  // ==============================================================================
  // 1. Central State Machine: Full 8x8 Transition Matrix
  // ==============================================================================

  describe('Central State Machine & Illegal Transitions Matrix', () => {
    const allStatuses: CustomOrderStatus[] = [
      CustomOrderStatus.SUBMITTED,
      CustomOrderStatus.IN_REVIEW,
      CustomOrderStatus.QUOTED,
      CustomOrderStatus.ACCEPTED,
      CustomOrderStatus.IN_PRODUCTION,
      CustomOrderStatus.READY,
      CustomOrderStatus.DELIVERED,
      CustomOrderStatus.REJECTED,
    ];

    it('rejects every illegal transition in the full 8x8 matrix with 409 Conflict', () => {
      let illegalJumpCount = 0;

      for (const fromStatus of allStatuses) {
        for (const toStatus of allStatuses) {
          const allowedTargets = ALLOWED_TRANSITIONS[fromStatus] || [];
          const isAllowed = allowedTargets.includes(toStatus);

          if (!isAllowed) {
            illegalJumpCount++;
            // Test that validateStatusTransition rejects illegal jump with 409 Conflict
            expect(() => {
              validateStatusTransition(fromStatus, toStatus, Role.ADMIN);
            }).toThrow(ConflictError);

            try {
              validateStatusTransition(fromStatus, toStatus, Role.ADMIN);
            } catch (err) {
              expect(err).toBeInstanceOf(ConflictError);
              expect((err as ConflictError).statusCode).toBe(409);
              expect((err as ConflictError).code).toBe(ErrorCode.CONFLICT);
            }
          }
        }
      }

      // Assert that a substantial matrix of illegal transitions was strictly verified
      expect(illegalJumpCount).toBeGreaterThanOrEqual(50);
    });

    it('enforces terminal states: DELIVERED and REJECTED allow zero outgoing transitions (409)', () => {
      for (const terminal of [CustomOrderStatus.DELIVERED, CustomOrderStatus.REJECTED]) {
        expect(TERMINAL_STATUSES.has(terminal)).toBe(true);
        for (const target of allStatuses) {
          expect(() => {
            validateStatusTransition(terminal, target, Role.ADMIN);
          }).toThrow(ConflictError);

          try {
            validateStatusTransition(terminal, target, Role.CUSTOMER);
          } catch (err) {
            expect(err).toBeInstanceOf(ConflictError);
            expect((err as ConflictError).statusCode).toBe(409);
          }
        }
      }
    });
  });

  // ==============================================================================
  // 2. Role Rules: Admin Drives vs Customer Only
  // ==============================================================================

  describe('Role Rules Enforcement', () => {
    it('customer cannot trigger admin transitions: returns 403 Forbidden', () => {
      const adminOnlyTransitions: Array<[CustomOrderStatus, CustomOrderStatus]> = [
        [CustomOrderStatus.SUBMITTED, CustomOrderStatus.IN_REVIEW],
        [CustomOrderStatus.IN_REVIEW, CustomOrderStatus.QUOTED],
        [CustomOrderStatus.ACCEPTED, CustomOrderStatus.IN_PRODUCTION],
        [CustomOrderStatus.IN_PRODUCTION, CustomOrderStatus.READY],
        [CustomOrderStatus.READY, CustomOrderStatus.DELIVERED],
        [CustomOrderStatus.QUOTED, CustomOrderStatus.QUOTED], // Re-quote
      ];

      for (const [from, to] of adminOnlyTransitions) {
        expect(() => {
          validateStatusTransition(from, to, Role.CUSTOMER);
        }).toThrow(ForbiddenError);

        try {
          validateStatusTransition(from, to, Role.CUSTOMER);
        } catch (err) {
          expect(err).toBeInstanceOf(ForbiddenError);
          expect((err as ForbiddenError).statusCode).toBe(403);
          expect((err as ForbiddenError).code).toBe(ErrorCode.FORBIDDEN);
        }
      }
    });

    it('admin cannot accept quotations on customer behalf: returns 403 Forbidden', () => {
      expect(() => {
        validateStatusTransition(CustomOrderStatus.QUOTED, CustomOrderStatus.ACCEPTED, Role.ADMIN);
      }).toThrow(ForbiddenError);

      try {
        validateStatusTransition(CustomOrderStatus.QUOTED, CustomOrderStatus.ACCEPTED, Role.ADMIN);
      } catch (err) {
        expect(err).toBeInstanceOf(ForbiddenError);
        expect((err as ForbiddenError).statusCode).toBe(403);
        expect((err as ForbiddenError).message).toContain('Administrators cannot accept');
      }
    });

    it('customer attempting admin API route /api/admin/custom-orders returns 403 Forbidden', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/custom-orders', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });

      const res = await adminListCustomOrders(req, {} as never);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    it('admin calling customer accept route returns 403 Forbidden', async () => {
      const order = await createTestOrder(CustomOrderStatus.QUOTED);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ expectedPriceInCents: 250000 }),
      });

      const res = await acceptCustomOrderQuote(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.message).toContain('Administrators cannot accept');
    });
  });

  // ==============================================================================
  // 3. Legal Transitions Lifecycle
  // ==============================================================================

  describe('Full Legal Lifecycle Flow', () => {
    it('executes a complete end-to-end bespoke order lifecycle legally', async () => {
      // 1. Order starts in SUBMITTED
      const order = await createTestOrder(CustomOrderStatus.SUBMITTED);
      expect(order.status).toBe(CustomOrderStatus.SUBMITTED);

      // 2. Admin moves to IN_REVIEW
      const reviewReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: CustomOrderStatus.IN_REVIEW }),
      });
      const reviewRes = await adminUpdateCustomOrder(reviewReq, { params: Promise.resolve({ id: order.id }) });
      expect(reviewRes.status).toBe(200);
      const reviewBody = await reviewRes.json();
      expect(reviewBody.data.status).toBe(CustomOrderStatus.IN_REVIEW);

      // 3. Admin quotes price: IN_REVIEW -> QUOTED
      const quoteReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quotedPriceInCents: 275000,
          internalNotes: 'Calculated with 4.5m Holland & Sherry wool fabric cost',
        }),
      });
      const quoteRes = await adminUpdateCustomOrder(quoteReq, { params: Promise.resolve({ id: order.id }) });
      expect(quoteRes.status).toBe(200);
      const quoteBody = await quoteRes.json();
      expect(quoteBody.data.status).toBe(CustomOrderStatus.QUOTED);
      expect(quoteBody.data.quotedPriceInCents).toBe(275000);

      // 4. Customer accepts quotation: QUOTED -> ACCEPTED
      const acceptReq = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ expectedPriceInCents: 275000 }),
      });
      const acceptRes = await acceptCustomOrderQuote(acceptReq, { params: Promise.resolve({ id: order.id }) });
      expect(acceptRes.status).toBe(200);
      const acceptBody = await acceptRes.json();
      expect(acceptBody.data.status).toBe(CustomOrderStatus.ACCEPTED);

      // 5. Admin starts production: ACCEPTED -> IN_PRODUCTION
      const prodReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: CustomOrderStatus.IN_PRODUCTION }),
      });
      const prodRes = await adminUpdateCustomOrder(prodReq, { params: Promise.resolve({ id: order.id }) });
      expect(prodRes.status).toBe(200);
      const prodBody = await prodRes.json();
      expect(prodBody.data.status).toBe(CustomOrderStatus.IN_PRODUCTION);

      // 6. Admin marks ready: IN_PRODUCTION -> READY
      const readyReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: CustomOrderStatus.READY }),
      });
      const readyRes = await adminUpdateCustomOrder(readyReq, { params: Promise.resolve({ id: order.id }) });
      expect(readyRes.status).toBe(200);
      const readyBody = await readyRes.json();
      expect(readyBody.data.status).toBe(CustomOrderStatus.READY);

      // 7. Admin marks delivered: READY -> DELIVERED (Terminal)
      const delivReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: CustomOrderStatus.DELIVERED }),
      });
      const delivRes = await adminUpdateCustomOrder(delivReq, { params: Promise.resolve({ id: order.id }) });
      expect(delivRes.status).toBe(200);
      const delivBody = await delivRes.json();
      expect(delivBody.data.status).toBe(CustomOrderStatus.DELIVERED);

      // 8. Attempting to change terminal DELIVERED status fails with 409 Conflict
      const illegalReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: CustomOrderStatus.READY }),
      });
      const illegalRes = await adminUpdateCustomOrder(illegalReq, { params: Promise.resolve({ id: order.id }) });
      expect(illegalRes.status).toBe(409);
      const illegalBody = await illegalRes.json();
      expect(illegalBody.error.code).toBe(ErrorCode.CONFLICT);
    }, 60000);
  });

  // ==============================================================================
  // 4. Cross-User IDOR Protection
  // ==============================================================================

  describe('IDOR & Cross-User Isolation', () => {
    it('Customer B cannot view or act on Customer A order (IDOR: 403 Forbidden)', async () => {
      const orderA = await createTestOrder(CustomOrderStatus.QUOTED, customerAId);

      // Customer B tries to view Customer A order
      const getReq = new NextRequest(`http://localhost:3000/api/custom-orders/${orderA.id}`, {
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const getRes = await getCustomOrderById(getReq, { params: Promise.resolve({ id: orderA.id }) });
      expect(getRes.status).toBe(403);

      // Customer B tries to accept Customer A order
      const acceptReq = new NextRequest(`http://localhost:3000/api/custom-orders/${orderA.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ expectedPriceInCents: 250000 }),
      });
      const acceptRes = await acceptCustomOrderQuote(acceptReq, { params: Promise.resolve({ id: orderA.id }) });
      expect(acceptRes.status).toBe(403);

      // Customer B tries to get Customer A WhatsApp handoff
      const waReq = new NextRequest(`http://localhost:3000/api/custom-orders/${orderA.id}/whatsapp`, {
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const waRes = await getWhatsAppLink(waReq, { params: Promise.resolve({ id: orderA.id }) });
      expect(waRes.status).toBe(403);

      // Customer B tries to withdraw Customer A order
      const withdrawReq = new NextRequest(`http://localhost:3000/api/custom-orders/${orderA.id}/withdraw`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ reason: 'Intruder cancellation' }),
      });
      const withdrawRes = await withdrawCustomOrder(withdrawReq, { params: Promise.resolve({ id: orderA.id }) });
      expect(withdrawRes.status).toBe(403);
    });
  });

  // ==============================================================================
  // 5. Internal Notes Privacy (Zero Leakage)
  // ==============================================================================

  describe('Internal Notes Field-Level Encryption & Zero Leakage', () => {
    it('internal notes never appear in any customer response (list, detail, history)', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW, customerAId);
      const secretNote = 'SECRET_VIP_MEMO: High profile client, do not disclose wholesale margins';

      // 1. Admin adds internal note during quoting
      const patchReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quotedPriceInCents: 290000,
          internalNotes: secretNote,
        }),
      });
      const patchRes = await adminUpdateCustomOrder(patchReq, { params: Promise.resolve({ id: order.id }) });
      expect(patchRes.status).toBe(200);

      // Verify note is encrypted at rest in the database
      const dbHistory = await prisma.customOrderStatusHistory.findFirst({
        where: { customOrderId: order.id },
        orderBy: { timestamp: 'desc' },
      });
      expect(dbHistory).toBeDefined();
      expect(dbHistory!.note).not.toContain('SECRET_VIP_MEMO'); // Encrypted at rest!

      // 2. Customer A retrieves order details (GET /api/custom-orders/[id])
      const getReq = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}`, {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCustomOrderById(getReq, { params: Promise.resolve({ id: order.id }) });
      expect(getRes.status).toBe(200);
      const getBody = await getRes.json();

      // Check detail: internalNotes field must NOT exist for customer
      expect(getBody.data.internalNotes).toBeUndefined();

      // Check history in detail: note containing [INTERNAL] is scrubbed to null
      for (const h of getBody.data.statusHistory) {
        if (h.note) {
          expect(h.note).not.toContain('SECRET_VIP_MEMO');
          expect(h.note).not.toContain('[INTERNAL]');
        }
      }

      // Check raw JSON payload for any string leakage
      const rawCustomerJson = JSON.stringify(getBody);
      expect(rawCustomerJson).not.toContain('SECRET_VIP_MEMO');
      expect(rawCustomerJson).not.toContain('wholesale margins');

      // 3. Customer A lists orders (GET /api/custom-orders)
      const listReq = new NextRequest('http://localhost:3000/api/custom-orders', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const listRes = await listCustomOrders(listReq, {} as never);
      expect(listRes.status).toBe(200);
      const listBody = await listRes.json();

      const customerOrderInList = listBody.data.find((o: { id: string }) => o.id === order.id);
      expect(customerOrderInList).toBeDefined();
      expect(customerOrderInList.internalNotes).toBeUndefined();

      const rawListJson = JSON.stringify(listBody);
      expect(rawListJson).not.toContain('SECRET_VIP_MEMO');

      // 4. Admin CAN view decrypted internal notes via admin routes
      const adminGetReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const adminGetRes = await adminGetCustomOrder(adminGetReq, { params: Promise.resolve({ id: order.id }) });
      expect(adminGetRes.status).toBe(200);
      const adminBody = await adminGetRes.json();
      expect(adminBody.data.internalNotes).toContain('High profile client');
    });

    it('deep-scans every customer response body for internal note plaintext and [INTERNAL] marker', async () => {
      const secretMarker = 'CONFIDENTIAL_MARGIN_ALLOWANCE_SECRET_XYZ999';
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW, customerAId);

      // Admin adds internal note during quoting
      const quoteReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quotedPriceInCents: 320000,
          internalNotes: secretMarker,
        }),
      });
      const quoteRes = await adminUpdateCustomOrder(quoteReq, { params: Promise.resolve({ id: order.id }) });
      expect(quoteRes.status).toBe(200);

      // Deep scan helper: checks every key name and string value in nested objects/arrays
      function deepScan(target: unknown, forbidden: string[]): string[] {
        const hits: string[] = [];
        function walk(val: unknown, path: string) {
          if (val === null || val === undefined) return;
          if (typeof val === 'string') {
            for (const f of forbidden) {
              if (val.includes(f)) {
                hits.push(`Found string "${f}" at ${path}: "${val}"`);
              }
            }
            return;
          }
          if (Array.isArray(val)) {
            val.forEach((item, i) => walk(item, `${path}[${i}]`));
            return;
          }
          if (typeof val === 'object') {
            for (const [k, v] of Object.entries(val)) {
              for (const f of forbidden) {
                if (k.toLowerCase().includes(f.toLowerCase())) {
                  hits.push(`Found key "${k}" matching "${f}" at ${path}.${k}`);
                }
              }
              walk(v, `${path}.${k}`);
            }
          }
        }
        walk(target, '$');
        return hits;
      }

      const forbiddenTokens = [secretMarker, '[INTERNAL]', 'internalNotes'];

      // 1. Customer detail route (GET /api/custom-orders/[id])
      const detailReq = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}`, {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const detailRes = await getCustomOrderById(detailReq, { params: Promise.resolve({ id: order.id }) });
      const detailBody = await detailRes.json();
      expect(deepScan(detailBody, forbiddenTokens)).toEqual([]);

      // 2. Customer list route (GET /api/custom-orders)
      const listReq = new NextRequest('http://localhost:3000/api/custom-orders', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const listRes = await listCustomOrders(listReq, {} as never);
      const listBody = await listRes.json();
      expect(deepScan(listBody, forbiddenTokens)).toEqual([]);

      // 3. Customer accept route (POST /api/custom-orders/[id]/accept)
      const acceptReq = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          expectedPriceInCents: 320000,
          notes: 'Customer note: Ready for first fitting',
        }),
      });
      const acceptRes = await acceptCustomOrderQuote(acceptReq, { params: Promise.resolve({ id: order.id }) });
      const acceptBody = await acceptRes.json();
      expect(deepScan(acceptBody, forbiddenTokens)).toEqual([]);

      // Verify that customer-authored note is still present and visible in response
      const allNotes = acceptBody.data.statusHistory.map((h: { note: string | null }) => h.note).filter(Boolean);
      expect(allNotes.some((n: string) => n.includes('Ready for first fitting'))).toBe(true);

      // Verify that the internal note history entry has note explicitly nulled
      const quotedHistory = acceptBody.data.statusHistory.find((h: { toStatus: string }) => h.toStatus === CustomOrderStatus.QUOTED);
      expect(quotedHistory).toBeDefined();
      expect(quotedHistory.note).toBeNull();
    });
  });

  // ==============================================================================
  // 6. Quote Safety & Race Condition
  // ==============================================================================

  describe('Quote Safety & Concurrency Protection', () => {
    it('customer accepts quote with matching expected price successfully', async () => {
      const order = await createTestOrder(CustomOrderStatus.QUOTED, customerAId);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ expectedPriceInCents: 250000 }),
      });

      const res = await acceptCustomOrderQuote(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe(CustomOrderStatus.ACCEPTED);
    });

    it('rejects accept with 409 Conflict if expected price does not match price on record', async () => {
      const order = await createTestOrder(CustomOrderStatus.QUOTED, customerAId);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ expectedPriceInCents: 199900 }), // Stale price attempt
      });

      const res = await acceptCustomOrderQuote(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(409);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.CONFLICT);
      expect(body.error.message).toContain('price has changed');
    });

    it('rejects accept with 422 Unprocessable Entity if expectedPriceInCents is omitted', async () => {
      const order = await createTestOrder(CustomOrderStatus.QUOTED, customerAId);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          notes: 'Customer accepts without providing mandatory price',
        }),
      });

      const res = await acceptCustomOrderQuote(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('accept versus re-quote race: row locking ensures exactly one outcome and prevents stale price', async () => {
      const order = await createTestOrder(CustomOrderStatus.QUOTED, customerAId);
      const originalPrice = 250000;
      const revisedPrice = 320000;

      // Customer accepts with original price expectation
      const customerAcceptPromise = acceptCustomOrderQuote(
        new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/accept`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ expectedPriceInCents: originalPrice }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );

      // Admin re-quotes concurrently with revised price
      const adminRequotePromise = adminUpdateCustomOrder(
        new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ quotedPriceInCents: revisedPrice }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );

      const [acceptResult, requoteResult] = await Promise.all([
        customerAcceptPromise,
        adminRequotePromise,
      ]);

      const acceptStatus = acceptResult.status;
      const requoteStatus = requoteResult.status;

      // Exactly one of the two serialized transactions succeeded, the other returned 409
      if (acceptStatus === 200) {
        // Customer accepted first: admin requote must fail with 409 (cannot re-quote ACCEPTED order)
        expect(requoteStatus).toBe(409);
      } else {
        // Admin re-quoted first: customer accept with stale price must fail with 409
        expect(acceptStatus).toBe(409);
        expect(requoteStatus).toBe(200);
      }

      // Check database state: Order is consistent, never in an invalid intermediate state
      const finalDbOrder = await prisma.customOrder.findUnique({ where: { id: order.id } });
      expect(finalDbOrder).toBeDefined();
      if (acceptStatus === 200) {
        expect(finalDbOrder!.status).toBe(CustomOrderStatus.ACCEPTED);
        expect(finalDbOrder!.quotedPriceInCents).toBe(originalPrice);
      } else {
        expect(finalDbOrder!.status).toBe(CustomOrderStatus.QUOTED);
        expect(finalDbOrder!.quotedPriceInCents).toBe(revisedPrice);
      }
    });

    it('admin moves order to IN_REVIEW or QUOTED while customer edit is in flight: atomic lock ensures edit either applies before transition or fails with 409 and never applies after QUOTED, description unchanged on reject', async () => {
      const initialDescription = 'Original bespoke navy wool suit requested by customer';
      const editedDescription = 'Updated description: add velvet collar and horn buttons';

      const order = await prisma.customOrder.create({
        data: {
          orderNumber: `CO-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
          profileId: customerAId,
          description: initialDescription,
          status: CustomOrderStatus.SUBMITTED,
        },
      });
      cleanupOrderIds.push(order.id);

      // Customer edit promise
      const customerEditPromise = updateCustomOrder(
        new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ description: editedDescription }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );

      // Admin moves the order to IN_REVIEW in flight
      const adminMovePromise = adminUpdateCustomOrder(
        new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ status: CustomOrderStatus.IN_REVIEW }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );

      const [editRes, adminRes] = await Promise.all([
        customerEditPromise,
        adminMovePromise,
      ]);

      expect(adminRes.status).toBe(200);

      const dbOrderAfterTransition = await prisma.customOrder.findUnique({ where: { id: order.id } });
      expect(dbOrderAfterTransition).toBeDefined();
      expect(dbOrderAfterTransition!.status).toBe(CustomOrderStatus.IN_REVIEW);

      if (editRes.status === 200) {
        // Edit arrived first and was locked before admin transition
        expect(dbOrderAfterTransition!.description).toBe(editedDescription);
      } else {
        // Admin transition locked first, customer edit must fail with 409
        expect(editRes.status).toBe(409);
        const editBody = await editRes.json();
        expect(editBody.error.code).toBe(ErrorCode.CONFLICT);
        // Assert description is unchanged after rejected edit
        expect(dbOrderAfterTransition!.description).toBe(initialDescription);
      }

      // Now admin moves the order to QUOTED
      const adminQuoteRes = await adminUpdateCustomOrder(
        new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ quotedPriceInCents: 350000 }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(adminQuoteRes.status).toBe(200);

      const currentDbOrder = await prisma.customOrder.findUnique({ where: { id: order.id } });
      expect(currentDbOrder!.status).toBe(CustomOrderStatus.QUOTED);
      const preAttemptDescription = currentDbOrder!.description;

      // Customer edit attempted while in QUOTED: MUST NEVER apply and MUST return 409
      const editAfterQuotedRes = await updateCustomOrder(
        new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ description: 'Illegitimate late edit attempt after QUOTED' }),
        }),
        { params: Promise.resolve({ id: order.id }) }
      );
      expect(editAfterQuotedRes.status).toBe(409);
      const editAfterQuotedBody = await editAfterQuotedRes.json();
      expect(editAfterQuotedBody.error.code).toBe(ErrorCode.CONFLICT);

      // Assert description is strictly unchanged after rejected edit
      const finalDbOrder = await prisma.customOrder.findUnique({ where: { id: order.id } });
      expect(finalDbOrder!.description).toBe(preAttemptDescription);
      expect(finalDbOrder!.description).not.toBe('Illegitimate late edit attempt after QUOTED');
    });
  });

  // ==============================================================================
  // 7. History and System Audit Logging
  // ==============================================================================

  describe('History and Audit Logging Compliance', () => {
    it('every transition writes CustomOrderStatusHistory and AuditLog rows with no sensitive fields', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW, customerAId);

      // Transition to QUOTED
      const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quotedPriceInCents: 310000 }),
      });

      const res = await adminUpdateCustomOrder(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(200);

      // 1. Verify CustomOrderStatusHistory
      const historyRows = await prisma.customOrderStatusHistory.findMany({
        where: { customOrderId: order.id, toStatus: CustomOrderStatus.QUOTED },
      });
      expect(historyRows.length).toBe(1);
      expect(historyRows[0].fromStatus).toBe(CustomOrderStatus.IN_REVIEW);
      expect(historyRows[0].toStatus).toBe(CustomOrderStatus.QUOTED);

      // 2. Verify AuditLog entry
      const auditRows = await prisma.auditLog.findMany({
        where: { entity: 'CustomOrder', entityId: order.id, action: 'CUSTOM_ORDER_STATUS_CHANGED' },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditRows.length).toBeGreaterThanOrEqual(1);
      const latestAudit = auditRows[0];
      const metadata = latestAudit.metadata as Record<string, unknown>;

      expect(metadata).toBeDefined();
      expect(metadata.orderNumber).toBe(order.orderNumber);
      expect(metadata.fromStatus).toBe(CustomOrderStatus.IN_REVIEW);
      expect(metadata.toStatus).toBe(CustomOrderStatus.QUOTED);
      expect(metadata.quotedPriceInCents).toBe(310000);

      // Non-negotiable: Never log measurements, notes, or phone numbers in audit metadata
      expect(metadata.measurements).toBeUndefined();
      expect(metadata.notes).toBeUndefined();
      expect(metadata.internalNotes).toBeUndefined();
      expect(metadata.phone).toBeUndefined();
      expect(metadata.phoneNumber).toBeUndefined();
    });
  });

  // ==============================================================================
  // 8. WhatsApp Handoff
  // ==============================================================================

  describe('WhatsApp Handoff URL Generation', () => {
    it('generates wa.me link containing only reference code and fixed greeting (zero PII)', async () => {
      const order = await createTestOrder(CustomOrderStatus.SUBMITTED, customerAId);

      // Direct helper unit test
      const directUrl = generateWhatsAppHandoffUrl(order.orderNumber);
      expect(directUrl).toMatch(/^https:\/\/wa\.me\/\d+\?text=/);
      expect(directUrl).toContain(encodeURIComponent(order.orderNumber));

      // Assert no PII in URL
      const decodedUrl = decodeURIComponent(directUrl);
      expect(decodedUrl).not.toContain('James');
      expect(decodedUrl).not.toContain(customerAEmail);
      expect(decodedUrl).not.toContain('$');
      expect(decodedUrl).not.toContain('cm');
      expect(decodedUrl).not.toContain('inches');

      // API route test (GET /api/custom-orders/[id]/whatsapp)
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/whatsapp`, {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const res = await getWhatsAppLink(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.orderNumber).toBe(order.orderNumber);
      expect(body.data.whatsappUrl).toBe(directUrl);
    });
  });

  // ==============================================================================
  // 9. Notification Service Resilience
  // ==============================================================================

  describe('Notification Service Resilience', () => {
    it('notification service failure does not roll back or fail status transition', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW, customerAId);

      // Simulate notification outage
      notificationService.setShouldFail(true);

      try {
        const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ quotedPriceInCents: 350000 }),
        });

        const res = await adminUpdateCustomOrder(req, { params: Promise.resolve({ id: order.id }) });
        // Must succeed with 200 despite notification service error
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.status).toBe(CustomOrderStatus.QUOTED);

        // Verify DB update committed
        const dbOrder = await prisma.customOrder.findUnique({ where: { id: order.id } });
        expect(dbOrder!.status).toBe(CustomOrderStatus.QUOTED);
      } finally {
        notificationService.setShouldFail(false);
      }
    });
  });

  // ==============================================================================
  // 10. Admin Route Hygiene (PATCH /api/admin/custom-orders/[id])
  // ==============================================================================

  describe('Admin Route Hygiene (PATCH /api/admin/custom-orders/[id])', () => {
    it('unknown field returns 422 Unprocessable Entity (strict schema)', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW);

      const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: CustomOrderStatus.QUOTED,
          quotedPriceInCents: 250000,
          unrecognizedInjectedProperty: 'malicious',
        }),
      });

      const res = await adminUpdateCustomOrder(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('price with a non-QUOTED target is rejected', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW);

      const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: CustomOrderStatus.REJECTED,
          quotedPriceInCents: 250000,
        }),
      });

      const res = await adminUpdateCustomOrder(req, { params: Promise.resolve({ id: order.id }) });
      expect([400, 422]).toContain(res.status);
      const body = await res.json();
      expect(body.success).toBe(false);
    });

    it('out-of-range price is rejected with 422 (below 1,000 or above 50,000,000 cents)', async () => {
      const order = await createTestOrder(CustomOrderStatus.IN_REVIEW);

      // A. Price below 1,000 cents ($10)
      const reqBelow = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quotedPriceInCents: 500, // $5.00 is below $10.00 min
        }),
      });
      const resBelow = await adminUpdateCustomOrder(reqBelow, { params: Promise.resolve({ id: order.id }) });
      expect(resBelow.status).toBe(422);

      // B. Price above 50,000,000 cents ($500,000)
      const reqAbove = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${order.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quotedPriceInCents: 60_000_000, // Exceeds upper boundary
        }),
      });
      const resAbove = await adminUpdateCustomOrder(reqAbove, { params: Promise.resolve({ id: order.id }) });
      expect(resAbove.status).toBe(422);
    });
  });

  // ==============================================================================
  // 11. Route-Level Table-Driven Transition Tests
  // ==============================================================================

  describe('Route-Level Table-Driven Transition Matrix (All 15 Legal Rows + Illegal Rows)', () => {
    const legalRows: Array<{
      description: string;
      initialStatus: CustomOrderStatus;
      targetStatus: CustomOrderStatus;
      execute: (orderId: string) => Promise<Response>;
    }> = [
      {
        description: '1. SUBMITTED -> IN_REVIEW (ADMIN PATCH)',
        initialStatus: CustomOrderStatus.SUBMITTED,
        targetStatus: CustomOrderStatus.IN_REVIEW,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.IN_REVIEW }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '2. SUBMITTED -> REJECTED (CUSTOMER POST /withdraw)',
        initialStatus: CustomOrderStatus.SUBMITTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          withdrawCustomOrder(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/withdraw`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'Customer changed styling plans' }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '3. SUBMITTED -> REJECTED (ADMIN PATCH cancel)',
        initialStatus: CustomOrderStatus.SUBMITTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.REJECTED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '4. IN_REVIEW -> QUOTED (ADMIN PATCH with quotedPriceInCents)',
        initialStatus: CustomOrderStatus.IN_REVIEW,
        targetStatus: CustomOrderStatus.QUOTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ quotedPriceInCents: 280000 }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '5. IN_REVIEW -> REJECTED (CUSTOMER POST /withdraw)',
        initialStatus: CustomOrderStatus.IN_REVIEW,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          withdrawCustomOrder(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/withdraw`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'Withdrawing before formal quote' }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '6. IN_REVIEW -> REJECTED (ADMIN PATCH decline)',
        initialStatus: CustomOrderStatus.IN_REVIEW,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.REJECTED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '7. QUOTED -> ACCEPTED (CUSTOMER POST /accept with expectedPriceInCents)',
        initialStatus: CustomOrderStatus.QUOTED,
        targetStatus: CustomOrderStatus.ACCEPTED,
        execute: (id) =>
          acceptCustomOrderQuote(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/accept`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ expectedPriceInCents: 250000 }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '8. QUOTED -> REJECTED (CUSTOMER POST /withdraw decline quote)',
        initialStatus: CustomOrderStatus.QUOTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          withdrawCustomOrder(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/withdraw`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'Quote exceeds planned budget' }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '9. QUOTED -> REJECTED (ADMIN PATCH cancel quote)',
        initialStatus: CustomOrderStatus.QUOTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.REJECTED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '10. QUOTED -> QUOTED (ADMIN PATCH revised quote)',
        initialStatus: CustomOrderStatus.QUOTED,
        targetStatus: CustomOrderStatus.QUOTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ quotedPriceInCents: 310000 }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '11. ACCEPTED -> IN_PRODUCTION (ADMIN PATCH begin tailoring)',
        initialStatus: CustomOrderStatus.ACCEPTED,
        targetStatus: CustomOrderStatus.IN_PRODUCTION,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.IN_PRODUCTION }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '12. ACCEPTED -> REJECTED (CUSTOMER POST /withdraw before production starts)',
        initialStatus: CustomOrderStatus.ACCEPTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          withdrawCustomOrder(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/withdraw`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'Emergency withdrawal prior to cutting cloth' }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '13. ACCEPTED -> REJECTED (ADMIN PATCH cancel before cutting)',
        initialStatus: CustomOrderStatus.ACCEPTED,
        targetStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.REJECTED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '14. IN_PRODUCTION -> READY (ADMIN PATCH garment finished)',
        initialStatus: CustomOrderStatus.IN_PRODUCTION,
        targetStatus: CustomOrderStatus.READY,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.READY }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: '15. READY -> DELIVERED (ADMIN PATCH garment delivered)',
        initialStatus: CustomOrderStatus.READY,
        targetStatus: CustomOrderStatus.DELIVERED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.DELIVERED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
    ];

    for (const row of legalRows) {
      it(`legal: ${row.description}`, async () => {
        const order = await createTestOrder(row.initialStatus, customerAId);
        const res = await row.execute(order.id);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.status).toBe(row.targetStatus);
      });
    }

    const illegalRows: Array<{
      description: string;
      initialStatus: CustomOrderStatus;
      execute: (orderId: string) => Promise<Response>;
    }> = [
      {
        description: 'Illegal 1: SUBMITTED -> ACCEPTED (skipping review and quote)',
        initialStatus: CustomOrderStatus.SUBMITTED,
        execute: (id) =>
          acceptCustomOrderQuote(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/accept`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ expectedPriceInCents: 250000 }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 2: SUBMITTED -> IN_PRODUCTION (jumping to production directly)',
        initialStatus: CustomOrderStatus.SUBMITTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.IN_PRODUCTION }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 3: IN_REVIEW -> ACCEPTED (accepting unquoted order)',
        initialStatus: CustomOrderStatus.IN_REVIEW,
        execute: (id) =>
          acceptCustomOrderQuote(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/accept`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ expectedPriceInCents: 250000 }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 4: IN_REVIEW -> DELIVERED (jumping to terminal delivered state)',
        initialStatus: CustomOrderStatus.IN_REVIEW,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.DELIVERED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 5: QUOTED -> DELIVERED (jumping to delivered without production)',
        initialStatus: CustomOrderStatus.QUOTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.DELIVERED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 6: IN_PRODUCTION -> REJECTED (withdrawing once garment is in production)',
        initialStatus: CustomOrderStatus.IN_PRODUCTION,
        execute: (id) =>
          withdrawCustomOrder(
            new NextRequest(`http://localhost:3000/api/custom-orders/${id}/withdraw`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'Attempted withdrawal during cutting' }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 7: DELIVERED -> READY (transitioning out of terminal DELIVERED status)',
        initialStatus: CustomOrderStatus.DELIVERED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.READY }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
      {
        description: 'Illegal 8: REJECTED -> SUBMITTED (transitioning out of terminal REJECTED status)',
        initialStatus: CustomOrderStatus.REJECTED,
        execute: (id) =>
          adminUpdateCustomOrder(
            new NextRequest(`http://localhost:3000/api/admin/custom-orders/${id}`, {
              method: 'PATCH',
              headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: CustomOrderStatus.SUBMITTED }),
            }),
            { params: Promise.resolve({ id }) }
          ),
      },
    ];

    for (const row of illegalRows) {
      it(`illegal: ${row.description}`, async () => {
        const order = await createTestOrder(row.initialStatus, customerAId);
        const res = await row.execute(order.id);
        expect(res.status).toBe(409);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.error.code).toBe(ErrorCode.CONFLICT);
      });
    }
  });
});
