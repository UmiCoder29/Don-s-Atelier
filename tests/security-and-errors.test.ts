import { describe, it, expect, vi } from 'vitest';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { withErrorHandler } from '@/lib/api/async-handler';
import { errorResponse } from '@/lib/api/response';
import { logger } from '@/lib/api/logger';
import {
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  InternalServerError,
} from '@/lib/errors/api-error';
import { ErrorCode } from '@/lib/errors/error-codes';
import nextConfig from '../next.config';
import { GET as getHealthRoute } from '@/app/api/health/route';
import { GET as getProductsRoute } from '@/app/api/products/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { GET as getCustomOrderRoute } from '@/app/api/custom-orders/[id]/route';
import { PATCH as adminUpdateCustomOrderRoute } from '@/app/api/admin/custom-orders/[id]/route';
import { prisma } from '@/lib/db/prisma';
import { validateOrderStatusTransition } from '@/services/order/order-state-machine';
import { OrderStatus, Role } from '@prisma/client';
import { systemActor, userActor } from '@/lib/auth/actor';
import { logAuditEvent } from '@/lib/audit/audit-logger';

describe('Security & Error Handling Standards', () => {
  describe('Consistent Error Format & Non-Leakage', () => {
    it('sanitizes unexpected internal exceptions and never exposes stack traces', async () => {
      const handler = withErrorHandler(async () => {
        throw new Error('FATAL: Database connection failed at postgres://user:secret@internal-db:5432');
      });

      const req = new NextRequest('http://localhost:3000/api/test-error');
      const response = await handler(req, {} as never);

      expect(response.status).toBe(500);

      const body = await response.json();

      // Standard error contract
      expect(body.success).toBe(false);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(ErrorCode.INTERNAL_SERVER_ERROR);

      // Sensitive internal strings or stack traces must NEVER be exposed
      expect(body.error.message).toBe('An unexpected internal error occurred. Please try again later.');
      expect(body.error.stack).toBeUndefined();
      expect(JSON.stringify(body)).not.toContain('postgres://user:secret');
      expect(JSON.stringify(body)).not.toContain('internal-db');
    });

    it('translates Zod validation errors to standardized 422 ValidationError', async () => {
      const testSchema = z.object({
        email: z.string().email(),
        quantity: z.number().int().positive(),
      });

      const handler = withErrorHandler(async (req) => {
        const body = await req.json();
        testSchema.parse(body);
        return NextResponse.json({ ok: true });
      });

      const req = new NextRequest('http://localhost:3000/api/test-zod', {
        method: 'POST',
        body: JSON.stringify({ email: 'invalid-email', quantity: -5 }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await handler(req, {} as never);
      expect(response.status).toBe(422);

      const body = await response.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toBe('Request validation failed');
      expect(Array.isArray(body.error.details)).toBe(true);
      expect(body.error.details.length).toBe(2);
    });

    it('formats specific operational errors with correct HTTP status codes', async () => {
      const errors = [
        { err: new BadRequestError('Invalid suit size'), expectedStatus: 400, expectedCode: ErrorCode.BAD_REQUEST },
        { err: new UnauthorizedError(), expectedStatus: 401, expectedCode: ErrorCode.UNAUTHORIZED },
        { err: new ForbiddenError(), expectedStatus: 403, expectedCode: ErrorCode.FORBIDDEN },
        { err: new NotFoundError('Product'), expectedStatus: 404, expectedCode: ErrorCode.NOT_FOUND },
      ];

      for (const { err, expectedStatus, expectedCode } of errors) {
        const handler = withErrorHandler(async () => {
          throw err;
        });

        const req = new NextRequest('http://localhost:3000/api/test-status');
        const response = await handler(req, {} as never);

        expect(response.status).toBe(expectedStatus);
        const body = await response.json();
        expect(body.success).toBe(false);
        expect(body.error.code).toBe(expectedCode);
      }
    });
  });

  describe('Security Headers Configuration', () => {
    it('defines all required security headers in next.config.ts', async () => {
      expect(nextConfig.headers).toBeDefined();

      if (typeof nextConfig.headers === 'function') {
        const headersList = await nextConfig.headers();
        expect(headersList.length).toBeGreaterThan(0);

        const routeHeaders = headersList[0].headers;
        const headerMap = new Map(routeHeaders.map((h) => [h.key, h.value]));

        // CSP
        expect(headerMap.has('Content-Security-Policy')).toBe(true);
        expect(headerMap.get('Content-Security-Policy')).toContain("default-src 'self'");

        // HSTS
        expect(headerMap.has('Strict-Transport-Security')).toBe(true);
        expect(headerMap.get('Strict-Transport-Security')).toContain('max-age=');

        // X-Frame-Options
        expect(headerMap.get('X-Frame-Options')).toBe('DENY');

        // X-Content-Type-Options
        expect(headerMap.get('X-Content-Type-Options')).toBe('nosniff');

        // Referrer-Policy
        expect(headerMap.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');

        // Permissions-Policy
        expect(headerMap.has('Permissions-Policy')).toBe(true);
      }
    });

    it('disables poweredByHeader in next.config.ts', () => {
      expect(nextConfig.poweredByHeader).toBe(false);
    });
  });

  describe('Sensitive Data Redaction & Zero Card Policy', () => {
    it('redacts sensitive customer PII, addresses, and measurements in logs', () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      const sensitivePayload = {
        requestId: 'req-test-sensitive',
        user: {
          id: 'user-123',
          email: 'customer@example.com',
          phone: '+1-555-123-4567',
        },
        shippingAddress: {
          recipientName: 'Lord Don',
          streetLine1: '40 Savile Row',
          postalCode: 'W1S 2EZ',
        },
        measurements: {
          chestInInches: 42,
          waistInInches: 34,
        },
        cardLast4: '4242',
        cardBrand: 'visa',
      };

      logger.info('Customer checkout initialized', sensitivePayload);

      expect(consoleLogSpy).toHaveBeenCalled();
      const loggedJson = JSON.parse(consoleLogSpy.mock.calls[0][0]);

      // Phone must be redacted
      expect(loggedJson.user.phone).toBe('[REDACTED]');
      // Address must be redacted
      expect(loggedJson.shippingAddress).toBe('[REDACTED]');
      // Measurements must be redacted
      expect(loggedJson.measurements).toBe('[REDACTED]');
      // Card-adjacent fields must be redacted
      expect(loggedJson.cardLast4).toBe('[REDACTED]');
      expect(loggedJson.cardBrand).toBe('[REDACTED]');

      // Plaintext values must NOT exist in the log output string
      const rawLog = consoleLogSpy.mock.calls[0][0];
      expect(rawLog).not.toContain('+1-555-123-4567');
      expect(rawLog).not.toContain('40 Savile Row');
      expect(rawLog).not.toContain('W1S 2EZ');

      consoleLogSpy.mockRestore();
    });
  });

  describe('Comprehensive Error Leakage Prevention (Step 3)', () => {
    function assertNoSensitiveLeakage(responseBodyStr: string) {
      const forbiddenPatterns = [
        /postgresql:\/\//i,
        /postgres:\/\//i,
        /internal-db/i,
        /supabase\.co/i,
        /5432/,
        /at\s+[A-Za-z0-9_.]+\s+\(/, // stack trace call site
        /node_modules/i,
        /runtime\/library\.js/i,
        /\.ts:\d+:\d+/, // file path and line number
        /\.js:\d+:\d+/,
        /SELECT\s+.+\s+FROM/i,
        /INSERT\s+INTO/i,
        /UPDATE\s+.+\s+SET/i,
        /DELETE\s+FROM/i,
        /PrismaClientKnownRequestError/i,
        /P2002/,
        /P2025/,
        /ProductVariant/,
        /CustomOrder/,
        /quotedPriceInCents/,
        /unit_price_in_cents/,
      ];

      for (const pattern of forbiddenPatterns) {
        expect(responseBodyStr).not.toMatch(pattern);
      }
    }

    it('sanitizes mocked Prisma DB error containing fake connection string and stack trace', async () => {
      const dbErrorWithSensitiveInfo = new Error(
        'FATAL: Connection pool failed at postgresql://postgres:p@ssw0rd@internal-db.supabase.co:5432/postgres\n' +
        '    at PrismaClient.query (/app/node_modules/@prisma/client/runtime/library.js:123:45)\n' +
        '    at executeQuery (src/lib/db/prisma.ts:88:12)'
      );

      const findManySpy = vi.spyOn(prisma.product, 'findMany').mockRejectedValueOnce(dbErrorWithSensitiveInfo);

      const req = new NextRequest('http://localhost:3000/api/products');
      const res = await getProductsRoute(req, {} as never);

      expect(res.status).toBe(500);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe(ErrorCode.INTERNAL_SERVER_ERROR);
      expect(json.error.message).toBe('An unexpected internal error occurred. Please try again later.');

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);

      findManySpy.mockRestore();
    });

    it('sanitizes malformed JSON error on POST routes and returns 400 without internals', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"email": "broken-json@example.com", ',
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(400);

      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe(ErrorCode.BAD_REQUEST);

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);
    });

    it('sanitizes oversized body rejection (HTTP 413) without leaking server internals', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': '150000',
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'Password123!' }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(413);

      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe(ErrorCode.PAYLOAD_TOO_LARGE);

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);
    });

    it('sanitizes invalid UUID parameter rejection without exposing SQL or table names', async () => {
      const handler = withErrorHandler(async (req, ctx: { params: Promise<{ id: string }> }) => {
        const { id } = z.object({ id: z.string().uuid() }).parse(await ctx.params);
        return NextResponse.json({ id });
      });

      const req = new NextRequest('http://localhost:3000/api/custom-orders/not-a-valid-uuid');
      const res = await handler(req, {
        params: Promise.resolve({ id: 'not-a-valid-uuid' }),
      } as never);

      expect(res.status).toBe(422);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);
    });

    it('sanitizes wrong HTTP method rejection without leaking internals', async () => {
      const handler = withErrorHandler(async () => {
        throw new BadRequestError('HTTP method DELETE is not supported on this endpoint');
      });

      const req = new NextRequest('http://localhost:3000/api/products', { method: 'DELETE' });
      const res = await handler(req, {} as never);

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.success).toBe(false);

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);
    });

    it('sanitizes invalid enum value rejection without exposing internal schema definitions', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/custom-orders/00000000-0000-0000-0000-000000000001', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-bearer-token',
        },
        body: JSON.stringify({
          status: 'FORGED_INVALID_STATUS_ENUM',
        }),
      });

      const res = await adminUpdateCustomOrderRoute(req, {
        params: Promise.resolve({ id: '00000000-0000-0000-0000-000000000001' }),
      });

      // May be 401 (auth) or 422 (validation) depending on execution order
      expect([401, 422]).toContain(res.status);
      const json = await res.json();
      expect(json.success).toBe(false);

      const bodyStr = JSON.stringify(json);
      assertNoSensitiveLeakage(bodyStr);
    });

    it('verifies GET /api/health exposes strictly authorized generic metadata without DB host or env values', async () => {
      const req = new NextRequest('http://localhost:3000/api/health');
      const res = await getHealthRoute(req, {} as never);

      expect(res.status).toBe(200);
      const json = await res.json();

      expect(json.success).toBe(true);
      expect(json.data).toBeDefined();

      // List of exact fields returned by GET /api/health (Prompt 14C: ONLY status and timestamp)
      const returnedFields = Object.keys(json.data).sort();
      const expectedFields = ['status', 'timestamp'].sort();

      expect(returnedFields).toEqual(expectedFields);
      expect(json.data.status).toBe('ok');
      expect(json.data.timestamp).toBeDefined();

      // Verify service, package, version, environment, uptime, and database secrets are NOT present
      expect(json.data.service).toBeUndefined();
      expect(json.data.package).toBeUndefined();
      expect(json.data.version).toBeUndefined();
      expect(json.data.environment).toBeUndefined();
      expect(json.data.uptimeSeconds).toBeUndefined();
      expect(json.data.database).toBeUndefined();
      expect(json.data.dbHost).toBeUndefined();
      expect(json.data.host).toBeUndefined();
      expect(json.data.connectionString).toBeUndefined();

      const rawJson = JSON.stringify(json);
      assertNoSensitiveLeakage(rawJson);
    });
  });

  describe('SYSTEM Actor Type & Automated Lifecycle (Step 4d)', () => {
    it('allows systemActor to execute automated lifecycle transitions (PENDING -> PAID, PENDING -> CANCELLED, PAID -> CANCELLED)', () => {
      const webhookActor = systemActor('payment_webhook');
      expect(() => validateOrderStatusTransition(OrderStatus.PENDING, OrderStatus.PAID, webhookActor)).not.toThrow();

      const schedulerActor = systemActor('expired_order_scheduler');
      expect(() => validateOrderStatusTransition(OrderStatus.PENDING, OrderStatus.CANCELLED, schedulerActor)).not.toThrow();

      const checkoutFailedActor = systemActor('checkout_payment_failed');
      expect(() => validateOrderStatusTransition(OrderStatus.PAID, OrderStatus.CANCELLED, checkoutFailedActor)).not.toThrow();
    });

    it('rejects systemActor from executing manual administrative transitions (e.g. SHIPPED -> DELIVERED, DELIVERED -> REFUNDED)', () => {
      const webhookActor = systemActor('payment_webhook');
      expect(() => validateOrderStatusTransition(OrderStatus.SHIPPED, OrderStatus.DELIVERED, webhookActor)).toThrowError(ForbiddenError);
      expect(() => validateOrderStatusTransition(OrderStatus.DELIVERED, OrderStatus.REFUNDED, webhookActor)).toThrowError(ForbiddenError);
    });

    it('logs audit events with actorKind: SYSTEM or USER and sanitized metadata', async () => {
      const sysActor = systemActor('payment_webhook');
      const log = await logAuditEvent({
        actor: sysActor,
        action: 'PAYMENT_CONFIRMED',
        entity: 'Order',
        entityId: '00000000-0000-0000-0000-000000000001',
        metadata: {
          note: 'Payment captured from Stripe mock \x00\x1f',
        },
      });

      expect(log).toBeDefined();
      expect(log?.actorId).toBeNull();
      const meta = log?.metadata as Record<string, unknown>;
      expect(meta.actorKind).toBe('SYSTEM');
      expect(meta.actorName).toBe('payment_webhook');
      expect(meta.note).toBe('Payment captured from Stripe mock ');

      await prisma.auditLog.delete({ where: { id: log!.id } });
    });
  });
});

