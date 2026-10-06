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
});

