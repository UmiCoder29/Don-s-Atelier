import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as registerRoute } from '@/app/api/auth/register/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { POST as checkoutRoute } from '@/app/api/orders/route';
import { POST as customOrderRoute } from '@/app/api/custom-orders/route';
import { POST as cartRoute } from '@/app/api/cart/route';
import { POST as uploadRoute } from '@/app/api/uploads/route';
import { PATCH as updateProfileRoute } from '@/app/api/account/profile/route';
import { GET as csrfRoute } from '@/app/api/auth/csrf/route';
import { rateLimiter, getClientIp } from '@/lib/security/rate-limiter';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '@/lib/security/csrf';
import { AUTH_ACCESS_COOKIE } from '@/lib/auth/cookies';
import { sanitizeText } from '@/lib/validation/sanitizer';
import { logAuditEvent } from '@/lib/audit/audit-logger';
import { prisma } from '@/lib/db/prisma';
import { ErrorCode } from '@/lib/errors/error-codes';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { checkoutSchema } from '@/services/order/types';
import { createCustomOrderSchema } from '@/services/bespoke/types';
import { addToCartSchema } from '@/services/cart/types';
import { registerSchema, loginSchema } from '@/lib/validation/auth-schemas';

describe('Cross-Cutting Protections Acceptance Suite', () => {
  let customerToken: string;
  let adminToken: string;
  let customerAddressId: string;
  let adminAddressId: string;

  beforeAll(async () => {
    const customerEmail = 'james.harrington@example.com';
    const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
    const adminEmail = 'admin@dons-atelier.com';
    const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

    const { data: authData } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });

    if (authData?.session) {
      customerToken = authData.session.access_token;
      const addr = await prisma.address.findFirst({ where: { profileId: authData.user.id } });
      customerAddressId = addr
        ? addr.id
        : (
            await prisma.address.create({
              data: {
                profileId: authData.user.id,
                recipientName: 'James Harrington',
                line1: '10 Savile Row',
                city: 'London',
                state: 'London',
                postalCode: 'W1S 3PB',
                country: 'GB',
                phone: '+442079460991',
              },
            })
          ).id;
    }

    const { data: adminAuth } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });

    if (adminAuth?.session) {
      adminToken = adminAuth.session.access_token;
      const addr = await prisma.address.findFirst({ where: { profileId: adminAuth.user.id } });
      adminAddressId = addr
        ? addr.id
        : (
            await prisma.address.create({
              data: {
                profileId: adminAuth.user.id,
                recipientName: 'Admin Recipient',
                line1: '10 Downing St',
                city: 'London',
                state: 'London',
                postalCode: 'SW1A 2AA',
                country: 'GB',
                phone: '+442079460000',
              },
            })
          ).id;
    }
  });

  beforeEach(() => {
    // Reset rate limiter windows between tests
    rateLimiter.reset();
  });

  describe('ACCEPTANCE 1: Rejection of Extra / Unknown Fields (Strict Zod Schemas)', () => {
    it('rejects unknown / injected fields on POST /api/auth/login with 422 ValidationError', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'valid.customer@example.com',
          password: 'Password123!',
          extraInjectedField: 'malicious_payload',
          isAdmin: true,
        }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toBe('Request validation failed');

      const unrecognizedFields = body.error.details.map((d: { message: string }) => d.message);
      expect(unrecognizedFields.some((m: string) => m.includes('extraInjectedField') || m.includes('Unrecognized key'))).toBe(true);
    });

    it('rejects extra fields on POST /api/auth/register with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test.register.extra@example.com',
          password: 'SecurePassword123!',
          name: 'Arthur Pendelton',
          unrecognizedAdminFlag: true, // Unknown field on strict schema
        }),
      });

      const res = await registerRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects extra fields on POST /api/orders (checkout) with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          addressId: customerAddressId,
          hackedPriceOverride: 0, // Injected extra field
        }),
      });

      const res = await checkoutRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects extra fields on POST /api/cart with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          productVariantId: '11111111-1111-1111-1111-111111111111',
          quantity: 2,
          unitPriceInCents: 50, // Client attempting to dictate price
        }),
      });

      const res = await cartRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects extra fields on bespoke POST /api/custom-orders with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/custom-orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          description: 'Custom bespoke tuxedo for royal opera gala.',
          status: 'ACCEPTED', // Unauthorized client status injection
        }),
      });

      const res = await customOrderRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('verifies strict schema rejection at unit level for all core entities', () => {
      expect(() =>
        registerSchema.parse({
          email: 'test@example.com',
          password: 'Password123!',
          name: 'Test',
          unknownAdminFlag: true,
        })
      ).toThrow();

      expect(() =>
        loginSchema.parse({
          email: 'test@example.com',
          password: 'Password123!',
          injected: 'value',
        })
      ).toThrow();

      expect(() =>
        checkoutSchema.parse({
          addressId: crypto.randomUUID(),
          extraField: 'not_allowed',
        })
      ).toThrow();

      expect(() =>
        createCustomOrderSchema.parse({
          description: 'Bespoke midnight navy three-piece suit',
          rogueKey: 'should_fail',
        })
      ).toThrow();

      expect(() =>
        addToCartSchema.parse({
          productVariantId: '11111111-1111-1111-1111-111111111111',
          quantity: 1,
          customPrice: 100,
        })
      ).toThrow();
    });
  });

  describe('ACCEPTANCE 2: Rejection of Oversized Payloads (HTTP 413 & Max Length Bounds)', () => {
    it('rejects oversized HTTP request payloads (> 100KB) with 413 Payload Too Large', async () => {
      // Simulate Content-Length exceeding 100KB (102,400 bytes)
      const oversizedByteLength = 150_000;
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(oversizedByteLength),
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'Password123!' }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(413);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.PAYLOAD_TOO_LARGE);
      expect(body.error.message).toContain('exceeds maximum allowed limit');
    });

    it('rejects oversized JSON payloads on upload routes (> 20KB) with 413 Payload Too Large', async () => {
      // Content-Length exceeding 20KB (20,480 bytes)
      const oversizedByteLength = 25 * 1024;
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(oversizedByteLength),
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({ fileName: 'test.jpg', mimeType: 'image/jpeg', size: 1024 }),
      });

      const res = await uploadRoute(req, {} as never);
      expect(res.status).toBe(413);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.PAYLOAD_TOO_LARGE);
      expect(body.error.message).toContain('exceeds maximum allowed limit (20480 bytes)');
    });

    it('rejects oversized string fields exceeding maximum character lengths with 422 ValidationError', async () => {
      // Bespoke description maximum is 2000 characters
      const massiveDescription = 'A'.repeat(3000);
      const req = new NextRequest('http://localhost:3000/api/custom-orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          description: massiveDescription,
        }),
      });

      const res = await customOrderRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.details.some((d: { message: string }) => d.message.includes('cannot exceed 2000 characters'))).toBe(true);
    });

    it('rejects oversized phone numbers exceeding 30 characters on registration', async () => {
      const massivePhone = '+44' + '9'.repeat(50);
      const req = new NextRequest('http://localhost:3000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test.phone.max@example.com',
          password: 'Password123!',
          name: 'Lord Sterling',
          phone: massivePhone,
        }),
      });

      const res = await registerRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.error.details.some((d: { message: string }) => d.message.includes('cannot exceed 30 characters'))).toBe(true);
    });
  });

  describe('ACCEPTANCE 3: Rate Limiting & Rapid-Fire Request Rejection (429 + Retry-After)', () => {
    it('rejects rapid-fire requests on auth route (/api/auth/login) with 429 and Retry-After header', async () => {
      // Set limit of 3 requests per 60s for testing
      rateLimiter.setRule('auth', { maxRequests: 3, windowSeconds: 60 });
      const testIp = '198.51.100.12';

      const makeRequest = (email: string) => {
        const req = new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email,
            password: 'WrongPassword123!',
          }),
        });
        (req as any).ip = testIp;
        return req;
      };

      // Requests 1, 2, 3 should proceed past rate limiting (different emails to avoid single-email limit)
      const res1 = await loginRoute(makeRequest('rapid.user.1@example.com'), {} as never);
      const res2 = await loginRoute(makeRequest('rapid.user.2@example.com'), {} as never);
      const res3 = await loginRoute(makeRequest('rapid.user.3@example.com'), {} as never);

      expect(res1.status).not.toBe(429);
      expect(res2.status).not.toBe(429);
      expect(res3.status).not.toBe(429);

      // Request 4 from same IP must be rate-limited by IP bucket
      const res4 = await loginRoute(makeRequest('rapid.user.4@example.com'), {} as never);
      expect(res4.status).toBe(429);

      // Must include standard Retry-After header (in seconds)
      const retryAfter = res4.headers.get('Retry-After');
      expect(retryAfter).toBeDefined();
      expect(parseInt(retryAfter!, 10)).toBeGreaterThan(0);

      const body = await res4.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.RATE_LIMITED);
      expect(body.error.message).toContain('Too many requests');
    });

    it('rate-limits checkout route (POST /api/orders) per IP and per user', async () => {
      rateLimiter.setRule('checkout', { maxRequests: 2, windowSeconds: 60 });
      const testIp = '203.0.113.88';

      const makeCheckoutRequest = (ip: string) => {
        const req = new NextRequest('http://localhost:3000/api/orders', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${customerToken}`,
          },
          body: JSON.stringify({
            addressId: customerAddressId,
          }),
        });
        (req as any).ip = ip;
        return req;
      };

      // 1st and 2nd pass rate limiter
      const r1 = await checkoutRoute(makeCheckoutRequest(testIp), {} as never);
      const r2 = await checkoutRoute(makeCheckoutRequest(testIp), {} as never);
      expect(r1.status).not.toBe(429);
      expect(r2.status).not.toBe(429);

      // 3rd is rejected with 429 + Retry-After
      const r3 = await checkoutRoute(makeCheckoutRequest(testIp), {} as never);
      expect(r3.status).toBe(429);
      expect(r3.headers.get('Retry-After')).toBeDefined();
      const body = await r3.json();
      expect(body.error.code).toBe(ErrorCode.RATE_LIMITED);
    });

    it('rate-limits upload routes (/api/uploads) with 429 and Retry-After', async () => {
      rateLimiter.setRule('upload', { maxRequests: 2, windowSeconds: 60 });
      const testIp = '192.0.2.45';

      const makeUploadRequest = () => {
        const req = new NextRequest('http://localhost:3000/api/uploads', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${customerToken}`,
          },
          body: JSON.stringify({
            fileName: 'suit-fabric-sample.jpg',
            mimeType: 'image/jpeg',
            size: 204800,
          }),
        });
        (req as any).ip = testIp;
        return req;
      };

      const r1 = await uploadRoute(makeUploadRequest(), {} as never);
      const r2 = await uploadRoute(makeUploadRequest(), {} as never);
      expect(r1.status).not.toBe(429);
      expect(r2.status).not.toBe(429);

      const r3 = await uploadRoute(makeUploadRequest(), {} as never);
      expect(r3.status).toBe(429);
      expect(r3.headers.get('Retry-After')).toBeDefined();
      const body = await r3.json();
      expect(body.error.code).toBe(ErrorCode.RATE_LIMITED);
    });

    it('isolates rate limiting buckets between distinct IP addresses', async () => {
      rateLimiter.setRule('auth', { maxRequests: 2, windowSeconds: 60 });

      const makeReq = (ip: string, email: string) => {
        const req = new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password: 'Password123!' }),
        });
        (req as any).ip = ip;
        return req;
      };

      // IP Alpha consumes its 2 requests
      await loginRoute(makeReq('10.0.0.1', 'alpha1@example.com'), {} as never);
      await loginRoute(makeReq('10.0.0.1', 'alpha2@example.com'), {} as never);
      const alphaBlocked = await loginRoute(makeReq('10.0.0.1', 'alpha3@example.com'), {} as never);
      expect(alphaBlocked.status).toBe(429);

      // IP Beta has not made any requests yet, so it succeeds
      const betaAllowed = await loginRoute(makeReq('10.0.0.2', 'beta1@example.com'), {} as never);
      expect(betaAllowed.status).not.toBe(429);
    });

    it('enforces per-user rate limit independently from per-IP limit (IP rotation does not bypass user limit)', async () => {
      rateLimiter.setRule('checkout', { maxRequests: 2, windowSeconds: 60 });

      const makeCheckoutReq = (ip: string) => {
        const req = new NextRequest('http://localhost:3000/api/orders', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${customerToken}`,
          },
          body: JSON.stringify({
            addressId: customerAddressId,
          }),
        });
        (req as any).ip = ip;
        return req;
      };

      // Request 1 from IP Alpha for customerToken (user count 1, IP Alpha count 1)
      const r1 = await checkoutRoute(makeCheckoutReq('198.51.100.1'), {} as never);
      expect(r1.status).not.toBe(429);

      // Request 2 from IP Beta for SAME customerToken (user count 2, IP Beta count 1)
      const r2 = await checkoutRoute(makeCheckoutReq('198.51.100.2'), {} as never);
      expect(r2.status).not.toBe(429);

      // Request 3 from IP Gamma (a brand-new IP with 0 prior requests) for SAME customerToken
      // IP Gamma has made 0 requests, but customer's per-user limit of 2 is exceeded
      const r3 = await checkoutRoute(makeCheckoutReq('198.51.100.3'), {} as never);
      expect(r3.status).toBe(429);
      const body3 = await r3.json();
      expect(body3.error.code).toBe(ErrorCode.RATE_LIMITED);
      expect(r3.headers.get('Retry-After')).toBeDefined();

      // Conversely, a DIFFERENT user (adminToken) on IP Gamma is NOT blocked by customer's user limit
      const differentUserReq = new NextRequest('http://localhost:3000/api/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          addressId: adminAddressId,
        }),
      });
      (differentUserReq as any).ip = '198.51.100.3';
      const differentUserRes = await checkoutRoute(differentUserReq, {} as never);
      expect(differentUserRes.status).not.toBe(429);
    });

    it('(a) ignores spoofed x-vercel-forwarded-for, cf-connecting-ip, and x-real-ip when TRUSTED_IP_HEADER=none', () => {
      const prevEnv = process.env.TRUSTED_IP_HEADER;
      try {
        process.env.TRUSTED_IP_HEADER = 'none';

        const spoofedReq = new NextRequest('http://localhost:3000/api/auth/login', {
          headers: {
            'x-vercel-forwarded-for': '203.0.113.199',
            'cf-connecting-ip': '198.51.100.88',
            'x-real-ip': '192.0.2.77',
            'x-forwarded-for': '10.99.99.99',
          },
        });

        // With no connection IP, returns 127.0.0.1 (all spoofed headers ignored)
        expect(getClientIp(spoofedReq)).toBe('127.0.0.1');

        // With connection IP set on socket/request, returns that connection IP
        (spoofedReq as any).ip = '10.20.30.40';
        expect(getClientIp(spoofedReq)).toBe('10.20.30.40');
      } finally {
        process.env.TRUSTED_IP_HEADER = prevEnv;
      }
    });

    it('(b) reads ONLY the single header configured in TRUSTED_IP_HEADER and ignores all others', () => {
      const prevEnv = process.env.TRUSTED_IP_HEADER;
      try {
        // Case 1: cf-connecting-ip
        process.env.TRUSTED_IP_HEADER = 'cf-connecting-ip';
        const reqCf = new NextRequest('http://localhost:3000/api/auth/login', {
          headers: {
            'cf-connecting-ip': '198.51.100.55',
            'x-vercel-forwarded-for': '203.0.113.1',
            'x-real-ip': '192.0.2.1',
          },
        });
        expect(getClientIp(reqCf)).toBe('198.51.100.55');

        // Case 2: x-real-ip
        process.env.TRUSTED_IP_HEADER = 'x-real-ip';
        const reqReal = new NextRequest('http://localhost:3000/api/auth/login', {
          headers: {
            'x-real-ip': '192.0.2.77',
            'cf-connecting-ip': '198.51.100.55',
            'x-vercel-forwarded-for': '203.0.113.1',
          },
        });
        expect(getClientIp(reqReal)).toBe('192.0.2.77');

        // Case 3: x-vercel-forwarded-for
        process.env.TRUSTED_IP_HEADER = 'x-vercel-forwarded-for';
        const reqVercel = new NextRequest('http://localhost:3000/api/auth/login', {
          headers: {
            'x-vercel-forwarded-for': '203.0.113.88, 10.0.0.1',
            'cf-connecting-ip': '198.51.100.55',
            'x-real-ip': '192.0.2.1',
          },
        });
        expect(getClientIp(reqVercel)).toBe('203.0.113.88');
      } finally {
        process.env.TRUSTED_IP_HEADER = prevEnv;
      }
    });

    it('(c) per-email login limit triggers after 5 failed attempts even when IP changes, with identical response for existing and non-existing emails', async () => {
      rateLimiter.reset();

      const existingEmail = 'james.harrington@example.com';
      const nonExistingEmail = 'ghost-nonexistent-user@example.com';

      // 1. Existing email: 5 failed login attempts with rotating IPs
      for (let i = 1; i <= 5; i++) {
        const req = new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: existingEmail, password: 'WrongPassword123!' }),
        });
        (req as any).ip = `10.1.0.${i}`;
        const res = await loginRoute(req, {} as never);
        expect(res.status).toBe(401);
      }

      // 6th attempt from a brand new IP for existing email -> Throttled with generic 401
      const req6Existing = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: existingEmail, password: 'WrongPassword123!' }),
      });
      (req6Existing as any).ip = '10.1.0.99';
      const res6Existing = await loginRoute(req6Existing, {} as never);
      expect(res6Existing.status).toBe(401);
      const jsonExisting = await res6Existing.json();

      // 2. Non-existing email: 5 failed login attempts with rotating IPs
      for (let i = 1; i <= 5; i++) {
        const req = new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: nonExistingEmail, password: 'WrongPassword123!' }),
        });
        (req as any).ip = `10.2.0.${i}`;
        const res = await loginRoute(req, {} as never);
        expect(res.status).toBe(401);
      }

      // 6th attempt from a brand new IP for non-existing email -> Throttled with generic 401
      const req6NonExisting = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: nonExistingEmail, password: 'WrongPassword123!' }),
      });
      (req6NonExisting as any).ip = '10.2.0.99';
      const res6NonExisting = await loginRoute(req6NonExisting, {} as never);
      expect(res6NonExisting.status).toBe(401);
      const jsonNonExisting = await res6NonExisting.json();

      // Verify identical non-enumerating error response structure and content
      expect(jsonExisting.error.code).toBe(ErrorCode.UNAUTHORIZED);
      expect(jsonExisting.error.message).toBe('Invalid email or password');
      expect(jsonNonExisting.error.code).toBe(ErrorCode.UNAUTHORIZED);
      expect(jsonNonExisting.error.message).toBe('Invalid email or password');
      expect(jsonExisting.error).toEqual(jsonNonExisting.error);
    });
  });

  describe('ACCEPTANCE 4: CSRF Protection on Cookie-Authenticated Mutations', () => {
    it('issues an anti-CSRF token and cookie via GET /api/auth/csrf', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/csrf');
      const res = await csrfRoute(req, {} as never);

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(typeof body.data.csrfToken).toBe('string');
      expect(body.data.csrfToken.length).toBeGreaterThanOrEqual(32);

      const csrfCookie = res.cookies.get(CSRF_COOKIE_NAME);
      expect(csrfCookie).toBeDefined();
      expect(csrfCookie?.value).toBe(body.data.csrfToken);
    });

    it('rejects cookie-authenticated mutation when Origin / Referer header is missing', async () => {
      // Cookie is present without Bearer authorization header
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `${AUTH_ACCESS_COOKIE}=some-valid-cookie-token`,
          // Origin & Referer are omitted
        },
        body: JSON.stringify({ name: 'Alistair' }),
      });

      const res = await updateProfileRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('CSRF check failed');
    });

    it('rejects cookie-authenticated mutation when Origin is from an untrusted external domain', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'https://evil-attacker-site.com',
          'Cookie': `${AUTH_ACCESS_COOKIE}=some-valid-cookie-token; ${CSRF_COOKIE_NAME}=token123`,
          [CSRF_HEADER_NAME]: 'token123',
        },
        body: JSON.stringify({ name: 'Alistair' }),
      });

      const res = await updateProfileRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.error.message).toContain('CSRF check failed: invalid, mismatched, or missing request origin');
    });

    it('rejects cookie-authenticated mutation when CSRF token is missing or mismatched', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://localhost:3000',
          'Cookie': `${AUTH_ACCESS_COOKIE}=cookie-token; ${CSRF_COOKIE_NAME}=correct-csrf-token`,
          [CSRF_HEADER_NAME]: 'wrong-or-forged-csrf-token',
        },
        body: JSON.stringify({ name: 'Alistair' }),
      });

      const res = await updateProfileRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.error.message).toContain('missing or invalid CSRF token');
    });

    it('allows Bearer-authenticated mutation to bypass CSRF (immune to ambient browser CSRF)', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-bearer-token',
        },
        body: JSON.stringify({ name: 'Alistair' }),
      });

      const res = await updateProfileRoute(req, {} as never);
      // Fails on auth token validation (401), NOT CSRF forbidden (403)!
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });
  });

  describe('ACCEPTANCE 5: User Free-Text Sanitization', () => {
    it('strips script tags, inner script content, style tags, and dangerous protocols', () => {
      const malicious = '<script>alert("XSS")</script><style>body{display:none}</style><b>Classic</b> <a href="javascript:steal()">Navy</a> Suit\0';
      const sanitized = sanitizeText(malicious);

      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('alert("XSS")');
      expect(sanitized).not.toContain('<style>');
      expect(sanitized).not.toContain('display:none');
      expect(sanitized).not.toContain('<b>');
      expect(sanitized).not.toContain('javascript:');
      expect(sanitized).not.toContain('\0');
      expect(sanitized).toBe('Classic Navy Suit');
    });
  });

  describe('ACCEPTANCE 6: Audit Logging Helper', () => {
    it('creates immutable AuditLog records in database', async () => {
      const testActorId = '00000000-0000-0000-0000-000000000001';
      const testEntityId = '00000000-0000-0000-0000-000000000002';

      const log = await logAuditEvent({
        actorId: testActorId,
        action: 'TEST_ADMIN_ACTION',
        entity: 'Product',
        entityId: testEntityId,
        metadata: { priceUpdated: 150000 },
        ip: '127.0.0.1',
        userAgent: 'Vitest Automated Suite',
      });

      expect(log).toBeDefined();
      expect(log?.action).toBe('TEST_ADMIN_ACTION');
      expect(log?.entity).toBe('Product');
      expect(log?.entityId).toBe(testEntityId);
      expect(log?.actorId).toBe(testActorId);

      // Verify in DB
      const dbRecord = await prisma.auditLog.findUnique({
        where: { id: log!.id },
      });
      expect(dbRecord).toBeDefined();
      expect(dbRecord?.action).toBe('TEST_ADMIN_ACTION');

      // Cleanup
      await prisma.auditLog.delete({ where: { id: log!.id } });
    });
  });
});
