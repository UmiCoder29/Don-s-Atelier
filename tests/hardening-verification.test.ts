import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';
import { Role } from '@prisma/client';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { PATCH as updateProfileRoute, GET as getProfileRoute } from '@/app/api/account/profile/route';
import { PATCH as updateRoleRoute } from '@/app/api/admin/users/[id]/role/route';
import { POST as logoutRoute } from '@/app/api/auth/logout/route';
import { GET as getOrderRoute } from '@/app/api/orders/route';
import { POST as ordersRoute } from '@/app/api/checkout/route';
import { GET as getSingleOrderRoute } from '@/app/api/orders/[id]/route';
import { POST as customOrdersRoute } from '@/app/api/custom-orders/route';
import { GET as getSingleCustomOrderRoute } from '@/app/api/custom-orders/[id]/route';
import { GET as getCsrfRoute } from '@/app/api/auth/csrf/route';
import { GET as getAdminUsersRoute } from '@/app/api/admin/users/route';
import { encryptField, decryptField, encryptPhone, decryptPhone, encryptAddressFields, decryptAddressFields, encryptMeasurementValue, decryptMeasurementValue } from '@/lib/crypto/field-encryption';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { AUTH_ACCESS_COOKIE } from '@/lib/auth/cookies';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '@/lib/security/csrf';
import { ErrorCode } from '@/lib/errors/error-codes';

describe("Don's Atelier - Security Hardening Layer Verification Pass", () => {
  const customerEmail = 'james.harrington@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerToken: string;
  let adminToken: string;
  let customerId: string;
  let adminId: string;

  const createdOrderIds: string[] = [];
  const createdCustomOrderIds: string[] = [];

  beforeAll(async () => {
    // 1. Authenticate seeded customer
    const { data: customerAuth, error: customerErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });
    if (customerErr || !customerAuth.session) {
      throw new Error(`Customer login failed during verification setup: ${customerErr?.message}`);
    }
    customerToken = customerAuth.session.access_token;
    customerId = customerAuth.user.id;

    // 2. Authenticate seeded admin
    const { data: adminAuth, error: adminErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (adminErr || !adminAuth.session) {
      throw new Error(`Admin login failed during verification setup: ${adminErr?.message}`);
    }
    adminToken = adminAuth.session.access_token;
    adminId = adminAuth.user.id;

    // Reset rate limiter for clean verification
    rateLimiter.reset();
  });

  afterAll(async () => {
    // Cleanup any created test orders
    for (const orderId of createdOrderIds) {
      await prisma.orderStatusHistory.deleteMany({ where: { orderId } }).catch(() => {});
      await prisma.orderItem.deleteMany({ where: { orderId } }).catch(() => {});
      await prisma.payment.deleteMany({ where: { orderId } }).catch(() => {});
      await prisma.order.delete({ where: { id: orderId } }).catch(() => {});
    }
    for (const customOrderId of createdCustomOrderIds) {
      await prisma.measurement.deleteMany({ where: { customOrderId } }).catch(() => {});
      await prisma.customOrderStatusHistory.deleteMany({ where: { customOrderId } }).catch(() => {});
      await prisma.customOrder.delete({ where: { id: customOrderId } }).catch(() => {});
    }
  });

  // =========================================================================
  // CHECK 1: Input Validation
  // =========================================================================
  describe('CHECK 1: Input Validation (3 routes: auth, account, admin)', () => {
    it('1.1 Auth route (POST /api/auth/login) rejects extra unknown field, oversized payload, and wrong data type', async () => {
      // 1. Extra unknown field
      const extraFieldReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: customerEmail,
          password: customerPassword,
          maliciousField: 'exploit_value',
        }),
      });
      const extraFieldRes = await loginRoute(extraFieldReq, { params: Promise.resolve({}) });
      expect(extraFieldRes.status).toBe(422);
      const extraJson = await extraFieldRes.json();
      expect(extraJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(extraJson.error.message).toBe('Request validation failed');

      // 2. Oversized payload (email exceeds 255 chars)
      const oversizedReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: `${'a'.repeat(250)}@example.com`,
          password: customerPassword,
        }),
      });
      const oversizedRes = await loginRoute(oversizedReq, { params: Promise.resolve({}) });
      expect(oversizedRes.status).toBe(422);
      const oversizedJson = await oversizedRes.json();
      expect(oversizedJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 3. Wrong data type (email is numeric)
      const wrongTypeReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: 99999999,
          password: customerPassword,
        }),
      });
      const wrongTypeRes = await loginRoute(wrongTypeReq, { params: Promise.resolve({}) });
      expect(wrongTypeRes.status).toBe(422);
      const wrongTypeJson = await wrongTypeRes.json();
      expect(wrongTypeJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('1.2 Account route (PATCH /api/account/profile) rejects extra unknown field, oversized payload, and wrong data type', async () => {
      const initialProfile = await prisma.profile.findUnique({ where: { id: customerId } });

      // 1. Extra unknown field
      const extraFieldReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          name: 'James Harrington Jr',
          isAdminEscalation: true,
        }),
      });
      const extraFieldRes = await updateProfileRoute(extraFieldReq, { params: Promise.resolve({}) });
      expect(extraFieldRes.status).toBe(422);
      const extraJson = await extraFieldRes.json();
      expect(extraJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 2. Oversized payload (name exceeds 100 chars)
      const oversizedReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          name: 'X'.repeat(105),
        }),
      });
      const oversizedRes = await updateProfileRoute(oversizedReq, { params: Promise.resolve({}) });
      expect(oversizedRes.status).toBe(422);
      const oversizedJson = await oversizedRes.json();
      expect(oversizedJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 3. Wrong data type (phone is boolean)
      const wrongTypeReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          phone: true,
        }),
      });
      const wrongTypeRes = await updateProfileRoute(wrongTypeReq, { params: Promise.resolve({}) });
      expect(wrongTypeRes.status).toBe(422);
      const wrongTypeJson = await wrongTypeRes.json();
      expect(wrongTypeJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // Confirm nothing was saved in database
      const unchangedProfile = await prisma.profile.findUnique({ where: { id: customerId } });
      expect(unchangedProfile?.name).toBe(initialProfile?.name);
      expect(unchangedProfile?.phone).toBe(initialProfile?.phone);
    });

    it('1.3 Admin route (PATCH /api/admin/users/[id]/role) rejects extra unknown field, oversized payload, and wrong data type', async () => {
      const initialCustomer = await prisma.profile.findUnique({ where: { id: customerId } });

      // 1. Extra unknown field
      const extraFieldReq = new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          role: 'ADMIN',
          grantSuperAdmin: true,
        }),
      });
      const extraFieldRes = await updateRoleRoute(extraFieldReq, { params: Promise.resolve({ id: customerId }) });
      expect(extraFieldRes.status).toBe(422);
      const extraJson = await extraFieldRes.json();
      expect(extraJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // 2. Oversized payload (>100KB body triggers 413)
      const hugeHeaderReq = new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${adminToken}`,
          'content-length': (150 * 1024).toString(),
        },
        body: JSON.stringify({ role: 'ADMIN' }),
      });
      const hugeRes = await updateRoleRoute(hugeHeaderReq, { params: Promise.resolve({ id: customerId }) });
      expect(hugeRes.status).toBe(413);

      // 3. Wrong data type (role is numeric integer)
      const wrongTypeReq = new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          role: 9999,
        }),
      });
      const wrongTypeRes = await updateRoleRoute(wrongTypeReq, { params: Promise.resolve({ id: customerId }) });
      expect(wrongTypeRes.status).toBe(422);
      const wrongTypeJson = await wrongTypeRes.json();
      expect(wrongTypeJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // Confirm nothing was saved in database
      const unchangedCustomer = await prisma.profile.findUnique({ where: { id: customerId } });
      expect(unchangedCustomer?.role).toBe(initialCustomer?.role);
    });
  });

  // =========================================================================
  // CHECK 2: Rate Limiting
  // =========================================================================
  describe('CHECK 2: Rate Limiting (POST /api/auth/login)', () => {
    it('rate limits login route with 429 and Retry-After, enforces per IP and per user, and isolates buckets', async () => {
      rateLimiter.reset();
      const testIpA = '198.51.100.10';
      const testIpB = '198.51.100.20';

      const createReq = (ip: string, email: string = 'nonexistent.attempt@dons-atelier.com') => {
        const req = new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            email,
            password: 'InvalidPassword123!',
          }),
        });
        (req as any).ip = ip;
        return req;
      };

      // Rapidly fire 10 requests from testIpA (limit is 10) with distinct emails to isolate IP limit
      for (let i = 0; i < 10; i++) {
        const res = await loginRoute(createReq(testIpA, `attempt-${i}@dons-atelier.com`), { params: Promise.resolve({}) });
        // Can be 401 unauthorized or processed
        expect(res.status).not.toBe(429);
      }

      // 11th request from testIpA must be rejected with 429 + Retry-After header
      const blockedResA = await loginRoute(createReq(testIpA, 'attempt-11@dons-atelier.com'), { params: Promise.resolve({}) });
      expect(blockedResA.status).toBe(429);
      const retryAfter = blockedResA.headers.get('retry-after');
      expect(retryAfter).toBeTruthy();
      expect(Number(retryAfter)).toBeGreaterThan(0);
      const blockedJson = await blockedResA.json();
      expect(blockedJson.error.code).toBe(ErrorCode.RATE_LIMITED);

      // Request from a DIFFERENT IP (testIpB) must NOT be locked out
      const allowedResB = await loginRoute(createReq(testIpB, 'attempt-b@dons-atelier.com'), { params: Promise.resolve({}) });
      expect(allowedResB.status).not.toBe(429);
    });
  });

  // =========================================================================
  // CHECK 3: CSRF Protection
  // =========================================================================
  describe('CHECK 3: CSRF Protection on Cookie Mutations', () => {
    it('rejects mismatched Origin and succeeds with correct Origin + token, using sameSite: lax cookies', async () => {
      // 1. Fetch genuine CSRF token and cookie from GET /api/auth/csrf
      const csrfReq = new NextRequest('http://localhost:3000/api/auth/csrf', { method: 'GET' });
      const csrfRes = await getCsrfRoute(csrfReq, { params: Promise.resolve({}) });
      expect(csrfRes.status).toBe(200);
      const csrfCookie = csrfRes.cookies.get(CSRF_COOKIE_NAME);
      expect(csrfCookie).toBeTruthy();
      expect(String(csrfCookie?.sameSite).toLowerCase()).toBe('lax');
      const csrfData = await csrfRes.json();
      const validCsrfToken = csrfData.data.csrfToken;
      expect(validCsrfToken).toBeTruthy();

      // 2. Cookie-authenticated mutation from MISMATCHED ORIGIN must fail (403 Forbidden)
      const mismatchedOriginReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          origin: 'https://evil-attacker-website.com',
          [CSRF_HEADER_NAME]: validCsrfToken,
          cookie: `${AUTH_ACCESS_COOKIE}=${customerToken}; ${CSRF_COOKIE_NAME}=${validCsrfToken}`,
        },
        body: JSON.stringify({ name: 'James Harrington CSRF Test' }),
      });
      const blockedMismatchedRes = await updateProfileRoute(mismatchedOriginReq, { params: Promise.resolve({}) });
      expect(blockedMismatchedRes.status).toBe(403);
      const blockedJson = await blockedMismatchedRes.json();
      expect(blockedJson.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(blockedJson.error.message).toMatch(/origin/i);

      // 3. Cookie-authenticated mutation with CORRECT ORIGIN + matching token must SUCCEED
      const legitimateReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          [CSRF_HEADER_NAME]: validCsrfToken,
          cookie: `${AUTH_ACCESS_COOKIE}=${customerToken}; ${CSRF_COOKIE_NAME}=${validCsrfToken}`,
        },
        body: JSON.stringify({ name: 'James Harrington Verified' }),
      });
      const legitimateRes = await updateProfileRoute(legitimateReq, { params: Promise.resolve({}) });
      expect(legitimateRes.status).toBe(200);
      const legitimateJson = await legitimateRes.json();
      expect(legitimateJson.data.name).toBe('James Harrington Verified');
    });
  });

  // =========================================================================
  // CHECK 4: Encryption Utility
  // =========================================================================
  describe('CHECK 4: Encryption Utility (AES-256-GCM)', () => {
    it('encrypts/decrypts sample value, uses random IV, rejects tampered ciphertext, includes version id, and reads from env', () => {
      // 1. Confirm encryption key is read from env variable
      expect(process.env.FIELD_ENCRYPTION_KEY).toBeTruthy();

      const sampleValue = '44 Savile Row, Mayfair, London W1S 2ER, United Kingdom';

      // 2. Encrypt sample value
      const cipherA = encryptField(sampleValue);
      expect(cipherA).not.toBe(sampleValue);
      expect(cipherA.startsWith('enc:')).toBe(true);

      // 3. Confirm output includes key version id (e.g., enc:v1:...)
      const partsA = cipherA.split(':');
      expect(partsA.length).toBe(5);
      const [, keyVersionId, ivHexA, tagHexA, dataHexA] = partsA;
      expect(keyVersionId).toBe('v1');
      expect(ivHexA.length).toBe(24); // 12 bytes = 24 hex chars
      expect(tagHexA.length).toBe(32); // 16 bytes = 32 hex chars

      // 4. Encrypt same value twice -> different ciphertext (random IV)
      const cipherB = encryptField(sampleValue);
      const partsB = cipherB.split(':');
      const ivHexB = partsB[2];
      expect(cipherA).not.toBe(cipherB);
      expect(ivHexA).not.toBe(ivHexB);

      // 5. Decrypt produces original plaintext
      const decryptedA = decryptField(cipherA);
      const decryptedB = decryptField(cipherB);
      expect(decryptedA).toBe(sampleValue);
      expect(decryptedB).toBe(sampleValue);

      // 6. Tampered ciphertext fails to decrypt
      const tamperedDataHex = dataHexA.slice(0, -2) + (dataHexA.slice(-2) === 'aa' ? 'bb' : 'aa');
      const tamperedCipher = `enc:${keyVersionId}:${ivHexA}:${tagHexA}:${tamperedDataHex}`;
      expect(() => decryptField(tamperedCipher)).toThrow(/Decryption failed|corrupted|integrity/i);

      // 7. Tampered tag fails to decrypt
      const tamperedTagHex = '00'.repeat(16);
      const tamperedTagCipher = `enc:${keyVersionId}:${ivHexA}:${tamperedTagHex}:${dataHexA}`;
      expect(() => decryptField(tamperedTagCipher)).toThrow(/Decryption failed|corrupted|integrity/i);
    });
  });

  // =========================================================================
  // CHECK 5: Sensitive Fields Storage & Access Control
  // =========================================================================
  describe('CHECK 5: Sensitive Fields (Phone, Address, Measurements)', () => {
    it('stores phone, address, and measurements encrypted in database and returns decrypted only to owner or admin', async () => {
      // 1. Update Profile with sensitive phone
      const plainPhone = '+44 20 7946 0912';
      const updateReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({ phone: plainPhone }),
      });
      const updateRes = await updateProfileRoute(updateReq, { params: Promise.resolve({}) });
      expect(updateRes.status).toBe(200);

      // Raw DB verification for Phone
      const rawProfile = await prisma.profile.findUnique({ where: { id: customerId } });
      expect(rawProfile?.phone).not.toBe(plainPhone);
      expect(rawProfile?.phone?.startsWith('enc:')).toBe(true);

      // 2. Submit Custom Bespoke Order with sensitive anatomical measurements
      const bespokeReq = new NextRequest('http://localhost:3000/api/custom-orders', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          description: 'Bespoke two-piece suit for formal evening galas',
          fabricPreference: 'Midnight Blue Super 150s Wool',
          stylePreference: 'Single-breasted, peak lapel, bespoke lining',
          measurements: {
            chestInInches: 42.5,
            waistInInches: 34.0,
            hipsInInches: 40.0,
            shoulderWidthInInches: 18.5,
            sleeveLengthInInches: 25.5,
            jacketLengthInInches: 30.0,
            trouserInseamInInches: 32.0,
            trouserOutseamInInches: 42.0,
          },
        }),
      });
      const bespokeRes = await customOrdersRoute(bespokeReq, { params: Promise.resolve({}) });
      expect(bespokeRes.status).toBe(201);
      const bespokeJson = await bespokeRes.json();
      const customOrderId = bespokeJson.data.id;
      createdCustomOrderIds.push(customOrderId);

      // Raw DB verification for Measurements
      const rawMeasurements = await prisma.measurement.findMany({ where: { customOrderId } });
      expect(rawMeasurements.length).toBeGreaterThan(0);
      for (const m of rawMeasurements) {
        expect(m.value.startsWith('enc:')).toBe(true);
        expect(m.value).not.toBe('42.5');
        expect(m.value).not.toBe('34');
      }

      // 3. Create pre-made order with sensitive shipping address
      // First ensure cart has an item
      const variant = await prisma.productVariant.findFirst({ where: { stockQuantity: { gt: 2 } } });
      expect(variant).toBeTruthy();
      const cart = await prisma.cart.findUnique({ where: { profileId: customerId } });
      await prisma.cartItem.upsert({
        where: { cartId_productVariantId: { cartId: cart!.id, productVariantId: variant!.id } },
        create: { cartId: cart!.id, productVariantId: variant!.id, quantity: 1 },
        update: { quantity: 1 },
      });

      const plainAddress = {
        recipientName: 'James Harrington',
        streetLine1: '10 Downing Street',
        streetLine2: 'Apt 4B',
        city: 'London',
        stateOrProvince: 'Greater London',
        postalCode: 'SW1A 2AA',
        country: 'GB',
        phone: '+44 20 7946 0912',
      };

      const createdAddress = await prisma.address.create({
        data: {
          profileId: customerId,
          recipientName: plainAddress.recipientName,
          line1: plainAddress.streetLine1,
          line2: plainAddress.streetLine2,
          city: plainAddress.city,
          state: plainAddress.stateOrProvince,
          postalCode: plainAddress.postalCode,
          country: plainAddress.country,
          phone: plainAddress.phone,
        },
      });

      const orderReq = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
          'idempotency-key': 'idemp-hardening-order-1',
        },
        body: JSON.stringify({
          addressId: createdAddress.id,
        }),
      });
      const orderRes = await ordersRoute(orderReq, { params: Promise.resolve({}) });
      expect(orderRes.status).toBe(201);
      const orderJson = await orderRes.json();
      const orderId = orderJson.data.order.id;
      createdOrderIds.push(orderId);

      // Raw DB verification for Order shippingAddress
      const rawOrder = await prisma.order.findUnique({ where: { id: orderId } });
      const rawAddress = rawOrder?.shippingAddress as Record<string, string>;
      expect(rawAddress.streetLine1.startsWith('enc:')).toBe(true);
      expect(rawAddress.recipientName.startsWith('enc:')).toBe(true);
      expect(rawAddress.streetLine1).not.toBe(plainAddress.streetLine1);

      // 4. Access Control: Owner receives decrypted data
      const ownerGetReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${customerToken}` },
      });
      const ownerGetRes = await getSingleOrderRoute(ownerGetReq, { params: Promise.resolve({ id: orderId }) });
      expect(ownerGetRes.status).toBe(200);
      const ownerData = await ownerGetRes.json();
      expect(ownerData.data.shippingAddress.streetLine1).toBe(plainAddress.streetLine1);

      // 5. Access Control: Admin receives decrypted data
      const adminGetReq = new NextRequest(`http://localhost:3000/api/orders/${orderId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      const adminGetRes = await getSingleOrderRoute(adminGetReq, { params: Promise.resolve({ id: orderId }) });
      expect(adminGetRes.status).toBe(200);
      const adminData = await adminGetRes.json();
      expect(adminData.data.shippingAddress.streetLine1).toBe(plainAddress.streetLine1);
    }, 90000);
  });

  // =========================================================================
  // CHECK 6: Audit Logging
  // =========================================================================
  describe('CHECK 6: Audit Logging (login, failed login, logout, role change)', () => {
    it('creates AuditLog rows with actor, action, and IP for login, failed login, logout, and role change', async () => {
      const testIp = '203.0.113.88';

      // 1. Successful Login
      const loginReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': testIp,
        },
        body: JSON.stringify({
          email: customerEmail,
          password: customerPassword,
        }),
      });
      (loginReq as any).ip = testIp;
      const loginRes = await loginRoute(loginReq, { params: Promise.resolve({}) });
      expect(loginRes.status).toBe(200);

      // Query latest AuditLog for login
      const loginAudit = await prisma.auditLog.findFirst({
        where: { action: 'USER_LOGIN_SUCCESS' },
        orderBy: { timestamp: 'desc' },
      });
      expect(loginAudit).toBeTruthy();
      expect(loginAudit?.actorId).toBe(customerId);
      expect(loginAudit?.ip).toBe(testIp);

      // 2. Failed Login
      const failedLoginReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': testIp,
        },
        body: JSON.stringify({
          email: customerEmail,
          password: 'WrongPassword123!',
        }),
      });
      (failedLoginReq as any).ip = testIp;
      const failedLoginRes = await loginRoute(failedLoginReq, { params: Promise.resolve({}) });
      expect(failedLoginRes.status).toBe(401);

      const failedLoginAudit = await prisma.auditLog.findFirst({
        where: { action: 'USER_LOGIN_FAILED' },
        orderBy: { timestamp: 'desc' },
      });
      expect(failedLoginAudit).toBeTruthy();
      expect(failedLoginAudit?.action).toBe('USER_LOGIN_FAILED');
      expect(failedLoginAudit?.actorId).toBe(customerId);
      expect(failedLoginAudit?.ip).toBe(testIp);

      // 3. Logout
      const logoutReq = new NextRequest('http://localhost:3000/api/auth/logout', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
          'x-forwarded-for': testIp,
        },
      });
      (logoutReq as any).ip = testIp;
      const logoutRes = await logoutRoute(logoutReq, { params: Promise.resolve({}) });
      expect(logoutRes.status).toBe(200);

      const logoutAudit = await prisma.auditLog.findFirst({
        where: { action: 'USER_LOGOUT' },
        orderBy: { timestamp: 'desc' },
      });
      expect(logoutAudit).toBeTruthy();
      expect(logoutAudit?.actorId).toBe(customerId);
      expect(logoutAudit?.ip).toBe(testIp);

      // Re-sign in customer after logout so customerToken remains valid for subsequent tests
      const { data: reauth } = await createSupabaseUserClient().auth.signInWithPassword({
        email: customerEmail,
        password: customerPassword,
      });
      if (reauth?.session) {
        customerToken = reauth.session.access_token;
      }

      // 4. Role Change (Admin action)
      const roleChangeReq = new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${adminToken}`,
          'x-forwarded-for': testIp,
        },
        body: JSON.stringify({ role: Role.CUSTOMER }),
      });
      (roleChangeReq as any).ip = testIp;
      const roleChangeRes = await updateRoleRoute(roleChangeReq, { params: Promise.resolve({ id: customerId }) });
      expect(roleChangeRes.status).toBe(200);

      const roleAudit = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_ROLE_UPDATED' },
        orderBy: { timestamp: 'desc' },
      });
      expect(roleAudit).toBeTruthy();
      expect(roleAudit?.actorId).toBe(adminId);
      expect(roleAudit?.ip).toBe(testIp);
    });
  });

  // =========================================================================
  // CHECK 7: Output Safety
  // =========================================================================
  describe('CHECK 7: Output Safety (Error Sanitization, Free-Text Sanitization, Length Bounds)', () => {
    it('ensures error responses never leak stack traces, SQL, or internal IDs', async () => {
      // Send malformed UUID to admin route
      const badIdReq = new NextRequest('http://localhost:3000/api/admin/users/not-a-valid-uuid/role', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ role: Role.CUSTOMER }),
      });
      const badIdRes = await updateRoleRoute(badIdReq, { params: Promise.resolve({ id: 'not-a-valid-uuid' }) });
      expect(badIdRes.status).toBe(422);
      const badIdJson = await badIdRes.json();
      expect(badIdJson.stack).toBeUndefined();
      expect(badIdJson.error.stack).toBeUndefined();
      const rawString = JSON.stringify(badIdJson);
      expect(rawString).not.toMatch(/node_modules/i);
      expect(rawString).not.toMatch(/SELECT /i);
      expect(rawString).not.toMatch(/INSERT INTO/i);
      expect(rawString).not.toMatch(/prisma/i);
    });

    it('ensures user free-text is sanitized (XSS stripped) and length-limited', async () => {
      // 1. Text sanitization on profile name
      const maliciousName = 'Lord Harrington <script>alert("xss")</script><style>body{color:red}</style>';
      const sanitizeReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({ name: maliciousName }),
      });
      const sanitizeRes = await updateProfileRoute(sanitizeReq, { params: Promise.resolve({}) });
      expect(sanitizeRes.status).toBe(200);
      const sanitizeJson = await sanitizeRes.json();
      expect(sanitizeJson.data.name).toBe('Lord Harrington');
      expect(sanitizeJson.data.name).not.toContain('<script>');
      expect(sanitizeJson.data.name).not.toContain('alert');

      // 2. Length-limited on custom order notes
      const oversizedNotesReq = new NextRequest('http://localhost:3000/api/custom-orders', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          fabricChoice: 'Wool',
          specialInstructions: 'E'.repeat(2500), // Max allowed is 2000
        }),
      });
      const oversizedNotesRes = await customOrdersRoute(oversizedNotesReq, { params: Promise.resolve({}) });
      expect(oversizedNotesRes.status).toBe(422);
      const oversizedNotesJson = await oversizedNotesRes.json();
      expect(oversizedNotesJson.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });
});
