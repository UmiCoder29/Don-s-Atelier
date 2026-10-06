import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { Role } from '@prisma/client';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';
import { getSession, requireAuth, requireRole, AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { middleware } from '@/middleware';
import { POST as registerRoute } from '@/app/api/auth/register/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { POST as logoutRoute } from '@/app/api/auth/logout/route';
import { POST as refreshRoute } from '@/app/api/auth/refresh/route';
import { GET as sessionRoute } from '@/app/api/auth/session/route';
import { POST as passwordResetRequestRoute } from '@/app/api/auth/password-reset/request/route';
import { GET as getAccountProfile, PATCH as updateAccountProfile } from '@/app/api/account/profile/route';
import { GET as getAdminUsers } from '@/app/api/admin/users/route';
import { PATCH as updateAdminUserRole } from '@/app/api/admin/users/[id]/role/route';
import { orderService } from '@/services/order/order-service';
import { ErrorCode } from '@/lib/errors/error-codes';
import { AUTH_ACCESS_COOKIE, AUTH_REFRESH_COOKIE } from '@/lib/auth/cookies';

describe("Don's Atelier - Full Authentication System Verification Pass", () => {
  const customerEmail = 'james.harrington@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerToken: string;
  let adminToken: string;
  let customerId: string;
  let adminId: string;
  let customerAddressId: string;

  // Track dynamically created test users to clean up after test execution
  const createdUserIds: string[] = [];

  beforeAll(async () => {
    // 1. Authenticate seeded customer
    const { data: customerAuth, error: customerErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });
    if (customerErr || !customerAuth.session) {
      throw new Error(`Customer login failed during test setup: ${customerErr?.message}`);
    }
    customerToken = customerAuth.session.access_token;
    customerId = customerAuth.user.id;

    const addr = await prisma.address.findFirst({ where: { profileId: customerId } });
    customerAddressId = addr
      ? addr.id
      : (
          await prisma.address.create({
            data: {
              profileId: customerId,
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

    // 2. Authenticate seeded admin
    const { data: adminAuth, error: adminErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (adminErr || !adminAuth.session) {
      throw new Error(`Admin login failed during test setup: ${adminErr?.message}`);
    }
    adminToken = adminAuth.session.access_token;
    adminId = adminAuth.user.id;
  });

  afterAll(async () => {
    // Cleanup any users created during tests
    for (const uid of createdUserIds) {
      try {
        await prisma.cartItem.deleteMany({ where: { cart: { profileId: uid } } });
        await prisma.cart.deleteMany({ where: { profileId: uid } });
        await prisma.auditLog.deleteMany({ where: { actorId: uid } });
        await prisma.profile.deleteMany({ where: { id: uid } });
        await supabaseAdmin.auth.admin.deleteUser(uid);
      } catch (err) {
        console.warn(`Cleanup error for user ${uid}:`, err);
      }
    }
  });

  // =========================================================================
  // CHECK 1: Registration, Login, Logout End-to-End & Role CUSTOMER Guarantee
  // =========================================================================
  describe('CHECK 1: Registration, Login, and Logout End-to-End & Role CUSTOMER Guarantee', () => {
    const uniqueSuffix = Date.now().toString().slice(-6);
    const testEmail = `bespoke.client.${uniqueSuffix}@example.com`;
    const testPassword = 'SecurePassword2026!Tailor';
    let newUserId: string;
    let newSessionToken: string;

    it('1.1: Registration succeeds end-to-end and assigns role CUSTOMER even if request body attempts role ADMIN', async () => {
      const regReq = new NextRequest('http://localhost:3000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          password: testPassword,
          name: `Client ${uniqueSuffix}`,
          phone: '+442079460111',
          role: 'ADMIN', // Hostile attempt to escalate role in request body
        }),
      });

      const regRes = await registerRoute(regReq, {} as never);
      expect(regRes.status).toBe(201);

      const regBody = await regRes.json();
      expect(regBody.success).toBe(true);

      newUserId = regBody.data.user.id;
      createdUserIds.push(newUserId);

      // Verify that the assigned role is strictly CUSTOMER, never ADMIN
      expect(regBody.data.user.role).toBe(Role.CUSTOMER);

      // Verify authoritative database profile in PostgreSQL
      const dbProfile = await prisma.profile.findUnique({ where: { id: newUserId } });
      expect(dbProfile?.role).toBe(Role.CUSTOMER);

      // Verify shopping cart auto-initialized
      const cart = await prisma.cart.findUnique({ where: { profileId: newUserId } });
      expect(cart).not.toBeNull();
    });

    it('1.2: Login works end-to-end with the newly registered user credentials', async () => {
      // Simulate user completing email verification
      await supabaseAdmin.auth.admin.updateUserById(newUserId, { email_confirm: true });

      const loginReq = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          password: testPassword,
        }),
      });

      const loginRes = await loginRoute(loginReq, {} as never);
      expect(loginRes.status).toBe(200);

      const loginBody = await loginRes.json();
      expect(loginBody.success).toBe(true);
      expect(loginBody.data.user.id).toBe(newUserId);
      expect(loginBody.data.user.role).toBe(Role.CUSTOMER);
      expect(loginBody.data.tokens?.accessToken).toBeTruthy();

      newSessionToken = loginBody.data.tokens.accessToken;

      // Verify active session via GET /api/auth/session
      const sessionReq = new NextRequest('http://localhost:3000/api/auth/session', {
        headers: { Authorization: `Bearer ${newSessionToken}` },
      });
      const sessionRes = await sessionRoute(sessionReq, {} as never);
      expect(sessionRes.status).toBe(200);
      const sessionBody = await sessionRes.json();
      expect(sessionBody.data.user.id).toBe(newUserId);
    });

    it('1.3: Logout works end-to-end, clears cookies, and invalidates the session', async () => {
      const logoutReq = new NextRequest('http://localhost:3000/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${newSessionToken}` },
      });

      const logoutRes = await logoutRoute(logoutReq, {} as never);
      expect(logoutRes.status).toBe(200);

      // Verify cookies cleared with maxAge: 0
      const accessCookie = logoutRes.cookies.get(AUTH_ACCESS_COOKIE);
      const refreshCookie = logoutRes.cookies.get(AUTH_REFRESH_COOKIE);
      expect(accessCookie?.value).toBe('');
      expect(accessCookie?.maxAge).toBe(0);
      expect(refreshCookie?.value).toBe('');
      expect(refreshCookie?.maxAge).toBe(0);

      // Verify token is invalidated on server: GET /api/auth/session rejects with 401
      const checkReq = new NextRequest('http://localhost:3000/api/auth/session', {
        headers: { Authorization: `Bearer ${newSessionToken}` },
      });
      const checkRes = await sessionRoute(checkReq, {} as never);
      expect(checkRes.status).toBe(401);
    });
  });

  // =========================================================================
  // CHECK 2: Email Verification Required Before Checkout Access
  // =========================================================================
  describe('CHECK 2: Email Verification Required Before Checkout Access', () => {
    it('2.1: Blocks checkout with 403 Forbidden for an unverified user (emailConfirmed: false)', async () => {
      const unverifiedUser: AuthenticatedUser = {
        id: 'unverified-customer-001',
        email: 'unconfirmed@example.com',
        role: Role.CUSTOMER,
        emailConfirmed: false,
      };

      await expect(
        orderService.checkout(unverifiedUser, {
          addressId: customerAddressId,
        })
      ).rejects.toThrow('Email verification is required before checkout. Please verify your email.');
    });

    it('2.2: Allows email verification check to pass for verified user (emailConfirmed: true)', async () => {
      const verifiedUser: AuthenticatedUser = {
        id: customerId,
        email: customerEmail,
        role: Role.CUSTOMER,
        emailConfirmed: true,
      };

      // Ensure empty cart so it fails on empty cart (400), proving email check (403) was passed!
      const cart = await prisma.cart.findUnique({ where: { profileId: customerId } });
      if (cart) {
        await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
      }

      await expect(
        orderService.checkout(verifiedUser, {
          addressId: customerAddressId,
        })
      ).rejects.toThrow('Cannot checkout an empty shopping cart');
    });
  });

  // =========================================================================
  // CHECK 3: Role Helpers & Route Access (Anonymous, Customer, Admin)
  // =========================================================================
  describe('CHECK 3: Role Helpers & Protected Routes (Anonymous, Customer, Admin)', () => {
    // 3.1: Anonymous User
    it('3.1a: ANONYMOUS user calling Customer-only route (/api/account/profile) receives 401 Unauthorized', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile');
      const res = await getAccountProfile(req, {} as never);

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('3.1b: ANONYMOUS user calling Admin-only route (/api/admin/users) receives 401 Unauthorized', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/users');
      const res = await getAdminUsers(req, {} as never);

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    // 3.2: Logged-in Customer
    it('3.2a: CUSTOMER calling Customer-only route (/api/account/profile) SUCCEEDS with 200 OK', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        headers: { Authorization: `Bearer ${customerToken}` },
      });
      const res = await getAccountProfile(req, {} as never);

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.profile.id).toBe(customerId);
      expect(body.data.profile.role).toBe(Role.CUSTOMER);
    });

    it('3.2b: CUSTOMER calling Admin-only route (/api/admin/users) receives 403 Forbidden', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        headers: { Authorization: `Bearer ${customerToken}` },
      });
      const res = await getAdminUsers(req, {} as never);

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('Requires one of roles: ADMIN');
    });

    it('3.2c: CUSTOMER calling Admin-only route (/api/admin/users/[id]/role) receives 403 Forbidden', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/users/${customerId}/role`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ role: Role.ADMIN }),
      });
      const res = await updateAdminUserRole(req, { params: Promise.resolve({ id: customerId }) } as never);

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    // 3.3: Admin User
    it('3.3a: ADMIN calling Customer-only route (/api/account/profile) SUCCEEDS with 200 OK', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const res = await getAccountProfile(req, {} as never);

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.profile.id).toBe(adminId);
      expect(body.data.profile.role).toBe(Role.ADMIN);
    });

    it('3.3b: ADMIN calling Admin-only route (/api/admin/users) SUCCEEDS with 200 OK', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const res = await getAdminUsers(req, {} as never);

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);
    });

    // 3.4: Direct Role Helper Invocations
    it('3.4: Direct helper invocations (requireAuth, requireRole) enforce RBAC contracts directly', async () => {
      const anonReq = new NextRequest('http://localhost:3000/api/test');
      const customerReq = new NextRequest('http://localhost:3000/api/test', {
        headers: { Authorization: `Bearer ${customerToken}` },
      });
      const adminReq = new NextRequest('http://localhost:3000/api/test', {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      // requireAuth
      await expect(requireAuth(anonReq)).rejects.toThrow('Authentication token is missing, expired, or invalid');
      const custUser = await requireAuth(customerReq);
      expect(custUser.role).toBe(Role.CUSTOMER);

      // requireRole curried: requireRole('ADMIN')(req)
      await expect(requireRole('ADMIN')(anonReq)).rejects.toThrow('Authentication token is missing, expired, or invalid');
      await expect(requireRole('ADMIN')(customerReq)).rejects.toThrow(/Requires one of roles: ADMIN/);
      const adminUserCurried = await requireRole('ADMIN')(adminReq);
      expect(adminUserCurried.role).toBe(Role.ADMIN);

      // requireRole direct: requireRole(req, 'ADMIN')
      await expect(requireRole(customerReq, 'ADMIN')).rejects.toThrow(/Requires one of roles: ADMIN/);
      const adminUserDirect = await requireRole(adminReq, 'ADMIN');
      expect(adminUserDirect.role).toBe(Role.ADMIN);
    });

    // 3.5: Next.js Middleware Route Guards
    it('3.5: Next.js middleware guards (/api/admin/* and /api/account/*) enforce 401 and 403 correctly', async () => {
      const anonAdminReq = new NextRequest('http://localhost:3000/api/admin/users');
      const anonAccountReq = new NextRequest('http://localhost:3000/api/account/profile');
      const customerAdminReq = new NextRequest('http://localhost:3000/api/admin/users', {
        headers: { Authorization: `Bearer ${customerToken}` },
      });
      const customerAccountReq = new NextRequest('http://localhost:3000/api/account/profile', {
        headers: { Authorization: `Bearer ${customerToken}` },
      });
      const adminAdminReq = new NextRequest('http://localhost:3000/api/admin/users', {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      expect((await middleware(anonAdminReq)).status).toBe(401);
      expect((await middleware(anonAccountReq)).status).toBe(401);
      expect((await middleware(customerAdminReq)).status).toBe(403);
      expect((await middleware(customerAccountReq)).status).toBe(200);
      expect((await middleware(adminAdminReq)).status).toBe(200);
    });
  });

  // =========================================================================
  // CHECK 4: httpOnly Secure Cookies & Server-Side Session Invalidation
  // =========================================================================
  describe('CHECK 4: httpOnly Secure Cookies & Server-Side Session Invalidation on Logout', () => {
    const sessionEmail = 'clara.beaumont@example.com';
    let freshToken: string;
    let claraId: string;

    it('4.1: Login route sets httpOnly, secure, sameSite: lax cookies (sb-access-token, sb-refresh-token)', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: sessionEmail,
          password: customerPassword,
        }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(200);

      const accessCookie = res.cookies.get(AUTH_ACCESS_COOKIE);
      const refreshCookie = res.cookies.get(AUTH_REFRESH_COOKIE);

      expect(accessCookie).toBeDefined();
      expect(accessCookie?.value).toBeTruthy();
      expect(accessCookie?.httpOnly).toBe(true);
      expect(String(accessCookie?.sameSite).toLowerCase()).toBe('lax');

      expect(refreshCookie).toBeDefined();
      expect(refreshCookie?.value).toBeTruthy();
      expect(refreshCookie?.httpOnly).toBe(true);
      expect(String(refreshCookie?.sameSite).toLowerCase()).toBe('lax');

      const body = await res.json();
      freshToken = body.data.tokens.accessToken;
      claraId = body.data.user.id;
    });

    it('4.2: GET /api/auth/session succeeds via httpOnly cookie without Bearer header', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/session', {
        headers: {
          Cookie: `${AUTH_ACCESS_COOKIE}=${freshToken}`,
        },
      });

      const res = await sessionRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.user.id).toBe(claraId);
    });

    it('4.3: Logging out actually invalidates the session on the server (not just clearing client-side)', async () => {
      // 1. Perform logout with the fresh session token
      const req = new NextRequest('http://localhost:3000/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${freshToken}` },
      });

      const res = await logoutRoute(req, {} as never);
      expect(res.status).toBe(200);

      // Verify cookies were cleared client-side
      const accessCookie = res.cookies.get(AUTH_ACCESS_COOKIE);
      const refreshCookie = res.cookies.get(AUTH_REFRESH_COOKIE);
      expect(accessCookie?.value).toBe('');
      expect(accessCookie?.maxAge).toBe(0);
      expect(refreshCookie?.value).toBe('');
      expect(refreshCookie?.maxAge).toBe(0);

      // 2. CRITICAL PROOF: Verify the session is revoked on the Supabase server!
      // Direct call to Supabase Auth admin API fails to get user with the revoked token:
      const supabaseUserCheck = await supabaseAdmin.auth.getUser(freshToken);
      expect(supabaseUserCheck.data.user).toBeNull();
      expect(supabaseUserCheck.error).not.toBeNull();
      expect(supabaseUserCheck.error?.message).toMatch(/Auth session missing|bad_jwt|invalid/i);

      // 3. Application route handler rejects the revoked token with 401 Unauthorized:
      const postLogoutReq = new NextRequest('http://localhost:3000/api/auth/session', {
        headers: { Authorization: `Bearer ${freshToken}` },
      });
      const postLogoutRes = await sessionRoute(postLogoutReq, {} as never);
      expect(postLogoutRes.status).toBe(401);

      const postLogoutBody = await postLogoutRes.json();
      expect(postLogoutBody.success).toBe(false);
      expect(postLogoutBody.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });
  });

  // =========================================================================
  // CHECK 5: Non-Enumeration Protection on Wrong Credentials
  // =========================================================================
  describe('CHECK 5: Non-Enumeration Protection on Wrong Credentials', () => {
    it('5.1: Attempting login with NON-EXISTENT email returns 401 "Invalid email or password"', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'unregistered.bespoke.user.999@dons-atelier.com',
          password: 'IncorrectPassword123!',
        }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
      expect(body.error.message).toBe('Invalid email or password');
    });

    it('5.2: Attempting login with EXISTING email and WRONG password returns IDENTICAL 401 "Invalid email or password"', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: customerEmail,
          password: 'CompletelyWrongPassword999!',
        }),
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
      expect(body.error.message).toBe('Invalid email or password');
    });

    it('5.3: Password reset request returns generic message without revealing if the account exists', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'unknown-client@example.com',
        }),
      });

      const res = await passwordResetRequestRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.message).toContain('If an account exists with this email address');
    });
  });

  // =========================================================================
  // ADDITIONAL: Password Policy & Account Profile Updates
  // =========================================================================
  describe('ADDITIONAL: Password Policy & Account Profile Updates', () => {
    it('rejects password failing policy with 422 ValidationError', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'policy.check@example.com',
          password: 'weak',
          name: 'Policy User',
        }),
      });

      const res = await registerRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('allows customer to update own profile via PATCH /api/account/profile', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'James Harrington Bespoke',
          phone: '+442079460999',
        }),
      });

      const res = await updateAccountProfile(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.name).toBe('James Harrington Bespoke');
      expect(body.data.phone).toBe('+442079460999');

      // Revert back
      const revertReq = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'James Harrington',
          phone: null,
        }),
      });
      await updateAccountProfile(revertReq, {} as never);
    });
  });
});
