import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { ErrorCode } from '@/lib/errors/error-codes';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { CustomOrderStatus, OrderStatus, Role } from '@prisma/client';

// Route handlers
import { PATCH as updateProfileRoute } from '@/app/api/account/profile/route';
import { PATCH as adminUpdateCustomOrderRoute } from '@/app/api/admin/custom-orders/[id]/route';
import { PATCH as adminUpdateOrderRoute } from '@/app/api/admin/orders/[id]/route';
import { POST as createProductRoute } from '@/app/api/admin/products/route';
import { POST as uploadProductImageRoute } from '@/app/api/admin/products/images/route';
import { PATCH as updateProductRoute } from '@/app/api/admin/products/[id]/route';
import { POST as uploadProductImageByIdRoute } from '@/app/api/admin/products/[id]/images/route';
import { POST as createVariantRoute } from '@/app/api/admin/products/[id]/variants/route';
import { PATCH as updateRoleRoute } from '@/app/api/admin/users/[id]/role/route';
import { PATCH as updateVariantRoute } from '@/app/api/admin/variants/[id]/route';
import { POST as adjustStockRoute } from '@/app/api/admin/variants/[id]/stock/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { POST as registerRoute } from '@/app/api/auth/register/route';
import { POST as passwordResetRequestRoute } from '@/app/api/auth/password-reset/request/route';
import { POST as passwordResetConfirmRoute } from '@/app/api/auth/password-reset/confirm/route';
import { POST as addToCartRoute } from '@/app/api/cart/route';
import { PATCH as updateCartItemRoute } from '@/app/api/cart/items/[id]/route';
import { POST as checkoutRoute } from '@/app/api/checkout/route';
import { POST as createCustomOrderRoute } from '@/app/api/custom-orders/route';
import { PATCH as customerEditCustomOrderRoute } from '@/app/api/custom-orders/[id]/route';
import { POST as acceptCustomOrderRoute } from '@/app/api/custom-orders/[id]/accept/route';
import { POST as uploadAttachmentRoute } from '@/app/api/custom-orders/[id]/attachments/route';
import { POST as addMessageRoute } from '@/app/api/custom-orders/[id]/messages/route';
import { POST as addNoteRoute } from '@/app/api/custom-orders/[id]/notes/route';
import { POST as withdrawRoute } from '@/app/api/custom-orders/[id]/withdraw/route';
import { POST as uploadRoute } from '@/app/api/uploads/route';
import { POST as signedUrlRoute } from '@/app/api/uploads/signed-url/route';

describe('Mass-Assignment Security Suite (tests/mass-assignment.test.ts)', () => {
  let customerToken: string;
  let customerId: string;
  let adminToken: string;
  let adminId: string;

  // Reusable test entities
  let testProductId: string;
  let testVariantId: string;
  let testCustomOrderId: string;
  let testOrderId: string;
  let testCartItemId: string;
  let testAddressId: string;

  const PRIVILEGED_FIELDS = {
    role: 'ADMIN',
    id: '00000000-0000-0000-0000-000000000099',
    profileId: '00000000-0000-0000-0000-000000000099',
    customerId: '00000000-0000-0000-0000-000000000099',
    userId: '00000000-0000-0000-0000-000000000099',
    status: 'PAID',
    isInternal: true,
    priceInCents: 100,
    totalInCents: 100,
    unitPriceInCents: 100,
    quotedPriceInCents: 100,
    emailVerified: true,
    stock: 9999,
    createdAt: '2020-01-01T00:00:00.000Z',
    // snake_case alternates
    price_in_cents: 100,
    customer_id: '00000000-0000-0000-0000-000000000099',
    profile_id: '00000000-0000-0000-0000-000000000099',
    user_id: '00000000-0000-0000-0000-000000000099',
    is_internal: true,
    total_in_cents: 100,
    unit_price_in_cents: 100,
    quoted_price_in_cents: 100,
    email_verified: true,
    created_at: '2020-01-01T00:00:00.000Z',
  };

  beforeAll(async () => {
    rateLimiter.reset();

    const customerEmail = 'james.harrington@example.com';
    const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
    const adminEmail = 'admin@dons-atelier.com';
    const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

    const { data: custAuth } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });
    if (!custAuth?.session) throw new Error('Customer auth failed in mass-assignment setup');
    customerToken = custAuth.session.access_token;
    customerId = custAuth.user.id;

    const { data: admAuth } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (!admAuth?.session) throw new Error('Admin auth failed in mass-assignment setup');
    adminToken = admAuth.session.access_token;
    adminId = admAuth.user.id;

    // Fetch existing catalog product & variant
    const product = await prisma.product.findFirst({
      include: { variants: true },
    });
    if (!product || !product.variants[0]) {
      throw new Error('Seed product/variant missing in database');
    }
    testProductId = product.id;
    testVariantId = product.variants[0].id;

    // Fetch or create customer address
    const addr = await prisma.address.findFirst({ where: { profileId: customerId } });
    if (addr) {
      testAddressId = addr.id;
    } else {
      const createdAddr = await prisma.address.create({
        data: {
          profileId: customerId,
          recipientName: 'James Harrington',
          line1: '10 Savile Row',
          city: 'London',
          state: 'London',
          postalCode: 'W1S 3PB',
          country: 'GB',
        },
      });
      testAddressId = createdAddr.id;
    }

    // Create a dedicated custom order for testing customer edit
    const customOrder = await prisma.customOrder.create({
      data: {
        profileId: customerId,
        orderNumber: `MA-BESPOKE-${Date.now()}`,
        status: CustomOrderStatus.SUBMITTED,
        description: 'Original bespoke suit request description for mass assignment test',
      },
    });
    testCustomOrderId = customOrder.id;

    // Create a cart item for customer
    let userCart = await prisma.cart.findUnique({ where: { profileId: customerId } });
    if (!userCart) {
      userCart = await prisma.cart.create({ data: { profileId: customerId } });
    }
    const cartItem = await prisma.cartItem.upsert({
      where: {
        cartId_productVariantId: {
          cartId: userCart.id,
          productVariantId: testVariantId,
        },
      },
      create: {
        cartId: userCart.id,
        productVariantId: testVariantId,
        quantity: 1,
      },
      update: {
        quantity: 1,
      },
    });
    testCartItemId = cartItem.id;

    // Create or find an order for admin testing
    let order = await prisma.order.findFirst({ where: { profileId: customerId } });
    if (!order) {
      order = await prisma.order.create({
        data: {
          profileId: customerId,
          orderNumber: `MA-ORDER-${Date.now()}`,
          status: OrderStatus.PENDING,
          subtotalInCents: 150000,
          shippingInCents: 0,
          totalInCents: 150000,
          shippingAddress: {
            recipientName: 'James Harrington',
            line1: '10 Savile Row',
            city: 'London',
            postalCode: 'W1S 3PB',
            country: 'GB',
          },
        },
      });
    }
    testOrderId = order.id;
  });

  afterAll(async () => {
    if (testCustomOrderId) {
      await prisma.customOrder.delete({ where: { id: testCustomOrderId } }).catch(() => {});
    }
  });

  function makeJsonReq(url: string, method: string, token: string | null, body: Record<string, unknown>) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return new NextRequest(url, {
      method,
      headers,
      body: JSON.stringify(body),
    });
  }

  // --- Account & Profiles ---
  describe('PATCH /api/account/profile', () => {
    it('rejects privileged fields (role, id, emailVerified) with 422 and preserves database row', async () => {
      const initialProfile = await prisma.profile.findUniqueOrThrow({ where: { id: customerId } });

      const req = makeJsonReq('http://localhost:3000/api/account/profile', 'PATCH', customerToken, {
        name: 'James Harrington Updated',
        role: 'ADMIN',
        id: '00000000-0000-0000-0000-000000000001',
        emailVerified: true,
        price_in_cents: 100,
      });

      const res = await updateProfileRoute(req, {} as never);
      expect(res.status).toBe(422);
      const json = await res.json();
      expect(json.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      const unchangedProfile = await prisma.profile.findUniqueOrThrow({ where: { id: customerId } });
      expect(unchangedProfile.role).toBe(Role.CUSTOMER);
      expect(unchangedProfile.id).toBe(customerId);
      expect(unchangedProfile.name).toBe(initialProfile.name);
    });
  });

  // --- Customer Bespoke Routes ---
  describe('Customer Custom Order Routes', () => {
    it('POST /api/custom-orders: rejects quotedPriceInCents, status, id, role with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/custom-orders', 'POST', customerToken, {
        description: 'New custom suit order with injected status and price',
        status: 'PAID',
        quotedPriceInCents: 500,
        priceInCents: 500,
        quoted_price_in_cents: 500,
        id: '00000000-0000-0000-0000-000000000999',
      });

      const res = await createCustomOrderRoute(req, {} as never);
      expect(res.status).toBe(422);
      const json = await res.json();
      expect(json.error.code).toBe(ErrorCode.VALIDATION_ERROR);

      // Verify no order was created with status PAID or id 00000000-0000-0000-0000-000000000999
      const rogueOrder = await prisma.customOrder.findUnique({
        where: { id: '00000000-0000-0000-0000-000000000999' },
      });
      expect(rogueOrder).toBeNull();
    });

    it('PATCH /api/custom-orders/[id]: rejects status, quotedPriceInCents, customerId with 422 and preserves row', async () => {
      const initial = await prisma.customOrder.findUniqueOrThrow({ where: { id: testCustomOrderId } });

      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}`, 'PATCH', customerToken, {
        description: 'Legitimate description update',
        status: 'ACCEPTED',
        quotedPriceInCents: 1000,
        customerId: adminId,
        customer_id: adminId,
      });

      const res = await customerEditCustomOrderRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);

      const after = await prisma.customOrder.findUniqueOrThrow({ where: { id: testCustomOrderId } });
      expect(after.status).toBe(initial.status);
      expect(after.quotedPriceInCents).toBe(initial.quotedPriceInCents);
      expect(after.description).toBe(initial.description);
    });

    it('POST /api/custom-orders/[id]/accept: rejects price, totalInCents, status overrides with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/accept`, 'POST', customerToken, {
        notes: 'Customer acceptance notes',
        priceInCents: 10,
        totalInCents: 10,
        status: 'PAID',
        total_in_cents: 10,
      });

      const res = await acceptCustomOrderRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/messages: rejects role, id, isInternal, customerId with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/messages`, 'POST', customerToken, {
        note: 'Customer follow-up note',
        role: 'ADMIN',
        isInternal: true,
        customerId: adminId,
      });

      const res = await addMessageRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/notes: rejects role, id, isInternal, customerId with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/notes`, 'POST', adminToken, {
        note: 'Customer follow-up note',
        role: 'ADMIN',
        isInternal: true,
        customer_id: adminId,
      });

      const res = await addNoteRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/withdraw: rejects status, id, role with 422 when unknown fields sent', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/withdraw`, 'POST', customerToken, {
        reason: 'Client changed mind',
        status: 'COMPLETED',
        role: 'ADMIN',
      });

      const res = await withdrawRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/attachments: rejects status, id, createdAt, role with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments`, 'POST', customerToken, {
        fileName: 'fabric.jpg',
        storagePath: `custom-orders/${customerId}/fabric-test.jpg`,
        status: 'VERIFIED',
        id: '00000000-0000-0000-0000-000000000999',
        createdAt: '2020-01-01T00:00:00.000Z',
      });

      const res = await uploadAttachmentRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);
    });
  });

  // --- Cart & Checkout ---
  describe('Cart & Checkout Routes', () => {
    it('POST /api/cart: rejects unitPriceInCents, priceInCents, id with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/cart', 'POST', customerToken, {
        productVariantId: testVariantId,
        quantity: 2,
        priceInCents: 100,
        unitPriceInCents: 100,
        price_in_cents: 100,
        unit_price_in_cents: 100,
        id: '00000000-0000-0000-0000-000000000999',
      });

      const res = await addToCartRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('PATCH /api/cart/items/[id]: rejects price, profileId, variantId with 422 and preserves row', async () => {
      const initial = await prisma.cartItem.findUniqueOrThrow({ where: { id: testCartItemId } });

      const req = makeJsonReq(`http://localhost:3000/api/cart/items/${testCartItemId}`, 'PATCH', customerToken, {
        quantity: 3,
        priceInCents: 50,
        profileId: adminId,
        profile_id: adminId,
      });

      const res = await updateCartItemRoute(req, { params: Promise.resolve({ id: testCartItemId }) });
      expect(res.status).toBe(422);

      const after = await prisma.cartItem.findUniqueOrThrow({ where: { id: testCartItemId } });
      expect(after.quantity).toBe(initial.quantity);
      expect(after.cartId).toBe(initial.cartId);
    });

    it('POST /api/checkout: rejects totalInCents, priceInCents, status, profileId with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
          'Idempotency-Key': 'mass-assign-checkout-key-12345',
        },
        body: JSON.stringify({
          addressId: testAddressId,
          totalInCents: 10,
          priceInCents: 10,
          total_in_cents: 10,
          status: 'PAID',
          profileId: adminId,
        }),
      });

      const res = await checkoutRoute(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });
  });

  // --- Admin Catalog & Orders ---
  describe('Admin Routes', () => {
    it('POST /api/admin/products: rejects id, createdAt, role with 422', async () => {
      const category = await prisma.category.findFirstOrThrow();

      const req = makeJsonReq('http://localhost:3000/api/admin/products', 'POST', adminToken, {
        title: 'Bespoke Tweed Jacket',
        slug: `test-tweed-jacket-${Date.now()}`,
        description: 'Finest Scottish tweed jacket handcrafted in atelier',
        basePriceInCents: 120000,
        categoryId: category.id,
        id: '00000000-0000-0000-0000-000000000888',
        createdAt: '2020-01-01T00:00:00.000Z',
        role: 'ADMIN',
      });

      const res = await createProductRoute(req, {} as never);
      expect(res.status).toBe(422);

      const rogue = await prisma.product.findUnique({
        where: { id: '00000000-0000-0000-0000-000000000888' },
      });
      expect(rogue).toBeNull();
    });

    it('PATCH /api/admin/products/[id]: rejects id, createdAt, stock with 422 and preserves row', async () => {
      const initial = await prisma.product.findUniqueOrThrow({ where: { id: testProductId } });

      const req = makeJsonReq(`http://localhost:3000/api/admin/products/${testProductId}`, 'PATCH', adminToken, {
        name: initial.name,
        id: '00000000-0000-0000-0000-000000000888',
        stock: 9999,
        createdAt: '2020-01-01T00:00:00.000Z',
      });

      const res = await updateProductRoute(req, { params: Promise.resolve({ id: testProductId }) });
      expect(res.status).toBe(422);

      const after = await prisma.product.findUniqueOrThrow({ where: { id: testProductId } });
      expect(after.id).toBe(initial.id);
    });

    it('POST /api/admin/products/[id]/variants: rejects id, createdAt, role with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/admin/products/${testProductId}/variants`, 'POST', adminToken, {
        size: '42R',
        color: 'Navy',
        sku: `VAR-TEST-${Date.now()}`,
        priceInCents: 150000,
        stockQuantity: 10,
        id: '00000000-0000-0000-0000-000000000777',
        role: 'SUPERADMIN',
      });

      const res = await createVariantRoute(req, { params: Promise.resolve({ id: testProductId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/variants/[id]: rejects id, sku, createdAt with 422 and preserves row', async () => {
      const initial = await prisma.productVariant.findUniqueOrThrow({ where: { id: testVariantId } });

      const req = makeJsonReq(`http://localhost:3000/api/admin/variants/${testVariantId}`, 'PATCH', adminToken, {
        color: initial.color,
        id: '00000000-0000-0000-0000-000000000777',
        stock: 9999,
        sku: 'HACKED-SKU',
        createdAt: '2020-01-01T00:00:00.000Z',
      });

      const res = await updateVariantRoute(req, { params: Promise.resolve({ id: testVariantId }) });
      expect(res.status).toBe(422);

      const after = await prisma.productVariant.findUniqueOrThrow({ where: { id: testVariantId } });
      expect(after.sku).toBe(initial.sku);
    });

    it('POST /api/admin/variants/[id]/stock: rejects id, stock, role with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/admin/variants/${testVariantId}/stock`, 'POST', adminToken, {
        adjustment: 5,
        reason: 'RESTOCK',
        stock: 9999,
        role: 'ADMIN',
      });

      const res = await adjustStockRoute(req, { params: Promise.resolve({ id: testVariantId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/orders/[id]: rejects totalInCents, id, profileId with 422 and preserves row', async () => {
      const initial = await prisma.order.findUniqueOrThrow({ where: { id: testOrderId } });

      const req = makeJsonReq(`http://localhost:3000/api/admin/orders/${testOrderId}`, 'PATCH', adminToken, {
        status: OrderStatus.PROCESSING,
        totalInCents: 0,
        total_in_cents: 0,
        id: '00000000-0000-0000-0000-000000000999',
        profileId: adminId,
      });

      const res = await adminUpdateOrderRoute(req, { params: Promise.resolve({ id: testOrderId }) });
      expect(res.status).toBe(422);

      const after = await prisma.order.findUniqueOrThrow({ where: { id: testOrderId } });
      expect(after.totalInCents).toBe(initial.totalInCents);
      expect(after.status).toBe(initial.status);
    });

    it('PATCH /api/admin/custom-orders/[id]: rejects customerId, id, createdAt with 422 and preserves row', async () => {
      const initial = await prisma.customOrder.findUniqueOrThrow({ where: { id: testCustomOrderId } });

      const req = makeJsonReq(`http://localhost:3000/api/admin/custom-orders/${testCustomOrderId}`, 'PATCH', adminToken, {
        adminNotes: 'Reviewed by head tailor',
        customerId: adminId,
        customer_id: adminId,
        id: '00000000-0000-0000-0000-000000000999',
        createdAt: '2020-01-01T00:00:00.000Z',
      });

      const res = await adminUpdateCustomOrderRoute(req, { params: Promise.resolve({ id: testCustomOrderId }) });
      expect(res.status).toBe(422);

      const after = await prisma.customOrder.findUniqueOrThrow({ where: { id: testCustomOrderId } });
      expect(after.profileId).toBe(initial.profileId);
    });

    it('PATCH /api/admin/users/[id]/role: rejects id, emailVerified, profileId with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/admin/users/${customerId}/role`, 'PATCH', adminToken, {
        role: 'CUSTOMER',
        id: '00000000-0000-0000-0000-000000000999',
        emailVerified: true,
        email_verified: true,
      });

      const res = await updateRoleRoute(req, { params: Promise.resolve({ id: customerId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products/images: rejects id, role, isInternal with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/admin/products/images', 'POST', adminToken, {
        file: 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP...',
        mimeType: 'image/jpeg',
        id: '00000000-0000-0000-0000-000000000999',
        role: 'ADMIN',
        isInternal: true,
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products/[id]/images: rejects id, role, isInternal with 422', async () => {
      const req = makeJsonReq(`http://localhost:3000/api/admin/products/${testProductId}/images`, 'POST', adminToken, {
        file: 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP...',
        mimeType: 'image/jpeg',
        id: '00000000-0000-0000-0000-000000000999',
        role: 'ADMIN',
        is_internal: true,
      });

      const res = await uploadProductImageByIdRoute(req, { params: Promise.resolve({ id: testProductId }) });
      expect(res.status).toBe(422);
    });
  });

  // --- Auth & Upload Routes ---
  describe('Auth & Storage Routes', () => {
    it('POST /api/auth/login: rejects role, id, isAdmin with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/auth/login', 'POST', null, {
        email: 'test@example.com',
        password: 'Password123!',
        role: 'ADMIN',
        id: '00000000-0000-0000-0000-000000000001',
      });

      const res = await loginRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/register: rejects role, emailVerified, id with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/auth/register', 'POST', null, {
        email: 'attacker@example.com',
        password: 'Password123!',
        name: 'Attacker',
        role: 'ADMIN',
        emailVerified: true,
        email_verified: true,
      });

      const res = await registerRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/password-reset/request: rejects role, id with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/auth/password-reset/request', 'POST', null, {
        email: 'james.harrington@example.com',
        role: 'ADMIN',
      });

      const res = await passwordResetRequestRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/password-reset/confirm: rejects role, id with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/auth/password-reset/confirm', 'POST', 'mock-recovery-bearer-token-12345', {
        password: 'NewSecurePassword123!',
        role: 'ADMIN',
      });

      const res = await passwordResetConfirmRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/uploads: rejects role, id, isInternal with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/uploads', 'POST', customerToken, {
        fileName: 'fabric.jpg',
        mimeType: 'image/jpeg',
        size: 1024,
        role: 'ADMIN',
        id: '00000000-0000-0000-0000-000000000001',
      });

      const res = await uploadRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('POST /api/uploads/signed-url: rejects role, id, isInternal with 422', async () => {
      const req = makeJsonReq('http://localhost:3000/api/uploads/signed-url', 'POST', customerToken, {
        bucket: 'custom-order-uploads',
        path: `custom-orders/${customerId}/sample.jpg`,
        action: 'download',
        role: 'ADMIN',
        id: '00000000-0000-0000-0000-000000000001',
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(422);
    });
  });
});
