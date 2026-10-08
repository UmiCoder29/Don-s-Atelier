import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { rateLimiter } from '@/lib/security/rate-limiter';

// ---------------------------------------------------------------------------
// Route Handler Imports
// ---------------------------------------------------------------------------

// Public & Auth Routes
import { GET as getHealth } from '@/app/api/health/route';
import { GET as listCategories } from '@/app/api/categories/route';
import { GET as listProducts } from '@/app/api/products/route';
import { GET as getProductBySlug } from '@/app/api/products/[slug]/route';
import { GET as getCsrf } from '@/app/api/auth/csrf/route';
import { POST as authLogin } from '@/app/api/auth/login/route';
import { POST as authLogout } from '@/app/api/auth/logout/route';
import { POST as authRegister } from '@/app/api/auth/register/route';
import { POST as authRefresh } from '@/app/api/auth/refresh/route';
import { POST as authPasswordResetRequest } from '@/app/api/auth/password-reset/request/route';
import { POST as authPasswordResetConfirm } from '@/app/api/auth/password-reset/confirm/route';

// User & Cart & Order & Bespoke Customer Routes
import { GET as getSession } from '@/app/api/auth/session/route';
import { GET as getProfile, PATCH as patchProfile } from '@/app/api/account/profile/route';
import { GET as getCart, POST as addToCart, DELETE as clearCart } from '@/app/api/cart/route';
import { PATCH as updateCartItem, DELETE as removeCartItem } from '@/app/api/cart/items/[id]/route';
import { POST as checkoutRoute } from '@/app/api/checkout/route';
import { GET as listOrders } from '@/app/api/orders/route';
import { GET as getOrderById } from '@/app/api/orders/[id]/route';
import { POST as cancelOrderRoute } from '@/app/api/orders/[id]/cancel/route';
import { GET as listCustomOrders, POST as createCustomOrder } from '@/app/api/custom-orders/route';
import { GET as getCustomOrder, PATCH as patchCustomOrder } from '@/app/api/custom-orders/[id]/route';
import { POST as acceptCustomOrder } from '@/app/api/custom-orders/[id]/accept/route';
import { POST as addCustomOrderAttachment } from '@/app/api/custom-orders/[id]/attachments/route';
import { GET as getCustomOrderAttachment } from '@/app/api/custom-orders/[id]/attachments/[attachmentId]/route';
import { POST as sendCustomOrderMessage } from '@/app/api/custom-orders/[id]/messages/route';
import { POST as addCustomOrderNote } from '@/app/api/custom-orders/[id]/notes/route';
import { GET as getCustomOrderWhatsapp } from '@/app/api/custom-orders/[id]/whatsapp/route';
import { POST as withdrawCustomOrder } from '@/app/api/custom-orders/[id]/withdraw/route';
import { POST as initiateUpload } from '@/app/api/uploads/route';
import { POST as getSignedUrl } from '@/app/api/uploads/signed-url/route';

// Admin Routes
import { GET as getAuditLogs } from '@/app/api/admin/audit-logs/route';
import { GET as listAdminCustomOrders } from '@/app/api/admin/custom-orders/route';
import { GET as getAdminCustomOrder, PATCH as patchAdminCustomOrder } from '@/app/api/admin/custom-orders/[id]/route';
import { GET as getInventory } from '@/app/api/admin/inventory/route';
import { GET as listAdminOrders } from '@/app/api/admin/orders/route';
import { GET as getAdminOrder, PATCH as patchAdminOrder } from '@/app/api/admin/orders/[id]/route';
import { GET as listAdminProducts, POST as createAdminProduct } from '@/app/api/admin/products/route';
import { POST as uploadAdminProductImage } from '@/app/api/admin/products/images/route';
import { GET as getAdminProduct, PATCH as patchAdminProduct, DELETE as deleteAdminProduct } from '@/app/api/admin/products/[id]/route';
import { POST as archiveAdminProduct } from '@/app/api/admin/products/[id]/archive/route';
import { POST as addAdminProductImage } from '@/app/api/admin/products/[id]/images/route';
import { GET as listAdminVariants, POST as createAdminVariant } from '@/app/api/admin/products/[id]/variants/route';
import { GET as getAdminSummary } from '@/app/api/admin/summary/route';
import { GET as listAdminUsers } from '@/app/api/admin/users/route';
import { GET as getAdminUser } from '@/app/api/admin/users/[id]/route';
import { PATCH as patchAdminUserRole } from '@/app/api/admin/users/[id]/role/route';
import { GET as getAdminVariant, PATCH as patchAdminVariant } from '@/app/api/admin/variants/[id]/route';
import { POST as adjustAdminVariantStock } from '@/app/api/admin/variants/[id]/stock/route';
import { POST as cancelExpiredOrdersJob } from '@/app/api/internal/jobs/cancel-expired-orders/route';

describe('Route Matrix Security & Validation Suite', { timeout: 60000 }, () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;
  let customerAId: string;
  let customerBId: string;

  // Resource IDs for IDOR and validation testing
  let customerACartItemId: string;
  let customerAOrderId: string;
  let customerACustomOrderId: string;
  let customerAAttachmentId: string;
  let validVariantId: string;
  let validCategoryId: string;
  let validProductId: string;
  let validAddressId: string;
  let originalCronSecret = process.env.CRON_SECRET;

  beforeAll(async () => {
    rateLimiter.reset();
    if (!process.env.CRON_SECRET || process.env.CRON_SECRET.length < 32) {
      process.env.CRON_SECRET = 'route_matrix_test_cron_secret_32_chars_long!';
    }

    const supabase = createSupabaseUserClient();

    // 1. Authenticate Customer A
    const { data: authA, error: errA } = await supabase.auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    if (errA || !authA.session) throw new Error(`Customer A sign in failed: ${errA?.message}`);
    customerAToken = authA.session.access_token;
    customerAId = authA.user.id;

    // 2. Authenticate Customer B
    const { data: authB, error: errB } = await supabase.auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    if (errB || !authB.session) throw new Error(`Customer B sign in failed: ${errB?.message}`);
    customerBToken = authB.session.access_token;
    customerBId = authB.user.id;

    // 3. Authenticate Admin
    const { data: authAdmin, error: errAdmin } = await supabase.auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdmin || !authAdmin.session) throw new Error(`Admin sign in failed: ${errAdmin?.message}`);
    adminToken = authAdmin.session.access_token;

    // 4. Fetch fixtures for testing
    const variant = await prisma.productVariant.findFirst({
      where: { stockQuantity: { gt: 5 } },
      include: { product: true },
    });
    if (!variant) throw new Error('No product variant available for testing');
    validVariantId = variant.id;
    validProductId = variant.productId;

    const category = await prisma.category.findFirst();
    if (!category) throw new Error('No category available for testing');
    validCategoryId = category.id;

    const address = await prisma.address.findFirst({ where: { profileId: customerAId } });
    if (!address) throw new Error('Customer A has no address on file');
    validAddressId = address.id;

    // Ensure Customer A has a cart with an item
    let cartA = await prisma.cart.findUnique({ where: { profileId: customerAId } });
    if (!cartA) {
      cartA = await prisma.cart.create({ data: { profileId: customerAId } });
    }
    let cartItemA = await prisma.cartItem.findFirst({ where: { cartId: cartA.id } });
    if (!cartItemA) {
      cartItemA = await prisma.cartItem.create({
        data: {
          cartId: cartA.id,
          productVariantId: validVariantId,
          quantity: 1,
        },
      });
    }
    customerACartItemId = cartItemA.id;

    // Ensure Customer A has an order
    let orderA = await prisma.order.findFirst({ where: { profileId: customerAId } });
    if (!orderA) {
      orderA = await prisma.order.create({
        data: {
          profileId: customerAId,
          orderNumber: `DA-TEST-${Date.now()}`,
          status: 'PENDING',
          subtotalInCents: 10000,
          shippingInCents: 0,
          totalInCents: 10000,
          shippingAddress: {
            fullName: 'James Harrington',
            addressLine1: '10 Savile Row',
            city: 'London',
            postalCode: 'W1S 3PR',
            country: 'UK',
          },
        },
      });
    }
    customerAOrderId = orderA.id;

    // Ensure Customer A has a custom order with attachment
    let customOrderA = await prisma.customOrder.findFirst({
      where: { profileId: customerAId },
      include: { attachments: true },
    });
    if (!customOrderA) {
      customOrderA = await prisma.customOrder.create({
        data: {
          profileId: customerAId,
          orderNumber: `CO-${Date.now()}`,
          status: 'SUBMITTED',
          description: 'Custom Bespoke Suit',
          fabricPreference: 'Italian Wool',
        },
        include: { attachments: true },
      });
    }
    customerACustomOrderId = customOrderA.id;

    if (customOrderA.attachments.length > 0) {
      customerAAttachmentId = customOrderA.attachments[0].id;
    } else {
      const att = await prisma.customOrderAttachment.create({
        data: {
          customOrderId: customerACustomOrderId,
          fileName: 'inspiration.jpg',
          size: 1024,
          mimeType: 'image/jpeg',
          storagePath: `custom-orders/${customerAId}/inspiration.jpg`,
        },
      });
      customerAAttachmentId = att.id;
    }
  });

  afterAll(() => {
    if (originalCronSecret !== undefined) {
      process.env.CRON_SECRET = originalCronSecret;
    } else {
      delete process.env.CRON_SECRET;
    }
  });

  beforeEach(() => {
    rateLimiter.reset();
  });

  // ============================================================================
  // NEGATIVE CONTROL TEST
  // ============================================================================
  describe('Negative Control: Test Harness Verification', () => {
    it('proves the test harness fails when a public route is asserted to reject unauthenticated callers', async () => {
      // Define assertion helper that expects 401
      async function assertRejectsUnauthenticated(handler: any, url: string) {
        const req = new NextRequest(url);
        const res = await handler(req, { params: Promise.resolve({}) });
        if (res.status !== 401) {
          throw new Error(`Expected 401 Unauthorized but received status ${res.status}`);
        }
      }

      // Assert that running this check on /api/health (known public route returning 200) throws an Error
      await expect(assertRejectsUnauthenticated(getHealth, 'http://localhost:3000/api/health')).rejects.toThrow(
        'Expected 401 Unauthorized but received status 200'
      );
    });
  });

  // ============================================================================
  // (a) Unauthenticated Request Returns 401 Unauthorized
  // ============================================================================
  describe('(a) Unauthenticated requests return 401 Unauthorized across all protected routes', () => {
    const protectedRoutes: Array<{
      name: string;
      handler: any;
      method: string;
      url: string;
      context?: any;
      body?: any;
    }> = [
      // Account & Session
      { name: 'GET /api/auth/session', handler: getSession, method: 'GET', url: 'http://localhost:3000/api/auth/session' },
      { name: 'GET /api/account/profile', handler: getProfile, method: 'GET', url: 'http://localhost:3000/api/account/profile' },
      { name: 'PATCH /api/account/profile', handler: patchProfile, method: 'PATCH', url: 'http://localhost:3000/api/account/profile', body: { fullName: 'Jane' } },

      // Cart
      { name: 'GET /api/cart', handler: getCart, method: 'GET', url: 'http://localhost:3000/api/cart' },
      { name: 'POST /api/cart', handler: addToCart, method: 'POST', url: 'http://localhost:3000/api/cart', body: { variantId: '123', quantity: 1 } },
      { name: 'DELETE /api/cart', handler: clearCart, method: 'DELETE', url: 'http://localhost:3000/api/cart' },
      { name: 'PATCH /api/cart/items/[id]', handler: updateCartItem, method: 'PATCH', url: 'http://localhost:3000/api/cart/items/item-id', context: { params: Promise.resolve({ id: 'item-id' }) }, body: { quantity: 2 } },
      { name: 'DELETE /api/cart/items/[id]', handler: removeCartItem, method: 'DELETE', url: 'http://localhost:3000/api/cart/items/item-id', context: { params: Promise.resolve({ id: 'item-id' }) } },

      // Orders & Checkout
      { name: 'POST /api/checkout', handler: checkoutRoute, method: 'POST', url: 'http://localhost:3000/api/checkout', body: { addressId: 'addr-id' } },
      { name: 'GET /api/orders', handler: listOrders, method: 'GET', url: 'http://localhost:3000/api/orders' },
      { name: 'GET /api/orders/[id]', handler: getOrderById, method: 'GET', url: 'http://localhost:3000/api/orders/order-id', context: { params: Promise.resolve({ id: 'order-id' }) } },
      { name: 'POST /api/orders/[id]/cancel', handler: cancelOrderRoute, method: 'POST', url: 'http://localhost:3000/api/orders/order-id/cancel', context: { params: Promise.resolve({ id: 'order-id' }) } },

      // Custom Orders (Bespoke)
      { name: 'GET /api/custom-orders', handler: listCustomOrders, method: 'GET', url: 'http://localhost:3000/api/custom-orders' },
      { name: 'POST /api/custom-orders', handler: createCustomOrder, method: 'POST', url: 'http://localhost:3000/api/custom-orders', body: { fabricChoice: 'Wool' } },
      { name: 'GET /api/custom-orders/[id]', handler: getCustomOrder, method: 'GET', url: 'http://localhost:3000/api/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) } },
      { name: 'PATCH /api/custom-orders/[id]', handler: patchCustomOrder, method: 'PATCH', url: 'http://localhost:3000/api/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) }, body: { notes: 'Edit' } },
      { name: 'POST /api/custom-orders/[id]/accept', handler: acceptCustomOrder, method: 'POST', url: 'http://localhost:3000/api/custom-orders/co-id/accept', context: { params: Promise.resolve({ id: 'co-id' }) }, body: {} },
      { name: 'POST /api/custom-orders/[id]/attachments', handler: addCustomOrderAttachment, method: 'POST', url: 'http://localhost:3000/api/custom-orders/co-id/attachments', context: { params: Promise.resolve({ id: 'co-id' }) }, body: {} },
      { name: 'GET /api/custom-orders/[id]/attachments/[attachmentId]', handler: getCustomOrderAttachment, method: 'GET', url: 'http://localhost:3000/api/custom-orders/co-id/attachments/att-id', context: { params: Promise.resolve({ id: 'co-id', attachmentId: 'att-id' }) } },
      { name: 'POST /api/custom-orders/[id]/messages', handler: sendCustomOrderMessage, method: 'POST', url: 'http://localhost:3000/api/custom-orders/co-id/messages', context: { params: Promise.resolve({ id: 'co-id' }) }, body: { content: 'Msg' } },
      { name: 'POST /api/custom-orders/[id]/notes', handler: addCustomOrderNote, method: 'POST', url: 'http://localhost:3000/api/custom-orders/co-id/notes', context: { params: Promise.resolve({ id: 'co-id' }) }, body: { content: 'Note' } },
      { name: 'GET /api/custom-orders/[id]/whatsapp', handler: getCustomOrderWhatsapp, method: 'GET', url: 'http://localhost:3000/api/custom-orders/co-id/whatsapp', context: { params: Promise.resolve({ id: 'co-id' }) } },
      { name: 'POST /api/custom-orders/[id]/withdraw', handler: withdrawCustomOrder, method: 'POST', url: 'http://localhost:3000/api/custom-orders/co-id/withdraw', context: { params: Promise.resolve({ id: 'co-id' }) }, body: { reason: 'Withdraw' } },

      // Uploads
      { name: 'POST /api/uploads', handler: initiateUpload, method: 'POST', url: 'http://localhost:3000/api/uploads', body: {} },
      { name: 'POST /api/uploads/signed-url', handler: getSignedUrl, method: 'POST', url: 'http://localhost:3000/api/uploads/signed-url', body: {} },

      // Admin Routes
      { name: 'GET /api/admin/audit-logs', handler: getAuditLogs, method: 'GET', url: 'http://localhost:3000/api/admin/audit-logs' },
      { name: 'GET /api/admin/custom-orders', handler: listAdminCustomOrders, method: 'GET', url: 'http://localhost:3000/api/admin/custom-orders' },
      { name: 'GET /api/admin/custom-orders/[id]', handler: getAdminCustomOrder, method: 'GET', url: 'http://localhost:3000/api/admin/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) } },
      { name: 'PATCH /api/admin/custom-orders/[id]', handler: patchAdminCustomOrder, method: 'PATCH', url: 'http://localhost:3000/api/admin/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) }, body: {} },
      { name: 'GET /api/admin/inventory', handler: getInventory, method: 'GET', url: 'http://localhost:3000/api/admin/inventory' },
      { name: 'GET /api/admin/orders', handler: listAdminOrders, method: 'GET', url: 'http://localhost:3000/api/admin/orders' },
      { name: 'GET /api/admin/orders/[id]', handler: getAdminOrder, method: 'GET', url: 'http://localhost:3000/api/admin/orders/order-id', context: { params: Promise.resolve({ id: 'order-id' }) } },
      { name: 'PATCH /api/admin/orders/[id]', handler: patchAdminOrder, method: 'PATCH', url: 'http://localhost:3000/api/admin/orders/order-id', context: { params: Promise.resolve({ id: 'order-id' }) }, body: {} },
      { name: 'GET /api/admin/products', handler: listAdminProducts, method: 'GET', url: 'http://localhost:3000/api/admin/products' },
      { name: 'POST /api/admin/products', handler: createAdminProduct, method: 'POST', url: 'http://localhost:3000/api/admin/products', body: {} },
      { name: 'POST /api/admin/products/images', handler: uploadAdminProductImage, method: 'POST', url: 'http://localhost:3000/api/admin/products/images', body: {} },
      { name: 'GET /api/admin/products/[id]', handler: getAdminProduct, method: 'GET', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'PATCH /api/admin/products/[id]', handler: patchAdminProduct, method: 'PATCH', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'DELETE /api/admin/products/[id]', handler: deleteAdminProduct, method: 'DELETE', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/archive', handler: archiveAdminProduct, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/archive', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/images', handler: addAdminProductImage, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/images', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'GET /api/admin/products/[id]/variants', handler: listAdminVariants, method: 'GET', url: 'http://localhost:3000/api/admin/products/prod-id/variants', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/variants', handler: createAdminVariant, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/variants', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'GET /api/admin/summary', handler: getAdminSummary, method: 'GET', url: 'http://localhost:3000/api/admin/summary' },
      { name: 'GET /api/admin/users', handler: listAdminUsers, method: 'GET', url: 'http://localhost:3000/api/admin/users' },
      { name: 'GET /api/admin/users/[id]', handler: getAdminUser, method: 'GET', url: 'http://localhost:3000/api/admin/users/usr-id', context: { params: Promise.resolve({ id: 'usr-id' }) } },
      { name: 'PATCH /api/admin/users/[id]/role', handler: patchAdminUserRole, method: 'PATCH', url: 'http://localhost:3000/api/admin/users/usr-id/role', context: { params: Promise.resolve({ id: 'usr-id' }) }, body: {} },
      { name: 'GET /api/admin/variants/[id]', handler: getAdminVariant, method: 'GET', url: 'http://localhost:3000/api/admin/variants/var-id', context: { params: Promise.resolve({ id: 'var-id' }) } },
      { name: 'PATCH /api/admin/variants/[id]', handler: patchAdminVariant, method: 'PATCH', url: 'http://localhost:3000/api/admin/variants/var-id', context: { params: Promise.resolve({ id: 'var-id' }) }, body: {} },
      { name: 'POST /api/admin/variants/[id]/stock', handler: adjustAdminVariantStock, method: 'POST', url: 'http://localhost:3000/api/admin/variants/var-id/stock', context: { params: Promise.resolve({ id: 'var-id' }) }, body: {} },
      // Internal Jobs (CRON Bearer Auth)
      { name: 'POST /api/internal/jobs/cancel-expired-orders', handler: cancelExpiredOrdersJob, method: 'POST', url: 'http://localhost:3000/api/internal/jobs/cancel-expired-orders' },
    ];

    for (const route of protectedRoutes) {
      it(`rejects unauthenticated ${route.name} with 401 Unauthorized`, async () => {
        const headers: Record<string, string> = {};
        let body: string | undefined = undefined;
        if (route.body) {
          headers['Content-Type'] = 'application/json';
          body = JSON.stringify(route.body);
        }
        const req = new NextRequest(route.url, {
          method: route.method,
          headers,
          body,
        });
        const res = await route.handler(req, route.context ?? { params: Promise.resolve({}) });
        expect(res.status).toBe(401);
      });
    }
  });

  // ============================================================================
  // (b) Wrong Role Returns 403 Forbidden
  // ============================================================================
  describe('(b) Wrong role returns 403 Forbidden across all admin-only routes', () => {
    const adminRoutes: Array<{
      name: string;
      handler: any;
      method: string;
      url: string;
      context?: any;
      body?: any;
    }> = [
      { name: 'GET /api/admin/audit-logs', handler: getAuditLogs, method: 'GET', url: 'http://localhost:3000/api/admin/audit-logs' },
      { name: 'GET /api/admin/custom-orders', handler: listAdminCustomOrders, method: 'GET', url: 'http://localhost:3000/api/admin/custom-orders' },
      { name: 'GET /api/admin/custom-orders/[id]', handler: getAdminCustomOrder, method: 'GET', url: 'http://localhost:3000/api/admin/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) } },
      { name: 'PATCH /api/admin/custom-orders/[id]', handler: patchAdminCustomOrder, method: 'PATCH', url: 'http://localhost:3000/api/admin/custom-orders/co-id', context: { params: Promise.resolve({ id: 'co-id' }) }, body: {} },
      { name: 'GET /api/admin/inventory', handler: getInventory, method: 'GET', url: 'http://localhost:3000/api/admin/inventory' },
      { name: 'GET /api/admin/orders', handler: listAdminOrders, method: 'GET', url: 'http://localhost:3000/api/admin/orders' },
      { name: 'GET /api/admin/orders/[id]', handler: getAdminOrder, method: 'GET', url: 'http://localhost:3000/api/admin/orders/order-id', context: { params: Promise.resolve({ id: 'order-id' }) } },
      { name: 'PATCH /api/admin/orders/[id]', handler: patchAdminOrder, method: 'PATCH', url: 'http://localhost:3000/api/admin/orders/order-id', context: { params: Promise.resolve({ id: 'order-id' }) }, body: {} },
      { name: 'GET /api/admin/products', handler: listAdminProducts, method: 'GET', url: 'http://localhost:3000/api/admin/products' },
      { name: 'POST /api/admin/products', handler: createAdminProduct, method: 'POST', url: 'http://localhost:3000/api/admin/products', body: {} },
      { name: 'POST /api/admin/products/images', handler: uploadAdminProductImage, method: 'POST', url: 'http://localhost:3000/api/admin/products/images', body: {} },
      { name: 'GET /api/admin/products/[id]', handler: getAdminProduct, method: 'GET', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'PATCH /api/admin/products/[id]', handler: patchAdminProduct, method: 'PATCH', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'DELETE /api/admin/products/[id]', handler: deleteAdminProduct, method: 'DELETE', url: 'http://localhost:3000/api/admin/products/prod-id', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/archive', handler: archiveAdminProduct, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/archive', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/images', handler: addAdminProductImage, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/images', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'GET /api/admin/products/[id]/variants', handler: listAdminVariants, method: 'GET', url: 'http://localhost:3000/api/admin/products/prod-id/variants', context: { params: Promise.resolve({ id: 'prod-id' }) } },
      { name: 'POST /api/admin/products/[id]/variants', handler: createAdminVariant, method: 'POST', url: 'http://localhost:3000/api/admin/products/prod-id/variants', context: { params: Promise.resolve({ id: 'prod-id' }) }, body: {} },
      { name: 'GET /api/admin/summary', handler: getAdminSummary, method: 'GET', url: 'http://localhost:3000/api/admin/summary' },
      { name: 'GET /api/admin/users', handler: listAdminUsers, method: 'GET', url: 'http://localhost:3000/api/admin/users' },
      { name: 'GET /api/admin/users/[id]', handler: getAdminUser, method: 'GET', url: 'http://localhost:3000/api/admin/users/usr-id', context: { params: Promise.resolve({ id: 'usr-id' }) } },
      { name: 'PATCH /api/admin/users/[id]/role', handler: patchAdminUserRole, method: 'PATCH', url: 'http://localhost:3000/api/admin/users/usr-id/role', context: { params: Promise.resolve({ id: 'usr-id' }) }, body: {} },
      { name: 'GET /api/admin/variants/[id]', handler: getAdminVariant, method: 'GET', url: 'http://localhost:3000/api/admin/variants/var-id', context: { params: Promise.resolve({ id: 'var-id' }) } },
      { name: 'PATCH /api/admin/variants/[id]', handler: patchAdminVariant, method: 'PATCH', url: 'http://localhost:3000/api/admin/variants/var-id', context: { params: Promise.resolve({ id: 'var-id' }) }, body: {} },
      { name: 'POST /api/admin/variants/[id]/stock', handler: adjustAdminVariantStock, method: 'POST', url: 'http://localhost:3000/api/admin/variants/var-id/stock', context: { params: Promise.resolve({ id: 'var-id' }) }, body: {} },
      {
        name: 'POST /api/uploads',
        handler: initiateUpload,
        method: 'POST',
        url: 'http://localhost:3000/api/uploads',
        body: { fileName: 'photo.jpg', mimeType: 'image/jpeg', size: 1024, folder: 'showcase' },
      },
    ];

    for (const route of adminRoutes) {
      it(`rejects customer calling ${route.name} with 403 Forbidden`, async () => {
        const headers: Record<string, string> = {
          Authorization: `Bearer ${customerAToken}`,
        };
        let body: string | undefined = undefined;
        if (route.body) {
          headers['Content-Type'] = 'application/json';
          body = JSON.stringify(route.body);
        }
        const req = new NextRequest(route.url, {
          method: route.method,
          headers,
          body,
        });
        const res = await route.handler(req, route.context ?? { params: Promise.resolve({}) });
        expect(res.status).toBe(403);
      });
    }
  });

  // ============================================================================
  // (d) Unknown Field on Mutating Route Returns 422
  // ============================================================================
  describe('(d) Unknown field on mutating route returns 422 Unprocessable Entity', () => {
    it('PATCH /api/account/profile rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/account/profile', {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Updated James', __unknown_field: 'malicious' }),
      });
      const res = await patchProfile(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/cart rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ variantId: validVariantId, quantity: 1, __unknown_field: 'malicious' }),
      });
      const res = await addToCart(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/cart/items/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/cart/items/${customerACartItemId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ quantity: 2, __unknown_field: 'malicious' }),
      });
      const res = await updateCartItem(req, { params: Promise.resolve({ id: customerACartItemId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/checkout rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/checkout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `idemp-strict-${Date.now()}`,
        },
        body: JSON.stringify({ addressId: validAddressId, __unknown_field: 'malicious' }),
      });
      const res = await checkoutRoute(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/custom-orders', {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          description: 'A bespoke suit for black tie event',
          fabricPreference: 'Wool',
          __unknown_field: 'malicious',
        }),
      });
      const res = await createCustomOrder(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/custom-orders/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: 'Updated suit description text', __unknown_field: 'malicious' }),
      });
      const res = await patchCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/accept rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/accept`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ expectedPriceInCents: 10000, __unknown_field: 'malicious' }),
      });
      const res = await acceptCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/notes rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/notes`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'Note text', __unknown_field: 'malicious' }),
      });
      const res = await addCustomOrderNote(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/messages rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/messages`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Message text', __unknown_field: 'malicious' }),
      });
      const res = await sendCustomOrderMessage(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/custom-orders/[id]/attachments rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/attachments`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'inspiration.jpg',
          mimeType: 'image/jpeg',
          fileSize: 1024,
          storagePath: 'custom-orders/path.jpg',
          __unknown_field: 'malicious',
        }),
      });
      const res = await addCustomOrderAttachment(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/login rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'valid@example.com',
          password: 'Password123!',
          __unknown_field: 'malicious',
        }),
      });
      const res = await authLogin(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/register rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'valid_new@example.com',
          password: 'Password123!',
          fullName: 'Test User',
          __unknown_field: 'malicious',
        }),
      });
      const res = await authRegister(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/password-reset/request rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com',
          __unknown_field: 'malicious',
        }),
      });
      const res = await authPasswordResetRequest(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/auth/password-reset/confirm rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/auth/password-reset/confirm', {
        method: 'POST',
        headers: { Authorization: 'Bearer mock-recovery-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password: 'Password123!',
          __unknown_field: 'malicious',
        }),
      });
      const res = await authPasswordResetConfirm(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/products', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Classic Tuxedo',
          description: 'Timeless tuxedo suit',
          categoryId: validCategoryId,
          priceInCents: 85000,
          __unknown_field: 'malicious',
        }),
      });
      const res = await createAdminProduct(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/products/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/products/${validProductId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Updated Tuxedo', __unknown_field: 'malicious' }),
      });
      const res = await patchAdminProduct(req, { params: Promise.resolve({ id: validProductId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products/images rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageUrl: 'https://example.com/suit.jpg',
          altText: 'Showcase',
          isPrimary: true,
          __unknown_field: 'malicious',
        }),
      });
      const res = await uploadAdminProductImage(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products/[id]/images rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/products/${validProductId}/images`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageUrl: 'https://example.com/suit.jpg',
          altText: 'Showcase',
          isPrimary: true,
          __unknown_field: 'malicious',
        }),
      });
      const res = await addAdminProductImage(req, { params: Promise.resolve({ id: validProductId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/products/[id]/variants rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/products/${validProductId}/variants`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sku: 'SUIT-NEW-TEST',
          size: '40R',
          color: 'Charcoal',
          priceInCents: 90000,
          stockQuantity: 5,
          __unknown_field: 'malicious',
        }),
      });
      const res = await createAdminVariant(req, { params: Promise.resolve({ id: validProductId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/variants/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/variants/${validVariantId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ priceInCents: 92000, __unknown_field: 'malicious' }),
      });
      const res = await patchAdminVariant(req, { params: Promise.resolve({ id: validVariantId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/admin/variants/[id]/stock rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/variants/${validVariantId}/stock`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ delta: 5, reason: 'RESTOCK', __unknown_field: 'malicious' }),
      });
      const res = await adjustAdminVariantStock(req, { params: Promise.resolve({ id: validVariantId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/orders/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/orders/${customerAOrderId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'PROCESSING', reason: 'Tailoring begun', __unknown_field: 'malicious' }),
      });
      const res = await patchAdminOrder(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/custom-orders/[id] rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${customerACustomOrderId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'IN_REVIEW', internalNotes: 'Checking fit', __unknown_field: 'malicious' }),
      });
      const res = await patchAdminCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect(res.status).toBe(422);
    });

    it('PATCH /api/admin/users/[id]/role rejects unknown field with 422', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/users/${customerAId}/role`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'CUSTOMER', __unknown_field: 'malicious' }),
      });
      const res = await patchAdminUserRole(req, { params: Promise.resolve({ id: customerAId }) });
      expect(res.status).toBe(422);
    });

    it('POST /api/uploads rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'photo.jpg',
          mimeType: 'image/jpeg',
          size: 1024,
          folder: 'showcase',
          __unknown_field: 'malicious',
        }),
      });
      const res = await initiateUpload(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });

    it('POST /api/uploads/signed-url rejects unknown field with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerAToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bucket: 'custom-order-uploads',
          path: 'photo.jpg',
          operation: 'upload',
          __unknown_field: 'malicious',
        }),
      });
      const res = await getSignedUrl(req, { params: Promise.resolve({}) });
      expect(res.status).toBe(422);
    });
  });

  // ============================================================================
  // (c) Targeted IDOR Tests for Every Route that Takes an Owned Resource ID
  // ============================================================================
  describe('(c) Targeted IDOR tests: Customer B cannot access or mutate Customer A resources', () => {
    it('PATCH /api/cart/items/[id]: Customer B cannot mutate Customer A cart item (rejected with 404/403)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/cart/items/${customerACartItemId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ quantity: 5 }),
      });
      const res = await updateCartItem(req, { params: Promise.resolve({ id: customerACartItemId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('DELETE /api/cart/items/[id]: Customer B cannot delete Customer A cart item (rejected with 404/403)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/cart/items/${customerACartItemId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const res = await removeCartItem(req, { params: Promise.resolve({ id: customerACartItemId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('GET /api/orders/[id]: Customer B cannot view Customer A order detail (rejected with 403 Forbidden)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/orders/${customerAOrderId}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const res = await getOrderById(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(403);
    });

    it('POST /api/orders/[id]/cancel: Customer B cannot cancel Customer A order (rejected with 403 Forbidden)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/orders/${customerAOrderId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const res = await cancelOrderRoute(req, { params: Promise.resolve({ id: customerAOrderId }) });
      expect(res.status).toBe(403);
    });

    it('GET /api/custom-orders/[id]: Customer B cannot view Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const res = await getCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('PATCH /api/custom-orders/[id]: Customer B cannot edit Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: 'Malicious modification of description' }),
      });
      const res = await patchCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('POST /api/custom-orders/[id]/accept: Customer B cannot accept quote on Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/accept`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ expectedPriceInCents: 10000 }),
      });
      const res = await acceptCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('POST /api/custom-orders/[id]/withdraw: Customer B cannot withdraw Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/withdraw`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Malicious withdraw' }),
      });
      const res = await withdrawCustomOrder(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('POST /api/custom-orders/[id]/notes: Customer B cannot add note to Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/notes`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'Malicious note content' }),
      });
      const res = await addCustomOrderNote(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('POST /api/custom-orders/[id]/messages: Customer B cannot send message on Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/messages`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Malicious message content' }),
      });
      const res = await sendCustomOrderMessage(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('POST /api/custom-orders/[id]/attachments: Customer B cannot attach files to Customer A custom order (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/attachments`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${customerBToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'malicious.jpg',
          mimeType: 'image/jpeg',
          fileSize: 1024,
          storagePath: 'custom-orders/path.jpg',
        }),
      });
      const res = await addCustomOrderAttachment(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });

    it('GET /api/custom-orders/[id]/attachments/[attachmentId]: Customer B cannot view Customer A attachment (rejected with 403 Forbidden)', async () => {
      const req = new NextRequest(
        `http://localhost:3000/api/custom-orders/${customerACustomOrderId}/attachments/${customerAAttachmentId}`,
        {
          method: 'GET',
          headers: { Authorization: `Bearer ${customerBToken}` },
        }
      );
      const res = await getCustomOrderAttachment(req, {
        params: Promise.resolve({ id: customerACustomOrderId, attachmentId: customerAAttachmentId }),
      });
      expect([403, 404]).toContain(res.status);
    });

    it('GET /api/custom-orders/[id]/whatsapp: Customer B cannot view Customer A WhatsApp handoff (rejected with 403/404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${customerACustomOrderId}/whatsapp`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const res = await getCustomOrderWhatsapp(req, { params: Promise.resolve({ id: customerACustomOrderId }) });
      expect([403, 404]).toContain(res.status);
    });
  });
});
