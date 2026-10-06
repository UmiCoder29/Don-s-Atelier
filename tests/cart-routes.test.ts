import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { ProductStatus } from '@prisma/client';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { GET as getCart, POST as addToCart, DELETE as clearCart } from '@/app/api/cart/route';
import { PATCH as updateCartItem, DELETE as deleteCartItem } from '@/app/api/cart/items/[id]/route';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { ErrorCode } from '@/lib/errors/error-codes';
import { MAX_LINE_ITEM_QUANTITY, MAX_DISTINCT_CART_ITEMS } from '@/services/cart/types';

describe('Cart API Routes', { timeout: 60000 }, () => {
  const customerAEmail = 'clara.beaumont@example.com';
  const customerBEmail = 'james.harrington@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;

  let standardVariantId: string;
  let standardVariantPriceInCents: number;
  let lowStockVariantId: string;
  let lowStockSku: string;
  let inactiveVariantId: string;
  let inactiveSku: string;
  let archivedProductId: string;
  let archivedVariantId: string;
  let archivedSku: string;

  async function cleanupCarts() {
    const customers = await prisma.profile.findMany({
      where: { email: { in: [customerAEmail, customerBEmail, adminEmail] } },
      include: { cart: true },
    });
    for (const customer of customers) {
      if (customer.cart) {
        await prisma.cartItem.deleteMany({ where: { cartId: customer.cart.id } });
      }
    }
  }

  beforeAll(async () => {
    rateLimiter.reset();

    const supabase = createSupabaseUserClient();

    // 1. Authenticate Customer A (Clara)
    const { data: authA, error: errA } = await supabase.auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    if (errA || !authA.session) {
      throw new Error(`Failed to sign in Customer A: ${errA?.message}`);
    }
    customerAToken = authA.session.access_token;

    // 2. Authenticate Customer B (James)
    const { data: authB, error: errB } = await supabase.auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    if (errB || !authB.session) {
      throw new Error(`Failed to sign in Customer B: ${errB?.message}`);
    }
    customerBToken = authB.session.access_token;

    // 3. Authenticate Admin
    const { data: authAdmin, error: errAdmin } = await supabase.auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdmin || !authAdmin.session) {
      throw new Error(`Failed to sign in Admin: ${errAdmin?.message}`);
    }
    adminToken = authAdmin.session.access_token;

    // 4. Find an active product with plenty of stock
    const variant = await prisma.productVariant.findFirst({
      where: { active: true, stockQuantity: { gte: 10 } },
    });
    if (!variant) {
      throw new Error('No active product variant with sufficient stock found in database');
    }
    standardVariantId = variant.id;
    standardVariantPriceInCents = variant.priceInCents;

    // 5. Create isolated test variants: Low stock (3), Inactive (active: false), and Archived Product
    const activeProduct = await prisma.product.findFirst({
      where: { status: 'ACTIVE' },
    });
    if (!activeProduct) {
      throw new Error('No active product found for creating test variants');
    }

    const timestamp = Date.now();
    lowStockSku = `DA-TEST-LOW-${timestamp}`;
    const lowStockVariant = await prisma.productVariant.create({
      data: {
        productId: activeProduct.id,
        size: '39R',
        color: `LowStock ${timestamp}`,
        sku: lowStockSku,
        priceInCents: 140000,
        stockQuantity: 3,
        active: true,
      },
    });
    lowStockVariantId = lowStockVariant.id;

    inactiveSku = `DA-TEST-INACT-${timestamp}`;
    const inactiveVariant = await prisma.productVariant.create({
      data: {
        productId: activeProduct.id,
        size: '41R',
        color: `Inactive ${timestamp}`,
        sku: inactiveSku,
        priceInCents: 155000,
        stockQuantity: 10,
        active: false,
      },
    });
    inactiveVariantId = inactiveVariant.id;

    // Create an archived product with a variant to test problem line detection
    const anyCategory = await prisma.category.findFirst();
    if (!anyCategory) throw new Error('No category found');

    const archivedProduct = await prisma.product.create({
      data: {
        categoryId: anyCategory.id,
        name: `Archived Test Tuxedo ${timestamp}`,
        slug: `da-test-archived-${timestamp}`,
        description: 'Archived product for cart problem line testing',
        fabric: 'Barathea Wool',
        fit: 'Slim Fit',
        status: ProductStatus.ARCHIVED,
      },
    });
    archivedProductId = archivedProduct.id;

    archivedSku = `DA-TEST-ARCH-${timestamp}`;
    const archivedVariant = await prisma.productVariant.create({
      data: {
        productId: archivedProduct.id,
        size: '40R',
        color: 'Archived Obsidian',
        sku: archivedSku,
        priceInCents: 165000,
        stockQuantity: 10,
        active: true,
      },
    });
    archivedVariantId = archivedVariant.id;

    await cleanupCarts();
  });

  afterAll(async () => {
    await cleanupCarts();

    // Clean up temporary test variants and products
    await prisma.productVariant.deleteMany({
      where: { sku: { in: [lowStockSku, inactiveSku, archivedSku] } },
    });
    if (archivedProductId) {
      await prisma.product.deleteMany({
        where: { id: archivedProductId },
      });
    }
  });

  describe('1. Authentication & Security Isolation', () => {
    it('rejects unauthenticated requests with 401 Unauthorized', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart');
      const res = await getCart(req, {} as never);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('rejects cross-user PATCH /api/cart/items/[id] with 403 Forbidden', async () => {
      // Customer A adds item to cart
      const addReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 1,
        }),
      });
      const addRes = await addToCart(addReq, {} as never);
      expect(addRes.status).toBe(201);
      const addData = await addRes.json();
      const customerAItemId = addData.data.items[0].id;

      // Customer B attempts to update Customer A's cart item
      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${customerAItemId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 2 }),
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: customerAItemId }),
      });
      expect(patchRes.status).toBe(403);

      const patchBody = await patchRes.json();
      expect(patchBody.success).toBe(false);
      expect(patchBody.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    it('rejects cross-user DELETE /api/cart/items/[id] with 403 Forbidden', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const customerAItemId = cartData.data.items[0].id;

      // Customer B attempts to delete Customer A's cart item
      const delReq = new NextRequest(`http://localhost:3000/api/cart/items/${customerAItemId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerBToken}` },
      });
      const delRes = await deleteCartItem(delReq, {
        params: Promise.resolve({ id: customerAItemId }),
      });
      expect(delRes.status).toBe(403);

      const delBody = await delRes.json();
      expect(delBody.success).toBe(false);
      expect(delBody.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    it('rejects ADMIN from updating another user cart item with 403 Forbidden (owner-only, no admin override)', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const customerAItemId = cartData.data.items[0].id;

      // ADMIN attempts to PATCH Customer A's cart item
      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${customerAItemId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 2 }),
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: customerAItemId }),
      });
      expect(patchRes.status).toBe(403);

      const patchBody = await patchRes.json();
      expect(patchBody.success).toBe(false);
      expect(patchBody.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(patchBody.error.message).toContain('Only the cart owner');
    });

    it('rejects ADMIN from deleting another user cart item with 403 Forbidden (owner-only, no admin override)', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const customerAItemId = cartData.data.items[0].id;

      // ADMIN attempts to DELETE Customer A's cart item
      const delReq = new NextRequest(`http://localhost:3000/api/cart/items/${customerAItemId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const delRes = await deleteCartItem(delReq, {
        params: Promise.resolve({ id: customerAItemId }),
      });
      expect(delRes.status).toBe(403);

      const delBody = await delRes.json();
      expect(delBody.success).toBe(false);
      expect(delBody.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(delBody.error.message).toContain('Only the cart owner');
    });
  });

  describe('2. Server-Calculated Pricing & Line Totals', () => {
    it('computes line totals and cart subtotal strictly from DB prices, ignoring client input', async () => {
      const clearReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      await clearCart(clearReq, {} as never);

      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 2,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);

      const item = body.data.items.find((i: any) => i.productVariant.id === standardVariantId);
      expect(item).toBeDefined();
      expect(item.quantity).toBe(2);
      expect(item.unitPriceInCents).toBe(standardVariantPriceInCents);
      expect(item.subtotalInCents).toBe(standardVariantPriceInCents * 2);
      expect(body.data.subtotalInCents).toBe(standardVariantPriceInCents * 2);
    });

    it('rejects client-supplied price tampering fields with 422 Unprocessable Entity', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 1,
          priceInCents: 100, // Attacker attempting to override price
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });

  describe('3. Stock Validation & Over-stock Handling', () => {
    it('rejects adding item quantity that exceeds available inventory stock with 400 Bad Request', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: lowStockVariantId,
          quantity: 4,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.BAD_REQUEST);
      expect(body.error.message).toContain('Insufficient inventory');
    });

    it('rejects cumulative additions exceeding available stock with 400 Bad Request', async () => {
      // Add 2 of lowStockVariant (available stock = 3)
      const firstAdd = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: lowStockVariantId,
          quantity: 2,
        }),
      });
      const firstRes = await addToCart(firstAdd, {} as never);
      expect(firstRes.status).toBe(201);

      // Now attempt to add 2 more (2 + 2 = 4 > 3 available)
      const secondAdd = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: lowStockVariantId,
          quantity: 2,
        }),
      });
      const secondRes = await addToCart(secondAdd, {} as never);
      expect(secondRes.status).toBe(400);

      const secondBody = await secondRes.json();
      expect(secondBody.error.code).toBe(ErrorCode.BAD_REQUEST);
      expect(secondBody.error.message).toContain('Insufficient inventory');
    });

    it('rejects updating item quantity beyond available stock with 400 Bad Request', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const lowStockCartItem = cartData.data.items.find(
        (i: any) => i.productVariant.id === lowStockVariantId
      );
      expect(lowStockCartItem).toBeDefined();

      // Attempt to PATCH quantity to 4 (stock is 3, max line cap is 5)
      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${lowStockCartItem.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 4 }),
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: lowStockCartItem.id }),
      });
      expect(patchRes.status).toBe(400);

      const patchBody = await patchRes.json();
      expect(patchBody.error.code).toBe(ErrorCode.BAD_REQUEST);
      expect(patchBody.error.message).toContain('Insufficient inventory');
    });
  });

  describe('4. Variant & Catalog Status Validation', () => {
    it('rejects adding an inactive variant (active: false) with 404 Not Found', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: inactiveVariantId,
          quantity: 1,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.NOT_FOUND);
      expect(body.error.message).toContain('Suit variant not found');
    });

    it('rejects non-existent product variant UUID with 404 Not Found', async () => {
      const nonExistentUuid = '00000000-0000-4000-8000-000000000000';
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: nonExistentUuid,
          quantity: 1,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.NOT_FOUND);
    });

    it('rejects adding variant belonging to an ARCHIVED product with 404 Not Found', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: archivedVariantId,
          quantity: 1,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.NOT_FOUND);
    });
  });

  describe('5. Quantity Boundary & Caps Validation', () => {
    it('rejects zero quantity on POST /api/cart with 422 Unprocessable Entity', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 0,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects negative quantity on POST /api/cart with 422 Unprocessable Entity', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: -2,
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects single-item quantity exceeding lowered per-line cap of 5 on POST /api/cart with 422', async () => {
      const req = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 6, // Exceeds lowered cap of 5
        }),
      });

      const res = await addToCart(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.details?.[0]?.message).toContain('Maximum 5 items');
    });

    it('rejects PATCH quantity exceeding lowered per-line cap of 5 with 422', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const itemId = cartData.data.items[0].id;

      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${itemId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 6 }), // Exceeds cap of 5
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: itemId }),
      });
      expect(patchRes.status).toBe(422);

      const body = await patchRes.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.details?.[0]?.message).toContain('Maximum 5 items');
    });

    it('rejects negative quantity on PATCH /api/cart/items/[id] with 422 Unprocessable Entity', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const itemId = cartData.data.items[0].id;

      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${itemId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: -1 }),
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: itemId }),
      });
      expect(patchRes.status).toBe(422);

      const body = await patchRes.json();
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('setting quantity to 0 via PATCH removes the item from the cart', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const lowStockItem = cartData.data.items.find(
        (i: any) => i.productVariant.id === lowStockVariantId
      );
      expect(lowStockItem).toBeDefined();

      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${lowStockItem.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 0 }),
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: lowStockItem.id }),
      });
      expect(patchRes.status).toBe(200);

      const updatedCart = await patchRes.json();
      const foundDeleted = updatedCart.data.items.find((i: any) => i.id === lowStockItem.id);
      expect(foundDeleted).toBeUndefined();
    });

    it('enforces cap of 10 distinct lines per cart and rejects extras with a validation error', async () => {
      // Clear Customer A's cart
      const clearReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      await clearCart(clearReq, {} as never);

      // Fetch Customer A's cart id
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;

      // Fetch 11 distinct active product variants
      const variants = await prisma.productVariant.findMany({
        where: {
          active: true,
          product: { status: ProductStatus.ACTIVE },
          stockQuantity: { gte: 2 },
        },
        take: 11,
      });

      expect(variants.length).toBeGreaterThanOrEqual(11);

      // Populate exactly 10 distinct items in DB
      for (let i = 0; i < MAX_DISTINCT_CART_ITEMS; i++) {
        await prisma.cartItem.create({
          data: {
            cartId,
            productVariantId: variants[i].id,
            quantity: 1,
          },
        });
      }

      // Verify cart has exactly 10 distinct lines
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      expect(cartData.data.items).toHaveLength(10);

      // Attempt to add 11th distinct item via API -> must be rejected with 422 ValidationError
      const excessReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: variants[10].id,
          quantity: 1,
        }),
      });
      const excessRes = await addToCart(excessReq, {} as never);
      expect(excessRes.status).toBe(422);

      const excessBody = await excessRes.json();
      expect(excessBody.success).toBe(false);
      expect(excessBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(excessBody.error.message || excessBody.error.details?.[0]?.message).toContain('10 distinct');
    });
  });

  describe('6. Problem Line Item Status Flagging & Subtotal Exclusion', () => {
    it('flags problem lines (OK, UNAVAILABLE, INSUFFICIENT_STOCK) and excludes non-OK lines from subtotal', async () => {
      // Clear Customer A's cart
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;
      await prisma.cartItem.deleteMany({ where: { cartId } });

      // 1. Line 1: OK (active variant, active product, quantity <= stock)
      await prisma.cartItem.create({
        data: {
          cartId,
          productVariantId: standardVariantId,
          quantity: 2,
        },
      });

      // 2. Line 2: INSUFFICIENT_STOCK (lowStockVariant has stock 3, we put quantity 5 in cart)
      await prisma.cartItem.create({
        data: {
          cartId,
          productVariantId: lowStockVariantId,
          quantity: 5,
        },
      });

      // 3. Line 3: UNAVAILABLE (inactive variant)
      await prisma.cartItem.create({
        data: {
          cartId,
          productVariantId: inactiveVariantId,
          quantity: 1,
        },
      });

      // 4. Line 4: UNAVAILABLE (archived product)
      await prisma.cartItem.create({
        data: {
          cartId,
          productVariantId: archivedVariantId,
          quantity: 1,
        },
      });

      // Fetch cart via GET /api/cart
      const req = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const res = await getCart(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);

      // All 4 problem lines are returned, NOT hidden
      expect(body.data.items).toHaveLength(4);

      const okLine = body.data.items.find((i: any) => i.productVariant.id === standardVariantId);
      expect(okLine).toBeDefined();
      expect(okLine.status).toBe('OK');
      expect(okLine.subtotalInCents).toBe(standardVariantPriceInCents * 2);

      const stockLine = body.data.items.find((i: any) => i.productVariant.id === lowStockVariantId);
      expect(stockLine).toBeDefined();
      expect(stockLine.status).toBe('INSUFFICIENT_STOCK');

      const inactiveLine = body.data.items.find((i: any) => i.productVariant.id === inactiveVariantId);
      expect(inactiveLine).toBeDefined();
      expect(inactiveLine.status).toBe('UNAVAILABLE');

      const archivedLine = body.data.items.find((i: any) => i.productVariant.id === archivedVariantId);
      expect(archivedLine).toBeDefined();
      expect(archivedLine.status).toBe('UNAVAILABLE');

      // Crucial requirement: Subtotal strictly equals ONLY the OK line total; non-OK lines are excluded!
      expect(body.data.subtotalInCents).toBe(standardVariantPriceInCents * 2);
    });
  });

  describe('7. Concurrency & Atomic Upsert Validation', () => {
    it('handles two concurrent POST /api/cart requests for same variant with no 500, no duplicate lines, and caps hold', async () => {
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;
      await prisma.cartItem.deleteMany({ where: { cartId } });

      // Prepare two concurrent requests adding 2 units of standardVariant (cap is 5, stock >= 10)
      const makeReq = () =>
        new NextRequest('http://localhost:3000/api/cart', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            productVariantId: standardVariantId,
            quantity: 2,
          }),
        });

      const [res1, res2] = await Promise.all([
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
      ]);

      // Neither request should return a 500 Internal Server Error
      expect(res1.status).not.toBe(500);
      expect(res2.status).not.toBe(500);

      // Verify cart state
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();

      // No duplicate lines in the cart
      const matchingItems = cartData.data.items.filter(
        (i: any) => i.productVariant.id === standardVariantId
      );
      expect(matchingItems).toHaveLength(1);

      // The quantity accumulated is 4 <= 5 (cap holds)
      expect(matchingItems[0].quantity).toBe(4);
      expect(matchingItems[0].quantity).toBeLessThanOrEqual(MAX_LINE_ITEM_QUANTITY);
    });

    it('handles concurrent requests exceeding per-line cap without 500 error, keeping cap intact', async () => {
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;
      await prisma.cartItem.deleteMany({ where: { cartId } });

      // Two concurrent requests adding 3 units each (total 6 exceeds cap of 5)
      const makeReq = () =>
        new NextRequest('http://localhost:3000/api/cart', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            productVariantId: standardVariantId,
            quantity: 3,
          }),
        });

      const [res1, res2] = await Promise.all([
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
      ]);

      // Neither request may fail with 500
      expect(res1.status).not.toBe(500);
      expect(res2.status).not.toBe(500);

      // Exactly one should succeed (201) and one should be rejected by cap guard (400)
      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toEqual([201, 400]);

      // Check cart: cap of 5 strictly holds and no duplicate lines
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();

      const matchingItems = cartData.data.items.filter(
        (i: any) => i.productVariant.id === standardVariantId
      );
      expect(matchingItems).toHaveLength(1);
      expect(matchingItems[0].quantity).toBe(3);
      expect(matchingItems[0].quantity).toBeLessThanOrEqual(MAX_LINE_ITEM_QUANTITY);
    });

    it('handles two concurrent requests adding different new variants to a 9-line cart, allowing exactly one 201 and one 422', async () => {
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;
      await prisma.cartItem.deleteMany({ where: { cartId } });

      // Fetch 11 distinct active product variants
      const variants = await prisma.productVariant.findMany({
        where: {
          active: true,
          product: { status: ProductStatus.ACTIVE },
          stockQuantity: { gte: 2 },
        },
        take: 11,
      });
      expect(variants.length).toBeGreaterThanOrEqual(11);

      // Pre-populate cart with exactly 9 distinct lines
      for (let i = 0; i < 9; i++) {
        await prisma.cartItem.create({
          data: {
            cartId,
            productVariantId: variants[i].id,
            quantity: 1,
          },
        });
      }

      // Verify cart has exactly 9 lines before concurrent additions
      const initialCount = await prisma.cartItem.count({ where: { cartId } });
      expect(initialCount).toBe(9);

      // Launch two concurrent requests attempting to add 2 different new variants (index 9 and 10)
      const makeReq = (variantId: string) =>
        new NextRequest('http://localhost:3000/api/cart', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            productVariantId: variantId,
            quantity: 1,
          }),
        });

      const [res1, res2] = await Promise.all([
        addToCart(makeReq(variants[9].id), {} as never),
        addToCart(makeReq(variants[10].id), {} as never),
      ]);

      // Exactly one must succeed (201) and the other must get a 422
      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toEqual([201, 422]);

      // Verify the 422 response body
      const failedRes = res1.status === 422 ? res1 : res2;
      const failedBody = await failedRes.json();
      expect(failedBody.success).toBe(false);
      expect(failedBody.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(failedBody.error.message || failedBody.error.details?.[0]?.message).toContain('10 distinct');

      // Verify final cart state: cart now has exactly 10 distinct lines
      const finalCount = await prisma.cartItem.count({ where: { cartId } });
      expect(finalCount).toBe(10);
    });

    it('guarantees 5 concurrent adds of the same variant never push the quantity above 5', async () => {
      const customer = await prisma.profile.findUnique({
        where: { email: customerAEmail },
        include: { cart: true },
      });
      const cartId = customer!.cart!.id;
      await prisma.cartItem.deleteMany({ where: { cartId } });

      // Launch 5 concurrent requests adding units of the standard variant
      // Each requests quantity 2 (total 10 requested, which would exceed cap of 5)
      const makeReq = () =>
        new NextRequest('http://localhost:3000/api/cart', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${customerAToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            productVariantId: standardVariantId,
            quantity: 2,
          }),
        });

      const responses = await Promise.all([
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
        addToCart(makeReq(), {} as never),
      ]);

      // Verify no internal server errors occurred
      for (const res of responses) {
        expect(res.status).not.toBe(500);
        expect([201, 400]).toContain(res.status);
      }

      // Check final cart: quantity must never be pushed above 5
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();

      const matchingItems = cartData.data.items.filter(
        (i: any) => i.productVariant.id === standardVariantId
      );
      expect(matchingItems).toHaveLength(1);
      expect(matchingItems[0].quantity).toBeLessThanOrEqual(5);
      expect(matchingItems[0].quantity).toBeLessThanOrEqual(MAX_LINE_ITEM_QUANTITY);
      expect(matchingItems[0].quantity).toBe(4);

      // Exactly 2 succeeded (2 * 2 = 4) and 3 failed with 400
      const statusCounts = responses.reduce((acc: Record<number, number>, res) => {
        acc[res.status] = (acc[res.status] || 0) + 1;
        return acc;
      }, {});
      expect(statusCounts[201]).toBe(2);
      expect(statusCounts[400]).toBe(3);
    });
  });

  describe('8. Cart Lifecycle & Management', () => {
    it('updates item quantity to a valid amount within stock and cap (4 <= 5)', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const standardItem = cartData.data.items.find(
        (i: any) => i.productVariant.id === standardVariantId
      );
      expect(standardItem).toBeDefined();

      const patchReq = new NextRequest(`http://localhost:3000/api/cart/items/${standardItem.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quantity: 4 }), // <= 5
      });
      const patchRes = await updateCartItem(patchReq, {
        params: Promise.resolve({ id: standardItem.id }),
      });
      expect(patchRes.status).toBe(200);

      const body = await patchRes.json();
      const updated = body.data.items.find((i: any) => i.id === standardItem.id);
      expect(updated.quantity).toBe(4);
      expect(updated.subtotalInCents).toBe(standardVariantPriceInCents * 4);
    });

    it('removes an individual item using DELETE /api/cart/items/[id]', async () => {
      const getReq = new NextRequest('http://localhost:3000/api/cart', {
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const getRes = await getCart(getReq, {} as never);
      const cartData = await getRes.json();
      const standardItem = cartData.data.items.find(
        (i: any) => i.productVariant.id === standardVariantId
      );
      expect(standardItem).toBeDefined();

      const delReq = new NextRequest(`http://localhost:3000/api/cart/items/${standardItem.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const delRes = await deleteCartItem(delReq, {
        params: Promise.resolve({ id: standardItem.id }),
      });
      expect(delRes.status).toBe(200);

      const body = await delRes.json();
      const foundDeleted = body.data.items.find((i: any) => i.id === standardItem.id);
      expect(foundDeleted).toBeUndefined();
    });

    it('clears all items in the cart using DELETE /api/cart', async () => {
      const addReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          productVariantId: standardVariantId,
          quantity: 1,
        }),
      });
      const addRes = await addToCart(addReq, {} as never);
      expect(addRes.status).toBe(201);

      const clearReq = new NextRequest('http://localhost:3000/api/cart', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${customerAToken}` },
      });
      const clearRes = await clearCart(clearReq, {} as never);
      expect(clearRes.status).toBe(200);

      const clearBody = await clearRes.json();
      expect(clearBody.data.items).toHaveLength(0);
      expect(clearBody.data.itemCount).toBe(0);
      expect(clearBody.data.subtotalInCents).toBe(0);
    });
  });
});
