import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { ProductStatus } from '@prisma/client';
import { ErrorCode } from '@/lib/errors/error-codes';

// Public routes
import { GET as getCategories } from '@/app/api/categories/route';
import { GET as getProducts } from '@/app/api/products/route';
import { GET as getProductBySlug } from '@/app/api/products/[slug]/route';

// Admin routes
import { POST as createAdminProduct, GET as listAdminProducts } from '@/app/api/admin/products/route';
import { GET as getAdminProduct, PATCH as updateAdminProduct, DELETE as deleteAdminProduct } from '@/app/api/admin/products/[id]/route';
import { POST as archiveAdminProduct } from '@/app/api/admin/products/[id]/archive/route';
import { POST as createAdminVariant, GET as listAdminVariants } from '@/app/api/admin/products/[id]/variants/route';
import { GET as getAdminVariant, PATCH as updateAdminVariant } from '@/app/api/admin/variants/[id]/route';
import { POST as adjustAdminStock } from '@/app/api/admin/variants/[id]/stock/route';

describe('Catalog API Routes & Services (Public & Admin)', () => {
  const customerEmail = 'james.harrington@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || 'DonAtelierAdmin2026!Secure';

  let customerToken: string;
  let adminToken: string;
  let testCategoryId: string;

  const createdProductIds: string[] = [];
  const createdVariantIds: string[] = [];

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Authenticate Customer
    const { data: customerAuth, error: custErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerEmail,
      password: customerPassword,
    });
    if (custErr || !customerAuth.session) {
      throw new Error(`Customer login failed in catalog test setup: ${custErr?.message}`);
    }
    customerToken = customerAuth.session.access_token;

    // 2. Authenticate Admin
    const { data: adminAuth, error: adminErr } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (adminErr || !adminAuth.session) {
      throw new Error(`Admin login failed in catalog test setup: ${adminErr?.message}`);
    }
    adminToken = adminAuth.session.access_token;

    // 3. Find test category
    const category = await prisma.category.findFirst();
    if (!category) throw new Error('No categories found in test database');
    testCategoryId = category.id;
  });

  afterAll(async () => {
    // Cleanup any test products/variants created during tests
    for (const variantId of createdVariantIds) {
      await prisma.productVariant.deleteMany({ where: { id: variantId } }).catch(() => { });
    }
    for (const productId of createdProductIds) {
      await prisma.productVariant.deleteMany({ where: { productId } }).catch(() => { });
      await prisma.productImage.deleteMany({ where: { productId } }).catch(() => { });
      await prisma.product.deleteMany({ where: { id: productId } }).catch(() => { });
    }
  });

  // ===========================================================================
  // PUBLIC CATALOG SUITE
  // ===========================================================================
  describe('PUBLIC CATALOG API', () => {
    describe('GET /api/categories', () => {
      it('returns all luxury categories with active product counts', async () => {
        const req = new NextRequest('http://localhost:3000/api/categories');
        const res = await getCategories(req, {} as never);
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data)).toBe(true);
        expect(body.data.length).toBeGreaterThanOrEqual(5);

        const slugs = body.data.map((c: { slug: string }) => c.slug);
        expect(slugs).toContain('tuxedos-black-tie');
        expect(slugs).toContain('business-classic');
      });
    });

    describe('GET /api/products', () => {
      it('conceals exact stock counts on public variants (returns inStock and lowStock booleans)', async () => {
        const req = new NextRequest('http://localhost:3000/api/products?page=1&limit=5');
        const res = await getProducts(req, {} as never);
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.length).toBeGreaterThan(0);

        for (const product of body.data) {
          // Product-level stock flags
          expect(typeof product.inStock).toBe('boolean');
          expect(typeof product.lowStock).toBe('boolean');

          // Variant-level stock concealment
          for (const variant of product.variants) {
            expect(variant.stockQuantity).toBeUndefined(); // NEVER leak exact count
            expect(typeof variant.inStock).toBe('boolean');
            expect(typeof variant.lowStock).toBe('boolean');
            expect(typeof variant.isLowStock).toBe('boolean');
          }
        }
      });

      it('filters suits by category slug', async () => {
        const req = new NextRequest('http://localhost:3000/api/products?categorySlug=tuxedos-black-tie');
        const res = await getProducts(req, {} as never);
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.length).toBeGreaterThanOrEqual(1);
        for (const item of body.data) {
          expect(item.category.slug).toBe('tuxedos-black-tie');
        }
      });

      it('filters suits by size, color, fabric, and price range', async () => {
        // Filter by size
        const reqSize = new NextRequest('http://localhost:3000/api/products?size=40R');
        const resSize = await getProducts(reqSize, {} as never);
        expect(resSize.status).toBe(200);
        const bodySize = await resSize.json();
        expect(bodySize.success).toBe(true);

        // Filter by fabric
        const reqFabric = new NextRequest('http://localhost:3000/api/products?fabric=Merino');
        const resFabric = await getProducts(reqFabric, {} as never);
        expect(resFabric.status).toBe(200);
        const bodyFabric = await resFabric.json();
        expect(bodyFabric.success).toBe(true);
        for (const item of bodyFabric.data) {
          expect(item.fabric.toLowerCase()).toContain('merino');
        }

        // Filter by price range ($1,500 - $3,000)
        const reqPrice = new NextRequest('http://localhost:3000/api/products?minPrice=150000&maxPrice=300000');
        const resPrice = await getProducts(reqPrice, {} as never);
        expect(resPrice.status).toBe(200);
        const bodyPrice = await resPrice.json();
        expect(bodyPrice.success).toBe(true);
      });

      it('filters suits by text search across name, description, and fabric', async () => {
        const req = new NextRequest('http://localhost:3000/api/products?search=Tuxedo');
        const res = await getProducts(req, {} as never);
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.length).toBeGreaterThanOrEqual(1);
        for (const item of body.data) {
          const match =
            item.name.toLowerCase().includes('tuxedo') ||
            item.description.toLowerCase().includes('tuxedo') ||
            item.fabric.toLowerCase().includes('tuxedo');
          expect(match).toBe(true);
        }
      });

      it('enforces capped page size limit (max 50)', async () => {
        // Requesting limit=51 must fail validation
        const reqOversized = new NextRequest('http://localhost:3000/api/products?page=1&limit=51');
        const resOversized = await getProducts(reqOversized, {} as never);
        expect(resOversized.status).toBe(422);

        const bodyOversized = await resOversized.json();
        expect(bodyOversized.error.code).toBe(ErrorCode.VALIDATION_ERROR);
        expect(bodyOversized.error.details.some((d: { message: string }) => d.message.includes('50'))).toBe(true);

        // Limit within bounds (e.g. 5) succeeds
        const reqValid = new NextRequest('http://localhost:3000/api/products?page=1&limit=5');
        const resValid = await getProducts(reqValid, {} as never);
        expect(resValid.status).toBe(200);
        const bodyValid = await resValid.json();
        expect(bodyValid.data.length).toBeLessThanOrEqual(5);
      });

      it('allows whitelisted sort fields and rejects un-whitelisted sort fields (no dynamic column injection)', async () => {
        // 1. Whitelisted sort fields succeed
        const reqNameAsc = new NextRequest('http://localhost:3000/api/products?sortBy=name&sortOrder=asc');
        const resNameAsc = await getProducts(reqNameAsc, {} as never);
        expect(resNameAsc.status).toBe(200);

        const reqPriceDesc = new NextRequest('http://localhost:3000/api/products?sortBy=price&sortOrder=desc');
        const resPriceDesc = await getProducts(reqPriceDesc, {} as never);
        expect(resPriceDesc.status).toBe(200);

        // 2. Unwhitelisted / malicious sort field rejected with 422
        const reqMalicious = new NextRequest('http://localhost:3000/api/products?sortBy=injected_column;DROP TABLE');
        const resMalicious = await getProducts(reqMalicious, {} as never);
        expect(resMalicious.status).toBe(422);

        const bodyMalicious = await resMalicious.json();
        expect(bodyMalicious.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      });

      it('rejects extra unknown query parameters with 422 ValidationError', async () => {
        const req = new NextRequest('http://localhost:3000/api/products?extraInjectedParam=attack');
        const res = await getProducts(req, {} as never);
        expect(res.status).toBe(422);

        const body = await res.json();
        expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      });
    });

    describe('GET /api/products/[slug]', () => {
      it('returns full suit details and active variants with concealed stock quantity', async () => {
        const req = new NextRequest('http://localhost:3000/api/products/the-mayfair-peak-lapel-tuxedo');
        const res = await getProductBySlug(req, { params: Promise.resolve({ slug: 'the-mayfair-peak-lapel-tuxedo' }) });
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.slug).toBe('the-mayfair-peak-lapel-tuxedo');
        expect(body.data.brand).toBe("Don's Atelier");

        for (const variant of body.data.variants) {
          expect(variant.stockQuantity).toBeUndefined(); // Concealed
          expect(typeof variant.inStock).toBe('boolean');
          expect(typeof variant.lowStock).toBe('boolean');
        }
      });

      it('returns 404 NotFoundError for non-existent suit', async () => {
        const req = new NextRequest('http://localhost:3000/api/products/non-existent-suit-xyz');
        const res = await getProductBySlug(req, { params: Promise.resolve({ slug: 'non-existent-suit-xyz' }) });
        expect(res.status).toBe(404);

        const body = await res.json();
        expect(body.error.code).toBe(ErrorCode.NOT_FOUND);
      });
    });
  });

  // ===========================================================================
  // ADMIN CATALOG SUITE: ROLE GUARDS (NON-ADMIN REJECTION)
  // ===========================================================================
  describe('ADMIN CATALOG API: Role Guard Enforcement (Non-Admin Rejection)', () => {
    it('rejects unauthenticated requests to admin product routes with 401 Unauthorized', async () => {
      const unauthReq = new NextRequest('http://localhost:3000/api/admin/products', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          categoryId: testCategoryId,
          name: 'Unauthorized Suit',
          description: 'A suit created without authentication.',
          fabric: 'Wool',
          fit: 'Slim Fit',
        }),
      });

      const res = await createAdminProduct(unauthReq, {} as never);
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('rejects CUSTOMER role from creating, updating, or archiving products with 403 Forbidden', async () => {
      // 1. Customer creates product -> 403
      const createReq = new NextRequest('http://localhost:3000/api/admin/products', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          categoryId: testCategoryId,
          name: 'Customer Infiltrated Suit',
          description: 'A suit created by customer.',
          fabric: 'Wool',
          fit: 'Slim Fit',
        }),
      });
      const createRes = await createAdminProduct(createReq, {} as never);
      expect(createRes.status).toBe(403);
      const createBody = await createRes.json();
      expect(createBody.error.code).toBe(ErrorCode.FORBIDDEN);

      // 2. Customer updates product -> 403
      const fakeId = '00000000-0000-0000-0000-000000000001';
      const updateReq = new NextRequest(`http://localhost:3000/api/admin/products/${fakeId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({ name: 'Hacked Name' }),
      });
      const updateRes = await updateAdminProduct(updateReq, { params: Promise.resolve({ id: fakeId }) });
      expect(updateRes.status).toBe(403);

      // 3. Customer archives product -> 403
      const archiveReq = new NextRequest(`http://localhost:3000/api/admin/products/${fakeId}/archive`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${customerToken}` },
      });
      const archiveRes = await archiveAdminProduct(archiveReq, { params: Promise.resolve({ id: fakeId }) });
      expect(archiveRes.status).toBe(403);
    });

    it('rejects CUSTOMER role from creating variants or adjusting stock with 403 Forbidden', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000001';

      // 1. Customer creates variant -> 403
      const createVarReq = new NextRequest(`http://localhost:3000/api/admin/products/${fakeId}/variants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({
          size: '42R',
          color: 'Charcoal',
          sku: 'HACK-SKU-001',
          priceInCents: 100000,
        }),
      });
      const createVarRes = await createAdminVariant(createVarReq, { params: Promise.resolve({ id: fakeId }) });
      expect(createVarRes.status).toBe(403);

      // 2. Customer adjusts stock -> 403
      const stockReq = new NextRequest(`http://localhost:3000/api/admin/variants/${fakeId}/stock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        },
        body: JSON.stringify({ adjustment: 50 }),
      });
      const stockRes = await adjustAdminStock(stockReq, { params: Promise.resolve({ id: fakeId }) });
      expect(stockRes.status).toBe(403);
    });
  });

  // ===========================================================================
  // ADMIN CATALOG SUITE: FULL CRUD, STOCK ADJUSTMENT & AUDIT LOGGING
  // ===========================================================================
  describe('ADMIN CATALOG API: CRUD, Stock Adjustment, Archival, and Audit Logging', () => {
    let createdProductId: string;
    let createdVariantId: string;
    const uniqueSuffix = Date.now().toString(36);

    it('allows ADMIN to create a new product and records audit log', async () => {
      const createReq = new NextRequest('http://localhost:3000/api/admin/products', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          categoryId: testCategoryId,
          name: `The Kensington Double-Breasted Suit ${uniqueSuffix}`,
          description: 'Meticulously crafted six-button double-breasted suit from pure British flannel.',
          fabric: 'British Flannel Wool',
          fit: 'Classic Tailored Fit',
          status: ProductStatus.ACTIVE,
        }),
      });

      const res = await createAdminProduct(createReq, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.status).toBe(ProductStatus.ACTIVE);
      expect(body.data.brand).toBe("Don's Atelier");

      createdProductId = body.data.id;
      createdProductIds.push(createdProductId);

      // Verify Audit Log in Postgres
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_PRODUCT_CREATED', entityId: createdProductId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog?.action).toBe('ADMIN_PRODUCT_CREATED');
      expect(auditLog?.entity).toBe('Product');
    });

    it('allows ADMIN to update a product and records audit log', async () => {
      const updateReq = new NextRequest(`http://localhost:3000/api/admin/products/${createdProductId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          description: 'Updated flannel composition with hand-stitched horn buttons.',
          fit: 'Modern Slim Fit',
        }),
      });

      const res = await updateAdminProduct(updateReq, { params: Promise.resolve({ id: createdProductId }) });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.fit).toBe('Modern Slim Fit');

      // Verify Audit Log
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_PRODUCT_UPDATED', entityId: createdProductId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog?.action).toBe('ADMIN_PRODUCT_UPDATED');
    });

    it('allows ADMIN to create a variant for the product and records audit log', async () => {
      const sku = `DA-KEN-${uniqueSuffix.toUpperCase()}-38R`;
      const createVarReq = new NextRequest(`http://localhost:3000/api/admin/products/${createdProductId}/variants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          size: '38R',
          color: 'Navy Flannel',
          sku,
          priceInCents: 220000, // $2,200.00
          stockQuantity: 10,
          active: true,
        }),
      });

      const res = await createAdminVariant(createVarReq, { params: Promise.resolve({ id: createdProductId }) });
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBeDefined();
      expect(body.data.stockQuantity).toBe(10);
      expect(body.data.sku).toBe(sku);

      createdVariantId = body.data.id;
      createdVariantIds.push(createdVariantId);

      // Verify Audit Log
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_VARIANT_CREATED', entityId: createdVariantId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog?.action).toBe('ADMIN_VARIANT_CREATED');
    });

    it('allows ADMIN to update a variant and records audit log', async () => {
      const updateVarReq = new NextRequest(`http://localhost:3000/api/admin/variants/${createdVariantId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          priceInCents: 235000, // $2,350.00
        }),
      });

      const res = await updateAdminVariant(updateVarReq, { params: Promise.resolve({ id: createdVariantId }) });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.priceInCents).toBe(235000);

      // Verify Audit Log
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_VARIANT_UPDATED', entityId: createdVariantId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog?.action).toBe('ADMIN_VARIANT_UPDATED');
    });

    it('allows ADMIN to adjust stock (delta and absolute) and prevents negative stock', async () => {
      // 1. Delta adjustment: +5 (10 -> 15)
      const deltaReq = new NextRequest(`http://localhost:3000/api/admin/variants/${createdVariantId}/stock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          adjustment: 5,
          reason: 'Received new stock delivery from Savile Row workshop',
        }),
      });
      const deltaRes = await adjustAdminStock(deltaReq, { params: Promise.resolve({ id: createdVariantId }) });
      expect(deltaRes.status).toBe(200);

      const deltaBody = await deltaRes.json();
      expect(deltaBody.success).toBe(true);
      expect(deltaBody.data.previousStock).toBe(10);
      expect(deltaBody.data.newStock).toBe(15);
      expect(deltaBody.data.variant.stockQuantity).toBe(15);

      // Verify Audit Log for stock adjustment
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_STOCK_ADJUSTED', entityId: createdVariantId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();
      expect(auditLog?.action).toBe('ADMIN_STOCK_ADJUSTED');

      // 2. Absolute stock set: set to 30
      const absReq = new NextRequest(`http://localhost:3000/api/admin/variants/${createdVariantId}/stock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          stockQuantity: 30,
          reason: 'Annual inventory audit count adjustment',
        }),
      });
      const absRes = await adjustAdminStock(absReq, { params: Promise.resolve({ id: createdVariantId }) });
      expect(absRes.status).toBe(200);
      const absBody = await absRes.json();
      expect(absBody.data.newStock).toBe(30);

      // 3. Rejects adjustment that causes negative stock with 400 BadRequest
      const negReq = new NextRequest(`http://localhost:3000/api/admin/variants/${createdVariantId}/stock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          adjustment: -100,
          reason: 'Inventory write-off test',
        }), // Current stock is 30, -100 would be -70
      });
      const negRes = await adjustAdminStock(negReq, { params: Promise.resolve({ id: createdVariantId }) });
      expect(negRes.status).toBe(400);

      const negBody = await negRes.json();
      expect(negBody.error.code).toBe(ErrorCode.BAD_REQUEST);
      expect(negBody.error.message).toContain('negative inventory');
    });

    it('allows ADMIN to archive a product, hiding it from public catalog while remaining in admin view', async () => {
      // 1. Archive the product via /archive route
      const archiveReq = new NextRequest(`http://localhost:3000/api/admin/products/${createdProductId}/archive`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${adminToken}` },
      });
      const archiveRes = await archiveAdminProduct(archiveReq, { params: Promise.resolve({ id: createdProductId }) });
      expect(archiveRes.status).toBe(200);

      const archiveBody = await archiveRes.json();
      expect(archiveBody.success).toBe(true);
      expect(archiveBody.data.status).toBe(ProductStatus.ARCHIVED);

      // Verify Audit Log
      const auditLog = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_PRODUCT_ARCHIVED', entityId: createdProductId },
        orderBy: { timestamp: 'desc' },
      });
      expect(auditLog).toBeDefined();

      // 2. Verify product is NO LONGER returned in public GET /api/products
      const publicReq = new NextRequest(`http://localhost:3000/api/products?search=${uniqueSuffix}`);
      const publicRes = await getProducts(publicReq, {} as never);
      expect(publicRes.status).toBe(200);
      const publicBody = await publicRes.json();
      const foundInPublic = publicBody.data.some((p: { id: string }) => p.id === createdProductId);
      expect(foundInPublic).toBe(false);

      // 3. Verify public GET /api/products/[slug] returns 404 for archived product
      const publicSlugReq = new NextRequest(`http://localhost:3000/api/products/${archiveBody.data.slug}`);
      const publicSlugRes = await getProductBySlug(publicSlugReq, { params: Promise.resolve({ slug: archiveBody.data.slug }) });
      expect(publicSlugRes.status).toBe(404);

      // 4. Verify admin CAN still view the archived product in GET /api/admin/products/[id]
      const adminViewReq = new NextRequest(`http://localhost:3000/api/admin/products/${createdProductId}`, {
        headers: { 'Authorization': `Bearer ${adminToken}` },
      });
      const adminViewRes = await getAdminProduct(adminViewReq, { params: Promise.resolve({ id: createdProductId }) });
      expect(adminViewRes.status).toBe(200);
      const adminViewBody = await adminViewRes.json();
      expect(adminViewBody.data.status).toBe(ProductStatus.ARCHIVED);
      expect(adminViewBody.data.variants[0].stockQuantity).toBe(30); // Admin sees exact count
    });
  });
});
