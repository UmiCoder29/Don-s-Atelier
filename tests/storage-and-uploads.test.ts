import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import sharp from 'sharp';
import { prisma } from '@/lib/db/prisma';
import { supabaseAdmin, createSupabaseUserClient } from '@/lib/db/supabase';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { STORAGE_BUCKETS, ensureStorageBucketsExist } from '@/lib/storage/buckets';
import {
  validateImageBuffer,
  detectImageMimeType,
  isExecutableOrHostile,
  stripImageMetadata,
  validateImagePixelLimit,
  MAX_PRODUCT_IMAGE_SIZE_BYTES,
  MAX_IMAGE_PIXELS,
} from '@/lib/storage/image-processing';
import {
  createSignedUploadUrl,
  createSignedDownloadUrl,
  DEFAULT_SIGNED_URL_EXPIRY_SECONDS,
} from '@/lib/storage/signed-urls';
import { POST as uploadProductImageRoute } from '@/app/api/admin/products/images/route';
import { POST as uploadProductImageForProductRoute } from '@/app/api/admin/products/[id]/images/route';
import { POST as signedUrlRoute } from '@/app/api/uploads/signed-url/route';
import { GET as getAttachmentRoute } from '@/app/api/custom-orders/[id]/attachments/[attachmentId]/route';
import { POST as initiateUploadRoute } from '@/app/api/uploads/route';
import { POST as createAttachmentRoute } from '@/app/api/custom-orders/[id]/attachments/route';
import { ErrorCode } from '@/lib/errors/error-codes';

describe("Don's Atelier - Supabase Storage & Upload Security Suite", () => {
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
  let adminId: string;

  let testProductId: string;
  let testCustomOrderId: string;
  let testAttachmentId: string;
  const uploadedFilesToCleanup: Array<{ bucket: string; path: string }> = [];

  beforeEach(() => {
    rateLimiter.reset();
  });

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Authenticate test actors
    const { data: authA, error: errA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    if (errA || !authA.session) throw new Error(`Customer A sign in failed: ${errA?.message}`);
    customerAToken = authA.session.access_token;
    customerAId = authA.user.id;

    const { data: authB, error: errB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    if (errB || !authB.session) throw new Error(`Customer B sign in failed: ${errB?.message}`);
    customerBToken = authB.session.access_token;
    customerBId = authB.user.id;

    const { data: authAdmin, error: errAdmin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdmin || !authAdmin.session) throw new Error(`Admin sign in failed: ${errAdmin?.message}`);
    adminToken = authAdmin.session.access_token;
    adminId = authAdmin.user.id;

    // 2. Fetch existing active product for image attachment testing
    const product = await prisma.product.findFirst({
      where: { status: 'ACTIVE' },
      select: { id: true },
    });
    if (!product) throw new Error('No active products found in seed catalog');
    testProductId = product.id;

    // 3. Create a test custom order for Customer A to verify private bucket ownership
    const customOrder = await prisma.customOrder.create({
      data: {
        profileId: customerAId,
        orderNumber: `CO-${Date.now().toString().slice(-6)}`,
        description: 'Bespoke test velvet dinner jacket with silk lapels',
        occasion: 'Black Tie Gala',
        budgetRange: '$2,000 - $3,000',
      },
    });
    testCustomOrderId = customOrder.id;

    // 4. Create an attachment in Customer A's custom order
    const testStoragePath = `custom-orders/${customerAId}/${Date.now()}-fabric-swatch.jpg`;
    const { error: uploadSwatchErr } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(testStoragePath, Buffer.from('swatch dummy file content'), {
        upsert: true,
        contentType: 'image/jpeg',
      });
    if (uploadSwatchErr) {
      throw new Error(`Failed to upload test swatch: ${uploadSwatchErr.message}`);
    }

    uploadedFilesToCleanup.push({
      bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
      path: testStoragePath,
    });

    const attachment = await prisma.customOrderAttachment.create({
      data: {
        customOrderId: testCustomOrderId,
        storagePath: testStoragePath,
        mimeType: 'image/jpeg',
        size: 2048,
        fileName: 'fabric-swatch.jpg',
      },
    });
    testAttachmentId = attachment.id;
  });

  afterAll(async () => {
    // Cleanup test records
    if (testAttachmentId) {
      await prisma.customOrderAttachment.deleteMany({ where: { id: testAttachmentId } });
    }
    if (testCustomOrderId) {
      await prisma.customOrder.deleteMany({ where: { id: testCustomOrderId } });
    }

    // Clean up uploaded test files from Supabase storage
    for (const file of uploadedFilesToCleanup) {
      try {
        await supabaseAdmin.storage.from(file.bucket).remove([file.path]);
      } catch {
        // Ignore cleanup deletion errors
      }
    }
  });

  // ============================================================================
  // CHECK 1: STORAGE BUCKETS CONFIGURATION (Public product-images vs Private custom-order-uploads)
  // ============================================================================
  describe('CHECK 1: Storage Buckets Configuration & Security Profiles', () => {
    it('sets up product-images as public read and custom-order-uploads as private', async () => {
      const setupResult = await ensureStorageBucketsExist(supabaseAdmin);
      expect(setupResult.success).toBe(true);
      expect(setupResult.buckets).toContain(STORAGE_BUCKETS.PRODUCT_IMAGES);
      expect(setupResult.buckets).toContain(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS);

      const { data: buckets, error } = await supabaseAdmin.storage.listBuckets();
      expect(error).toBeNull();
      expect(buckets).toBeDefined();

      const productImagesBucket = buckets!.find((b) => b.name === STORAGE_BUCKETS.PRODUCT_IMAGES);
      expect(productImagesBucket).toBeDefined();
      expect(productImagesBucket!.public).toBe(true); // Public read for suit showcase
      expect(productImagesBucket!.file_size_limit).toBe(10 * 1024 * 1024); // 10MB
      expect(productImagesBucket!.allowed_mime_types).toEqual(
        expect.arrayContaining(['image/jpeg', 'image/png', 'image/webp'])
      );

      const customOrderBucket = buckets!.find((b) => b.name === STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS);
      expect(customOrderBucket).toBeDefined();
      expect(customOrderBucket!.public).toBe(false); // Private bucket: signed URLs only
      expect(customOrderBucket!.file_size_limit).toBe(10 * 1024 * 1024);
      expect(customOrderBucket!.allowed_mime_types).toEqual(
        expect.arrayContaining(['image/jpeg', 'image/png', 'image/webp'])
      );
      expect(customOrderBucket!.allowed_mime_types).not.toContain('application/pdf');
    });

    it('rejects application/pdf on POST /api/uploads with 422 Unprocessable Entity', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'suit-specifications.pdf',
          mimeType: 'application/pdf',
          size: 1024 * 100,
          folder: 'custom-orders',
        }),
      });

      const res = await initiateUploadRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message.toLowerCase()).toContain('validation failed');
    });

    it('rejects application/pdf on POST /api/custom-orders/[id]/attachments with 422 Unprocessable Entity', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'order-document.pdf',
          mimeType: 'application/pdf',
          size: 1024 * 50,
          storagePath: `custom-orders/${customerAId}/test-doc.pdf`,
        }),
      });

      const res = await createAttachmentRoute(req, {
        params: Promise.resolve({ id: testCustomOrderId }),
      });
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });
  });

  // ============================================================================
  // CHECK 2: ACCEPTANCE: REJECT EXECUTABLES & HOSTILE SCRIPTS
  // ============================================================================
  describe('CHECK 2: Executable & Hostile File Rejection (Acceptance)', () => {
    it('rejects Windows PE executable (.exe / MZ header) masquerading as image/jpeg', async () => {
      const peExecutableBuffer = Buffer.concat([
        Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]), // 'MZ' magic bytes
        Buffer.from('This program cannot be run in DOS mode.\r\n$'),
        Buffer.alloc(100, 0x00),
      ]);

      expect(isExecutableOrHostile(peExecutableBuffer)).toBe(true);
      expect(detectImageMimeType(peExecutableBuffer)).toBeNull();

      // Test directly against validation helper
      expect(() =>
        validateImageBuffer(peExecutableBuffer, { declaredMimeType: 'image/jpeg' })
      ).toThrow();

      // Test against admin upload route
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: peExecutableBuffer.toString('base64'),
          mimeType: 'image/jpeg',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toContain('Validation failed');
    });

    it('rejects Linux ELF binary (\\x7fELF) masquerading as image/png', async () => {
      const elfExecutableBuffer = Buffer.concat([
        Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), // '\x7fELF' magic bytes
        Buffer.alloc(200, 0x90),
      ]);

      expect(isExecutableOrHostile(elfExecutableBuffer)).toBe(true);

      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: elfExecutableBuffer.toString('base64'),
          mimeType: 'image/png',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('rejects Shell scripts (#!/bin/sh) disguised as webp image', async () => {
      const shellScriptBuffer = Buffer.from('#!/bin/bash\necho "Malicious payload executed"\nrm -rf /');

      expect(isExecutableOrHostile(shellScriptBuffer)).toBe(true);

      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: shellScriptBuffer.toString('base64'),
          mimeType: 'image/webp',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);
    });

    it('rejects HTML and script payloads (<script>alert(1)</script>)', async () => {
      const scriptPayload = Buffer.from('<script>alert("XSS")</script>');

      expect(isExecutableOrHostile(scriptPayload)).toBe(true);

      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: scriptPayload.toString('base64'),
          mimeType: 'image/jpeg',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);
    });
  });

  // ============================================================================
  // CHECK 3: ACCEPTANCE: REJECT OVERSIZED FILES
  // ============================================================================
  describe('CHECK 3: Oversized Files Rejection (Acceptance)', () => {
    it('rejects file buffer exceeding 5MB maximum limit with 413 Payload Too Large', async () => {
      // 5.5MB buffer (exceeds 5MB MAX_PRODUCT_IMAGE_SIZE_BYTES limit)
      const oversizedBuffer = Buffer.alloc(5.5 * 1024 * 1024, 0x00);
      // Valid JPEG header so size is the sole reason for rejection
      oversizedBuffer[0] = 0xff;
      oversizedBuffer[1] = 0xd8;
      oversizedBuffer[2] = 0xff;

      expect(() => validateImageBuffer(oversizedBuffer)).toThrow();

      // Test against image route via FormData or direct helper
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'image/jpeg',
          'Content-Length': String(oversizedBuffer.length),
        },
        body: oversizedBuffer,
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(413);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.PAYLOAD_TOO_LARGE);
      expect(body.error.message).toContain('exceeds maximum allowed limit');
    });

    it('rejects oversized Content-Length header > 5MB on product image route with 413', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
          'Content-Length': String(6 * 1024 * 1024), // 6MB header
        },
        body: JSON.stringify({ file: 'dGVzdA==' }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(413);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.PAYLOAD_TOO_LARGE);
    });

    it('rejects oversized image dimensions exceeding 40 million pixels with 422 Unprocessable Entity', async () => {
      // 7000 x 6000 = 42,000,000 pixels (> 40M MAX_IMAGE_PIXELS limit)
      const oversizedSvg = '<svg width="7000" height="6000"><rect width="7000" height="6000" fill="navy"/></svg>';
      const oversizedPngBuffer = await sharp(Buffer.from(oversizedSvg)).png().toBuffer();

      // 1. Direct validation helper rejects
      await expect(validateImagePixelLimit(oversizedPngBuffer)).rejects.toThrow();

      // 2. Direct metadata stripper enforces limitInputPixels
      await expect(stripImageMetadata(oversizedPngBuffer, 'image/png')).rejects.toThrow();

      // 3. Admin upload route rejects oversized pixel count with 422
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: oversizedPngBuffer.toString('base64'),
          mimeType: 'image/png',
          productId: testProductId,
          altText: 'Decompression bomb oversized test suit image',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toContain('pixel limit');
    });
  });

  // ============================================================================
  // CHECK 4: ADMIN PRODUCT IMAGE UPLOAD ROUTE, METADATA STRIPPING & RANDOM UUID
  // ============================================================================
  describe('CHECK 4: Admin Product Image Upload, Metadata Stripping & Random UUID Naming', () => {
    it('rejects anonymous unauthenticated requests with 401 Unauthorized', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file: 'dGVzdA==' }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('rejects CUSTOMER role from uploading to product-images with 403 Forbidden', async () => {
      const validJpeg = await sharp({
        create: { width: 10, height: 10, channels: 3, background: { r: 10, g: 20, b: 30 } },
      })
        .jpeg()
        .toBuffer();

      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: validJpeg.toString('base64'),
          mimeType: 'image/jpeg',
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('ADMIN');
    });

    it('allows ADMIN to upload product image: strips metadata, renames to random UUID, uploads to public bucket', async () => {
      // 1. Generate real JPEG with EXIF metadata (camera info, device tag)
      const rawImageWithMetadata = await sharp({
        create: { width: 40, height: 40, channels: 3, background: { r: 15, g: 35, b: 75 } },
      })
        .withMetadata({
          exif: {
            IFD0: {
              Make: "Don's Atelier Studio Camera",
              Model: 'Savile Row Bespoke Lens 50mm',
            },
          },
        })
        .jpeg()
        .toBuffer();

      // Ensure the raw buffer contains the test EXIF string
      expect(rawImageWithMetadata.toString('latin1')).toContain("Don's Atelier Studio Camera");

      // Test stripImageMetadata helper
      const sanitized = await stripImageMetadata(rawImageWithMetadata, 'image/jpeg');
      expect(sanitized.toString('latin1')).not.toContain("Don's Atelier Studio Camera");

      // 2. Perform upload via Admin route
      const req = new NextRequest('http://localhost:3000/api/admin/products/images', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: rawImageWithMetadata.toString('base64'),
          mimeType: 'image/jpeg',
          productId: testProductId,
          altText: 'Mayfair Midnight Navy Tuxedo Silk Lapel Detail',
          sortOrder: 1,
        }),
      });

      const res = await uploadProductImageRoute(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);

      const uploadData = body.data;
      expect(uploadData.storagePath).toBeDefined();
      expect(uploadData.publicUrl).toContain(STORAGE_BUCKETS.PRODUCT_IMAGES);
      expect(uploadData.mimeType).toBe('image/jpeg');
      expect(uploadData.size).toBeGreaterThan(0);

      // Verify filename is an unpredictable random UUID
      // Expected format: catalog/[0-9a-f-]{36}.jpg
      expect(uploadData.fileName).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jpg$/i);
      expect(uploadData.storagePath).toMatch(/^catalog\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jpg$/i);

      uploadedFilesToCleanup.push({
        bucket: STORAGE_BUCKETS.PRODUCT_IMAGES,
        path: uploadData.storagePath,
      });

      // 3. Verify uploaded file in Supabase Storage has metadata stripped
      const { data: downloadedBlob, error: downloadErr } = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.PRODUCT_IMAGES)
        .download(uploadData.storagePath);

      expect(downloadErr).toBeNull();
      expect(downloadedBlob).toBeDefined();

      const downloadedBuffer = Buffer.from(await downloadedBlob!.arrayBuffer());
      expect(downloadedBuffer.toString('latin1')).not.toContain("Don's Atelier Studio Camera");

      // 4. Verify ProductImage record was saved in Postgres database
      if (uploadData.id) {
        const dbImage = await prisma.productImage.findUnique({
          where: { id: uploadData.id },
        });
        expect(dbImage).toBeDefined();
        expect(dbImage!.productId).toBe(testProductId);
        expect(dbImage!.storagePath).toBe(uploadData.storagePath);
        expect(dbImage!.altText).toBe('Mayfair Midnight Navy Tuxedo Silk Lapel Detail');
      }
    });

    it('allows ADMIN to upload directly to product ID via POST /api/admin/products/[id]/images', async () => {
      const validPng = await sharp({
        create: { width: 30, height: 30, channels: 4, background: { r: 40, g: 60, b: 80, alpha: 1 } },
      })
        .png()
        .toBuffer();

      const req = new NextRequest(`http://localhost:3000/api/admin/products/${testProductId}/images`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file: validPng.toString('base64'),
          mimeType: 'image/png',
          altText: 'Westminster Charcoal Three-Piece Suit Lining Detail',
        }),
      });

      const res = await uploadProductImageForProductRoute(req, {
        params: Promise.resolve({ id: testProductId }),
      });
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.productId).toBe(testProductId);
      expect(body.data.fileName).toMatch(/\.png$/i);

      uploadedFilesToCleanup.push({
        bucket: STORAGE_BUCKETS.PRODUCT_IMAGES,
        path: body.data.storagePath,
      });
    });
  });

  // ============================================================================
  // CHECK 5: SIGNED UPLOAD / DOWNLOAD URL HELPERS WITH SHORT EXPIRY
  // ============================================================================
  describe('CHECK 5: Signed Upload & Download URL Helpers with Short Expiry', () => {
    it('creates short-lived signed upload URL (default 60s)', async () => {
      const testPath = `test-uploads/${customerAId}/${Date.now()}-test.jpg`;
      const result = await createSignedUploadUrl(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS, testPath);

      expect(result.signedUrl).toBeDefined();
      expect(result.signedUrl).toContain('token=');
      expect(result.expiresIn).toBe(DEFAULT_SIGNED_URL_EXPIRY_SECONDS); // 60s
      expect(result.path).toBe(testPath);
    });

    it('creates short-lived signed download URL (default 60s)', async () => {
      const testPath = `catalog/test-sample.jpg`;
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.PRODUCT_IMAGES)
        .upload(testPath, Buffer.from('test sample image data'), {
          upsert: true,
          contentType: 'image/jpeg',
        });
      uploadedFilesToCleanup.push({ bucket: STORAGE_BUCKETS.PRODUCT_IMAGES, path: testPath });

      const result = await createSignedDownloadUrl(STORAGE_BUCKETS.PRODUCT_IMAGES, testPath, {
        expiresIn: 60,
      });

      expect(result.signedUrl).toBeDefined();
      expect(result.signedUrl).toContain('token=');
      expect(result.expiresIn).toBe(60);
    });

    it('rejects signed URL creation with invalid or excessive expiry (> 300s)', async () => {
      await expect(
        createSignedUploadUrl(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS, 'test.jpg', {
          expiresIn: 500, // Exceeds 300s maximum
        })
      ).rejects.toThrow();

      await expect(
        createSignedDownloadUrl(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS, 'test.jpg', {
          expiresIn: 0,
        })
      ).rejects.toThrow();
    });
  });

  // ============================================================================
  // CHECK 6: ACCEPTANCE: REJECT UNAUTHORIZED ACCESS TO PRIVATE BUCKET
  // ============================================================================
  describe('CHECK 6: Private Bucket Access Isolation & Protection (Acceptance)', () => {
    it('rejects anonymous unauthenticated request to generate signed URL for private bucket', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `custom-orders/${customerAId}/private-measurements.jpg`,
          operation: 'download',
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('enforces customer isolation: Customer B CANNOT access Customer A file in private bucket (403 Forbidden)', async () => {
      // Customer B attempts to get signed download URL for Customer A's file
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `custom-orders/${customerAId}/private-measurements.jpg`,
          operation: 'download',
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('Access denied');
    });

    it('enforces customer isolation via GET /api/custom-orders/[id]/attachments/[attachmentId] (403 Forbidden)', async () => {
      // Customer B attempts to get attachment signed URL belonging to Customer A's custom order
      const req = new NextRequest(
        `http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments/${testAttachmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${customerBToken}`,
          },
        }
      );

      const res = await getAttachmentRoute(req, {
        params: Promise.resolve({ id: testCustomOrderId, attachmentId: testAttachmentId }),
      });
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    });

    it('allows Customer A (Owner) to generate signed URL for their own file in private bucket (200 OK)', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `custom-orders/${customerAId}/my-fabric-swatch.jpg`,
          operation: 'upload',
          expiresIn: 60,
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.signedUrl).toBeDefined();
      expect(body.data.expiresIn).toBe(60);
    });

    it('allows Customer A (Owner) to download their bespoke attachment with signed URL via route', async () => {
      const req = new NextRequest(
        `http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments/${testAttachmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${customerAToken}`,
          },
        }
      );

      const res = await getAttachmentRoute(req, {
        params: Promise.resolve({ id: testCustomOrderId, attachmentId: testAttachmentId }),
      });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.signedUrl).toBeDefined();
      expect(body.data.expiresIn).toBe(60);
      expect(body.data.id).toBe(testAttachmentId);
    });

    it('allows ADMIN to access any customer private upload via signed URL (200 OK)', async () => {
      const req = new NextRequest(
        `http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments/${testAttachmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${adminToken}`,
          },
        }
      );

      const res = await getAttachmentRoute(req, {
        params: Promise.resolve({ id: testCustomOrderId, attachmentId: testAttachmentId }),
      });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.signedUrl).toBeDefined();
    });

    it('rejects CUSTOMER from uploading to product-images via signed-url route (403 Forbidden)', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.PRODUCT_IMAGES,
          path: 'catalog/malicious.jpg',
          operation: 'upload',
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('administrators');
    });

    it('rejects CUSTOMER from initiating showcase upload via POST /api/uploads (403 Forbidden)', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'suit-showcase-attempt.jpg',
          mimeType: 'image/jpeg',
          size: 1024 * 50,
          folder: 'showcase',
        }),
      });

      const res = await initiateUploadRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('administrators');
    });

    it('rejects CUSTOMER from requesting signed upload URL for catalog/ path via signed-url route (403 Forbidden)', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: 'catalog/hacked-suit.jpg',
          operation: 'upload',
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('administrators');
    });

    it('ensures POST /api/uploads generates signed URL pointing to custom-order-uploads bucket for customer files', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'customer-fitting-reference.png',
          mimeType: 'image/png',
          size: 1024 * 50,
          folder: 'custom-orders',
        }),
      });

      const res = await initiateUploadRoute(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.bucket).toBe(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS);
      expect(body.data.signedUrl).toBeDefined();
      expect(body.data.expiresIn).toBe(60);
      expect(body.data.storagePath).toContain(customerAId);
    });

    it('strictly generates random UUID under user directory and never uses client-supplied fileName in storagePath', async () => {
      const maliciousClientFileName = '../../../etc/passwd.jpg';
      const req = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: maliciousClientFileName,
          mimeType: 'image/jpeg',
          size: 1024 * 20,
          folder: 'custom-orders',
        }),
      });

      const res = await initiateUploadRoute(req, {} as never);
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body.success).toBe(true);
      // Path must be custom-orders/${customerAId}/<UUID>.jpg
      const expectedPattern = new RegExp(`^custom-orders/${customerAId}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.jpg$`, 'i');
      expect(body.data.storagePath).toMatch(expectedPattern);
      expect(body.data.storagePath).not.toContain('passwd');
      expect(body.data.storagePath).not.toContain('..');
    });

    it('enforces server-generated random UUID path on /api/uploads/signed-url for custom-order-uploads', async () => {
      const req = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `arbitrary-dir/client-named-file.png`,
          operation: 'upload',
        }),
      });

      const res = await signedUrlRoute(req, {} as never);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      // The server overrides the client path with custom-orders/${customerAId}/<UUID>.png
      const expectedPattern = new RegExp(`^custom-orders/${customerAId}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.png$`, 'i');
      expect(body.data.path).toMatch(expectedPattern);
      expect(body.data.path).not.toContain('arbitrary-dir');
    });

    it('rejects custom-order attachment with storagePath pointing outside customer directory with 403 Forbidden', async () => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${testCustomOrderId}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'stolen-reference.jpg',
          mimeType: 'image/jpeg',
          size: 1024 * 30,
          storagePath: `custom-orders/${customerBId}/unauthorized-file.jpg`,
        }),
      });

      const res = await createAttachmentRoute(req, {
        params: Promise.resolve({ id: testCustomOrderId }),
      });
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
      expect(body.error.message).toContain('authorized user upload directory');
    });

    it('configures upload rate-limit group to 30 requests per 60 seconds per user and per IP', () => {
      const rule = rateLimiter.getRule('upload');
      expect(rule.maxRequests).toBe(30);
      expect(rule.windowSeconds).toBe(60);

      const check = rateLimiter.check('upload', '198.51.100.1', customerAId);
      expect(check.limit).toBe(30);
      expect(check.remaining).toBe(29);
      expect(check.allowed).toBe(true);

      rateLimiter.reset();
    });

    it('enforces rate limits on /api/uploads/signed-url (30 requests/min max) returning 429', async () => {
      rateLimiter.reset();

      // Pre-fill 29 requests in the rate limiter for Customer A / IP
      for (let i = 0; i < 29; i++) {
        rateLimiter.check('upload', '127.0.0.1', customerAId);
      }

      // The 30th request must succeed
      const allowedReq = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `custom-orders/${customerAId}/batch-30.jpg`,
          operation: 'upload',
        }),
      });
      const allowedRes = await signedUrlRoute(allowedReq, {} as never);
      expect(allowedRes.status).toBe(200);

      // The 31st request must be throttled with 429
      const throttledReq = new NextRequest('http://localhost:3000/api/uploads/signed-url', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          bucket: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
          path: `custom-orders/${customerAId}/batch-31.jpg`,
          operation: 'upload',
        }),
      });

      const throttledRes = await signedUrlRoute(throttledReq, {} as never);
      expect(throttledRes.status).toBe(429);

      const throttledBody = await throttledRes.json();
      expect(throttledBody.success).toBe(false);
      expect(throttledBody.error.code).toBe(ErrorCode.RATE_LIMITED);
      expect(throttledBody.error.message).toContain('Too many requests');

      // Reset limiter afterwards so subsequent tests are clean
      rateLimiter.reset();
    });

    it('enforces rate limits on /api/uploads (30 requests/min max) returning 429', async () => {
      rateLimiter.reset();

      // Pre-fill 29 requests in the rate limiter for Customer A / IP
      for (let i = 0; i < 29; i++) {
        rateLimiter.check('upload', '127.0.0.1', customerAId);
      }

      // The 30th request must succeed
      const allowedReq = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'sample-30.jpg',
          mimeType: 'image/jpeg',
          size: 1024 * 10,
          folder: 'custom-orders',
        }),
      });
      const allowedRes = await initiateUploadRoute(allowedReq, {} as never);
      expect(allowedRes.status).toBe(201);

      // The 31st request must be throttled with 429
      const throttledReq = new NextRequest('http://localhost:3000/api/uploads', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'sample-31.jpg',
          mimeType: 'image/jpeg',
          size: 1024 * 10,
          folder: 'custom-orders',
        }),
      });

      const throttledRes = await initiateUploadRoute(throttledReq, {} as never);
      expect(throttledRes.status).toBe(429);

      const throttledBody = await throttledRes.json();
      expect(throttledBody.success).toBe(false);
      expect(throttledBody.error.code).toBe(ErrorCode.RATE_LIMITED);

      rateLimiter.reset();
    });
  });
});
