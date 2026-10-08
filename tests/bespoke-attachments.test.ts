import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { NextRequest } from 'next/server';
import sharp from 'sharp';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';
import { STORAGE_BUCKETS } from '@/lib/storage/buckets';
import { POST as createAttachmentRoute } from '@/app/api/custom-orders/[id]/attachments/route';
import { ErrorCode } from '@/lib/errors/error-codes';
import { CustomOrderStatus } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';
import { sanitizeClientFileName } from '@/services/bespoke/attachment-sanitizer';

describe('Bespoke Custom Order Attachment Hardening', () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD;
  if (!customerPassword) {
    throw new Error('SEED_CUSTOMER_PASSWORD environment variable is required');
  }

  let customerAToken: string;
  let customerBToken: string;
  let customerAId: string;
  let customerBId: string;

  const createdOrderIds: string[] = [];
  const uploadedStoragePaths: string[] = [];

  beforeAll(async () => {
    rateLimiter.reset();

    // 1. Auth Customer A
    const { data: authA, error: errA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });
    if (errA || !authA.session) throw new Error(`Customer A sign in failed: ${errA?.message}`);
    customerAToken = authA.session.access_token;
    customerAId = authA.user.id;

    // 2. Auth Customer B
    const { data: authB, error: errB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });
    if (errB || !authB.session) throw new Error(`Customer B sign in failed: ${errB?.message}`);
    customerBToken = authB.session.access_token;
    customerBId = authB.user.id;
  });

  afterAll(async () => {
    if (createdOrderIds.length > 0) {
      await prisma.customOrder.deleteMany({ where: { id: { in: createdOrderIds } } });
    }
    if (uploadedStoragePaths.length > 0) {
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .remove(uploadedStoragePaths)
        .catch(() => {});
    }
  });

  async function createValidJpeg(color: { r: number; g: number; b: number } = { r: 50, g: 100, b: 150 }) {
    return await sharp({
      create: {
        width: 50,
        height: 50,
        channels: 3,
        background: color,
      },
    })
      .jpeg({ quality: 80 })
      .toBuffer();
  }

  // ==============================================================================
  // 1. ATOMIC 5-IMAGE CAP & CONCURRENCY
  // ==============================================================================

  it('5 concurrent attachment adds on an order that already has 3 images: exactly 2 succeed, 3 are rejected, final count is 5', async () => {
    // 1. Create a custom order owned by Customer A
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-CAP-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for atomic 5-image cap testing',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    // 2. Upload and attach 3 initial images
    for (let i = 1; i <= 3; i++) {
      const initialPath = `custom-orders/${customerAId}/init-${i}-${Date.now()}.jpg`;
      const buf = await createValidJpeg({ r: i * 20, g: i * 30, b: i * 40 });
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .upload(initialPath, buf, { contentType: 'image/jpeg', upsert: true });
      uploadedStoragePaths.push(initialPath);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: `init-${i}.jpg`,
          storagePath: initialPath,
        }),
      });

      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(201);
      const resBody = await res.json();
      uploadedStoragePaths.push(resBody.data.storagePath);
    }

    const preCount = await prisma.customOrderAttachment.count({ where: { customOrderId: order.id } });
    expect(preCount).toBe(3);

    // 3. Prepare 5 distinct uploaded images in Supabase Storage
    const concurrentPaths: string[] = [];
    for (let j = 1; j <= 5; j++) {
      const concPath = `custom-orders/${customerAId}/conc-${j}-${Date.now()}.jpg`;
      const buf = await createValidJpeg({ r: 100 + j * 10, g: 120, b: 150 });
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .upload(concPath, buf, { contentType: 'image/jpeg', upsert: true });
      concurrentPaths.push(concPath);
      uploadedStoragePaths.push(concPath);
    }

    // 4. Send 5 concurrent attachment add requests
    const promises = concurrentPaths.map((cPath, idx) => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: `conc-${idx + 1}.jpg`,
          storagePath: cPath,
        }),
      });
      return createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    });

    const results = await Promise.all(promises);

    const succeeded = results.filter((r) => r.status === 201);
    const rejected = results.filter((r) => r.status >= 400);

    expect(succeeded.length).toBe(2);
    expect(rejected.length).toBe(3);

    // 5. Final count must be exactly 5
    const finalCount = await prisma.customOrderAttachment.count({ where: { customOrderId: order.id } });
    expect(finalCount).toBe(5);
  }, 90000);

  // ==============================================================================
  // 2. SERVER-SIDE RE-VALIDATION: NON-IMAGE ORPHAN CLEANUP
  // ==============================================================================

  it('a non-image file renamed .jpg is rejected with 422 and the orphan is deleted', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-FAKE-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for non-image detection test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const fakePath = `custom-orders/${customerAId}/fake-image-${Date.now()}.jpg`;
    const fakeBuffer = Buffer.from('Plain text file with malicious PHP shell pretending to be a JPG');
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(fakePath, fakeBuffer, { contentType: 'image/jpeg', upsert: true });

    // Verify object exists before attach call
    const existsBefore = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .exists(fakePath);
    expect(existsBefore.data).toBe(true);

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'fake-image.jpg',
        storagePath: fakePath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);

    // Confirm orphan object was deleted from storage
    const existsAfter = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .exists(fakePath);
    expect(existsAfter.data).toBe(false);
  });

  // ==============================================================================
  // 3. EXIF GPS DATA STRIPPING
  // ==============================================================================

  it('a JPEG with EXIF GPS data: the attached file has no EXIF', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-EXIF-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for EXIF stripping verification',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    // Create JPEG with EXIF GPS metadata using Sharp
    const exifJpeg = await sharp({
      create: {
        width: 60,
        height: 60,
        channels: 3,
        background: { r: 200, g: 50, b: 50 },
      },
    })
      .jpeg({ quality: 90 })
      .withMetadata({
        exif: {
          IFD0: {
            Make: 'Atelier Secret Camera',
            Model: 'Savile Row 100',
          },
          GPSInfo: {
            GPSLatitudeRef: 'N',
            GPSLatitude: '51/1 30/1 44/1',
            GPSLongitudeRef: 'W',
            GPSLongitude: '0/1 8/1 26/1',
          },
        } as never,
      })
      .toBuffer();

    const metaBefore = await sharp(exifJpeg).metadata();
    expect(metaBefore.exif).toBeDefined();

    const exifPath = `custom-orders/${customerAId}/gps-test-${Date.now()}.jpg`;
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(exifPath, exifJpeg, { contentType: 'image/jpeg', upsert: true });

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'customer-gps-sketch.jpg',
        storagePath: exifPath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);
    const newAttachedPath = body.data.storagePath;
    uploadedStoragePaths.push(newAttachedPath);

    // Download the re-encoded, sanitized file from Supabase Storage
    const { data: blob } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .download(newAttachedPath);
    expect(blob).toBeDefined();

    const sanitizedBuf = Buffer.from(await blob!.arrayBuffer());
    const metaAfter = await sharp(sanitizedBuf).metadata();
    expect(metaAfter.exif).toBeUndefined();
  });

  // ==============================================================================
  // 4. PATH TRAVERSAL ATTEMPTS REJECTED
  // ==============================================================================

  it('path traversal attempts (.., %2e%2e, double-encoded, backslash, wrong bucket, another user prefix) are all rejected', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-TRAV-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for path traversal security verification',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const maliciousPaths = [
      `custom-orders/${customerAId}/../secret.jpg`,
      `custom-orders/${customerAId}/%2e%2e/secret.jpg`,
      `custom-orders/${customerAId}/%252e%252e/secret.jpg`,
      `custom-orders\\${customerAId}\\secret.jpg`,
      `product-images/${customerAId}/secret.jpg`,
      `custom-orders/${customerBId}/secret.jpg`,
      `${customerAId}/secret.jpg`,
      `custom-orders/${customerAId}/secret\0.jpg`,
      `/custom-orders/${customerAId}/secret.jpg`,
      `custom-orders/${customerAId}/nested/subdir/secret.jpg`,
    ];

    for (const badPath of maliciousPaths) {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'attack.jpg',
          storagePath: badPath,
        }),
      });

      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBeGreaterThanOrEqual(400);

      const body = await res.json();
      expect(body.success).toBe(false);
    }
  }, 60000);

  // ==============================================================================
  // 5. SERVER-GENERATED OBJECT IMMUTABILITY / OVERWRITE ISOLATION
  // ==============================================================================

  it('after attach, overwrite the original uploaded object; confirm the attached file is unaffected and the original object no longer exists', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-OVERWRITE-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for overwrite immutability verification',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    // 1. Upload original green JPEG
    const greenBuf = await createValidJpeg({ r: 0, g: 255, b: 0 });
    const originalPath = `custom-orders/${customerAId}/orig-to-overwrite-${Date.now()}.jpg`;
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(originalPath, greenBuf, { contentType: 'image/jpeg', upsert: true });

    // 2. Attach the original path
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'green-swatch.jpg',
        storagePath: originalPath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(201);
    const body = await res.json();
    const attachedNewPath = body.data.storagePath;
    uploadedStoragePaths.push(attachedNewPath);

    // 3. Confirm original upload object no longer exists
    const origExists = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .exists(originalPath);
    expect(origExists.data).toBe(false);

    // 4. Download attached file content
    const { data: blobInitial } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .download(attachedNewPath);
    const attachedBufInitial = Buffer.from(await blobInitial!.arrayBuffer());

    // 5. Maliciously overwrite the original upload path with a completely different red file
    const redBuf = await createValidJpeg({ r: 255, g: 0, b: 0 });
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(originalPath, redBuf, { contentType: 'image/jpeg', upsert: true });
    uploadedStoragePaths.push(originalPath);

    // 6. Download attached file again and confirm it is unaffected
    const { data: blobAfter } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .download(attachedNewPath);
    const attachedBufAfter = Buffer.from(await blobAfter!.arrayBuffer());

    expect(attachedBufAfter.equals(attachedBufInitial)).toBe(true);
  });

  // ==============================================================================
  // 6. OVERSIZED FILE REJECTED BEFORE FULL DOWNLOAD
  // ==============================================================================

  it('oversized file is rejected before full download', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-OVERSIZED-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for oversized file metadata rejection test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const oversizedPath = `custom-orders/${customerAId}/oversized-${Date.now()}.jpg`;
    const validBuf = await createValidJpeg();
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(oversizedPath, validBuf, { contentType: 'image/jpeg', upsert: true });

    // Mock storage info to report 15MB file size from storage metadata
    const originalFrom = supabaseAdmin.storage.from.bind(supabaseAdmin.storage);
    const fileApi = originalFrom(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS);

    const infoSpy = vi.spyOn(fileApi, 'info').mockResolvedValue({
      data: {
        id: 'test-id',
        name: oversizedPath,
        size: 15 * 1024 * 1024, // 15MB
        contentType: 'image/jpeg',
        bucketId: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
        version: '1',
        cacheControl: 'max-age=3600',
        etag: 'test',
        metadata: {},
        lastModified: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        archivedAt: null,
        isDeleteMarker: false,
        isVersioned: false,
      } as any,
      error: null,
    });

    const downloadSpy = vi.spyOn(fileApi, 'download');
    const fromSpy = vi.spyOn(supabaseAdmin.storage, 'from').mockImplementation(((b: string) => {
      if (b === STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS) {
        return fileApi;
      }
      return originalFrom(b);
    }) as any);

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'huge-file.jpg',
        storagePath: oversizedPath,
      }),
    });

    try {
      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toContain('File size');

      // Confirm download was NEVER called (rejected before full download)
      expect(downloadSpy).not.toHaveBeenCalledWith(oversizedPath);

      // Confirm orphan was deleted
      const existsAfter = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .exists(oversizedPath);
      expect(existsAfter.data).toBe(false);
    } finally {
      fromSpy.mockRestore();
      infoSpy.mockRestore();
      downloadSpy.mockRestore();
    }
  });

  // ==============================================================================
  // 7. FAIL CLOSED ON UNKNOWN SIZE (METADATA LOOKUP FAILURE)
  // ==============================================================================

  it('simulated metadata failure means rejected with generic error, download never called, and orphan deleted', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-META-FAIL-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for simulated metadata failure test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const testPath = `custom-orders/${customerAId}/meta-fail-${Date.now()}.jpg`;
    const validBuf = await createValidJpeg();
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(testPath, validBuf, { contentType: 'image/jpeg', upsert: true });

    // Mock storage info and list to fail / return no size
    const originalFrom = supabaseAdmin.storage.from.bind(supabaseAdmin.storage);
    const fileApi = originalFrom(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS);

    const infoSpy = vi.spyOn(fileApi, 'info').mockResolvedValue({
      data: null,
      error: { name: 'StorageError', message: 'Storage metadata lookup service error' } as any,
    });
    const listSpy = vi.spyOn(fileApi, 'list').mockResolvedValue({
      data: [],
      error: null,
    });

    const downloadSpy = vi.spyOn(fileApi, 'download');
    const fromSpy = vi.spyOn(supabaseAdmin.storage, 'from').mockImplementation(((b: string) => {
      if (b === STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS) {
        return fileApi;
      }
      return originalFrom(b);
    }) as any);

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'meta-fail.jpg',
        storagePath: testPath,
      }),
    });

    try {
      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(422);

      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(body.error.message).toContain('File size verification failed');

      // Confirm download was NEVER called
      expect(downloadSpy).not.toHaveBeenCalled();

      // Confirm orphan was deleted from storage
      const existsAfter = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .exists(testPath);
      expect(existsAfter.data).toBe(false);
    } finally {
      fromSpy.mockRestore();
      infoSpy.mockRestore();
      listSpy.mockRestore();
      downloadSpy.mockRestore();
    }
  });

  // ==============================================================================
  // 8. EXIF ORIENTATION 6 AUTO-ROTATION AND EXIF STRIPPING
  // ==============================================================================

  it('JPEG with EXIF orientation 6: output dimensions are swapped and no EXIF remains', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-ORIENT-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for orientation 6 rotation test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    // Initial image is 100 wide x 60 high with orientation 6 (90 deg CW rotation)
    const initialWidth = 100;
    const initialHeight = 60;
    const orient6Jpeg = await sharp({
      create: {
        width: initialWidth,
        height: initialHeight,
        channels: 3,
        background: { r: 120, g: 80, b: 200 },
      },
    })
      .jpeg()
      .withMetadata({ orientation: 6 })
      .toBuffer();

    const metaBefore = await sharp(orient6Jpeg).metadata();
    expect(metaBefore.width).toBe(initialWidth);
    expect(metaBefore.height).toBe(initialHeight);
    expect(metaBefore.orientation).toBe(6);
    expect(metaBefore.exif).toBeDefined();

    const orientPath = `custom-orders/${customerAId}/orient6-${Date.now()}.jpg`;
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(orientPath, orient6Jpeg, { contentType: 'image/jpeg', upsert: true });

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'oriented-portrait.jpg',
        storagePath: orientPath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);
    const newStoragePath = body.data.storagePath;
    uploadedStoragePaths.push(newStoragePath);

    // Download sanitized image from storage
    const { data: blob } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .download(newStoragePath);
    expect(blob).toBeDefined();

    const sanitizedBuf = Buffer.from(await blob!.arrayBuffer());
    const metaAfter = await sharp(sanitizedBuf).metadata();

    // Dimensions must be swapped (100x60 rotated 90 deg CW becomes 60x100)
    expect(metaAfter.width).toBe(initialHeight);
    expect(metaAfter.height).toBe(initialWidth);

    // EXIF must be completely stripped
    expect(metaAfter.exif).toBeUndefined();
    expect(metaAfter.orientation).toBeUndefined();
  });

  // ==============================================================================
  // 9. CLIENT-SUPPLIED FILENAME SANITIZATION & STORAGE PATH ISOLATION
  // ==============================================================================

  it('client-supplied fileName strips path separators, control characters, null bytes, caps length, and is never used as storage path', async () => {
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-NAME-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for client fileName sanitization test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const testPath = `custom-orders/${customerAId}/name-test-${Date.now()}.jpg`;
    const validBuf = await createValidJpeg();
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(testPath, validBuf, { contentType: 'image/jpeg', upsert: true });

    // Malicious fileName containing directory separators, null bytes, control chars, and excessive length
    const dirtyFileName = `../../nested\\dir\0\x08\x1b[31m${'a'.repeat(300)}-sketch.jpg`;

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: dirtyFileName,
        storagePath: testPath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);

    const returnedFileName = body.data.fileName;
    const returnedStoragePath = body.data.storagePath;
    uploadedStoragePaths.push(returnedStoragePath);

    // 1. Path separators and null bytes stripped from fileName
    expect(returnedFileName).not.toContain('/');
    expect(returnedFileName).not.toContain('\\');
    expect(returnedFileName).not.toContain('\0');
    expect(/[\x00-\x1f\x7f-\x9f]/.test(returnedFileName)).toBe(false);

    // 2. Length is capped to max 255 chars
    expect(returnedFileName.length).toBeLessThanOrEqual(255);

    // 3. Storage path is NEVER constructed from client fileName
    expect(returnedStoragePath).not.toContain('nested');
    expect(returnedStoragePath).not.toContain('dir');
    expect(returnedStoragePath).not.toContain('sketch');
    expect(returnedStoragePath).toMatch(new RegExp(`^custom-orders/${customerAId}/[a-f0-9-]{36}\\.jpg$`));
  });

  // ==============================================================================
  // 10. UNICODE BIDI AND INVISIBLE CHARACTER STRIPPING (U+202E, ETC.)
  // ==============================================================================

  it('a name containing U+202E comes out with it removed (both unit and attachment route)', async () => {
    // 1. Direct function assertion
    const bidiName = 'customer-order\u202Egpj.exe';
    const cleaned = sanitizeClientFileName(bidiName);
    expect(cleaned).toBe('customer-ordergpj.exe');
    expect(cleaned).not.toContain('\u202E');

    // Also verify other invisible/bidi characters: U+200B-200F, U+202A-202E, U+2066-2069, U+FEFF
    const complexInvis = '\u200Bbespoke\u200Csuit\u202Atest\u202Ephoto\u2066sample\uFEFF.jpg';
    const cleanedComplex = sanitizeClientFileName(complexInvis);
    expect(cleanedComplex).toBe('bespokesuittestphotosample.jpg');

    // 2. Route-level integration assertion
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-BIDI-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke suit request for U+202E bidi stripping test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    const testPath = `custom-orders/${customerAId}/bidi-test-${Date.now()}.jpg`;
    const validBuf = await createValidJpeg();
    await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .upload(testPath, validBuf, { contentType: 'image/jpeg', upsert: true });

    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'bespoke-suit\u202Ephoto.jpg',
        storagePath: testPath,
      }),
    });

    const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.fileName).toBe('bespoke-suitphoto.jpg');
    expect(body.data.fileName).not.toContain('\u202E');
    uploadedStoragePaths.push(body.data.storagePath);
  });

  // ==============================================================================
  // 11. ORPHAN CLEANUP ON 5-IMAGE CAP FAILURE (7 CONCURRENT ON ORDER WITH 0 ATTACHMENTS)
  // ==============================================================================

  it('fire 7 concurrent attachments at an order with 0 attachments: exactly 5 DB rows AND exactly 5 sanitized objects in storage under that order path', async () => {
    // 1. Create order with 0 attachments for Customer B
    const order = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-CAP7-${Date.now()}`,
        profileId: customerBId,
        description: 'Bespoke suit request for 7 concurrent attachment cap & storage cleanup test',
        status: CustomOrderStatus.SUBMITTED,
      },
    });
    createdOrderIds.push(order.id);

    // Clean up any pre-existing files in customerB's folder to ensure a clean slate
    const { data: existingFiles } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .list(`custom-orders/${customerBId}`);
    if (existingFiles && existingFiles.length > 0) {
      const oldPaths = existingFiles.map((f) => `custom-orders/${customerBId}/${f.name}`);
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .remove(oldPaths);
    }

    // 2. Upload 7 valid initial files
    const initialPaths: string[] = [];
    for (let i = 1; i <= 7; i++) {
      const uPath = `custom-orders/${customerBId}/batch7-${i}-${Date.now()}.jpg`;
      const buf = await createValidJpeg({ r: 25 * i, g: 30 * i, b: 35 * i });
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .upload(uPath, buf, { contentType: 'image/jpeg', upsert: true });
      initialPaths.push(uPath);
      uploadedStoragePaths.push(uPath);
    }

    // 3. Fire 7 concurrent attachments
    const promises = initialPaths.map((p, idx) => {
      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerBToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: `fabric-${idx + 1}.jpg`,
          storagePath: p,
        }),
      });
      return createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
    });

    const results = await Promise.all(promises);

    const succeeded = results.filter((r) => r.status === 201);
    const rejected = results.filter((r) => r.status >= 400);

    expect(succeeded.length).toBe(5);
    expect(rejected.length).toBe(2);

    // 4. Assert exactly 5 DB rows
    const dbAttachments = await prisma.customOrderAttachment.findMany({
      where: { customOrderId: order.id },
    });
    expect(dbAttachments.length).toBe(5);

    // 5. Assert exactly 5 sanitized objects in storage under that order's path
    const { data: storageObjects } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
      .list(`custom-orders/${customerBId}`);

    expect(storageObjects).toBeDefined();
    expect(storageObjects!.length).toBe(5);

    // Verify all 5 storage objects match the 5 DB attachment rows
    const dbObjectNames = dbAttachments.map((att) => att.storagePath.split('/').pop());
    for (const obj of storageObjects!) {
      expect(dbObjectNames).toContain(obj.name);
      uploadedStoragePaths.push(`custom-orders/${customerBId}/${obj.name}`);
    }
  }, 90000);

  describe('Attachment Route Rollback vs Preservation (Step 4c)', () => {
    it('Outcome 1: preserved when DB insert commits (storage object exists and is NOT deleted)', async () => {
      const order = await prisma.customOrder.create({
        data: {
          orderNumber: `CO-COMMIT-${Date.now()}`,
          profileId: customerAId,
          description: 'Testing committed storage preservation',
          status: CustomOrderStatus.SUBMITTED,
        },
      });
      createdOrderIds.push(order.id);

      const rawPath = `custom-orders/${customerAId}/commit-test-${Date.now()}.jpg`;
      const buf = await createValidJpeg({ r: 40, g: 80, b: 120 });
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .upload(rawPath, buf, { contentType: 'image/jpeg', upsert: true });
      uploadedStoragePaths.push(rawPath);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'committed-sample.jpg',
          storagePath: rawPath,
        }),
      });

      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.success).toBe(true);
      const sanitizedPath = json.data.storagePath;
      uploadedStoragePaths.push(sanitizedPath);

      // Verify the DB row exists
      const dbRow = await prisma.customOrderAttachment.findUnique({
        where: { id: json.data.id },
      });
      expect(dbRow).toBeDefined();

      // Verify the sanitized object in storage is NOT deleted and exists
      const sanitizedFileName = sanitizedPath.split('/').pop()!;
      const { data: storageList } = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .list(`custom-orders/${customerAId}`);
      expect(storageList?.some((item) => item.name === sanitizedFileName)).toBe(true);
    });

    it('Outcome 2: deleted when DB insert fails to commit (sanitized object deleted from storage on error)', async () => {
      // Create order already at 5 images cap
      const order = await prisma.customOrder.create({
        data: {
          orderNumber: `CO-FAIL-${Date.now()}`,
          profileId: customerAId,
          description: 'Testing failed commit rollback',
          status: CustomOrderStatus.SUBMITTED,
        },
      });
      createdOrderIds.push(order.id);

      // Pre-fill 5 attachments directly in DB
      for (let i = 1; i <= 5; i++) {
        await prisma.customOrderAttachment.create({
          data: {
            customOrderId: order.id,
            fileName: `dummy-${i}.jpg`,
            size: 1000,
            mimeType: 'image/jpeg',
            storagePath: `custom-orders/${customerAId}/dummy-${i}.jpg`,
          },
        });
      }

      // Upload raw file to storage
      const rawPath = `custom-orders/${customerAId}/fail-test-${Date.now()}.jpg`;
      const buf = await createValidJpeg({ r: 90, g: 90, b: 90 });
      await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .upload(rawPath, buf, { contentType: 'image/jpeg', upsert: true });
      uploadedStoragePaths.push(rawPath);

      const req = new NextRequest(`http://localhost:3000/api/custom-orders/${order.id}/attachments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${customerAToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileName: 'should-fail-rollback.jpg',
          storagePath: rawPath,
        }),
      });

      // 6th image must fail with 409 or 400 because max cap is 5
      const res = await createAttachmentRoute(req, { params: Promise.resolve({ id: order.id }) });
      expect([400, 409]).toContain(res.status);

      // Assert that DB attachments remain exactly 5
      const count = await prisma.customOrderAttachment.count({
        where: { customOrderId: order.id },
      });
      expect(count).toBe(5);

      // Assert that no new sanitized file remains in storage (storage object was cleaned up)
      const { data: storageList } = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS)
        .list(`custom-orders/${customerAId}`);
      expect(storageList?.some((item) => item.name.includes('fail-test'))).toBe(false);
    });
  });
});
