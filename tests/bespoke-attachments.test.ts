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

describe('Bespoke Custom Order Attachment Hardening', () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';

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
        },
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
  });

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
      },
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

    fromSpy.mockRestore();
    infoSpy.mockRestore();
    downloadSpy.mockRestore();
  });
});
