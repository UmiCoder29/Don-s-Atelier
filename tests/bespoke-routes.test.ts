import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient } from '@/lib/db/supabase';
import { POST as createCustomOrder, GET as listCustomOrders } from '@/app/api/custom-orders/route';
import { GET as getCustomOrderById, PATCH as customerEditCustomOrder } from '@/app/api/custom-orders/[id]/route';
import { PATCH as adminUpdateCustomOrder } from '@/app/api/admin/custom-orders/[id]/route';
import { POST as acceptCustomOrder } from '@/app/api/custom-orders/[id]/accept/route';
import { POST as addCustomOrderNote } from '@/app/api/custom-orders/[id]/notes/route';
import { POST as addCustomOrderMessage } from '@/app/api/custom-orders/[id]/messages/route';
import { POST as withdrawCustomOrder } from '@/app/api/custom-orders/[id]/withdraw/route';
import { POST as addAttachment } from '@/app/api/custom-orders/[id]/attachments/route';
import { POST as initiateUpload } from '@/app/api/uploads/route';
import { ErrorCode } from '@/lib/errors/error-codes';
import { CustomOrderStatus } from '@prisma/client';
import { rateLimiter } from '@/lib/security/rate-limiter';

describe('Bespoke Custom Order API Routes', () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const adminEmail = 'admin@dons-atelier.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD;
  const adminPassword = process.env.SEED_ADMIN_PASSWORD;
  if (!customerPassword || !adminPassword) {
    throw new Error('SEED_CUSTOMER_PASSWORD and SEED_ADMIN_PASSWORD environment variables are required');
  }

  let customerAToken: string;
  let customerBToken: string;
  let adminToken: string;
  let customerAId: string;
  let customerBId: string;
  let createdCustomOrderId: string;
  const createdOrderIds: string[] = [];

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

    // 3. Auth Admin
    const { data: authAdmin, error: errAdmin } = await createSupabaseUserClient().auth.signInWithPassword({
      email: adminEmail,
      password: adminPassword,
    });
    if (errAdmin || !authAdmin.session) throw new Error(`Admin sign in failed: ${errAdmin?.message}`);
    adminToken = authAdmin.session.access_token;
  });

  afterAll(async () => {
    if (createdOrderIds.length > 0) {
      await prisma.customOrder.deleteMany({ where: { id: { in: createdOrderIds } } });
    }
  });

  // ==============================================================================
  // 1. Core Submission & Lifecycle
  // ==============================================================================

  it('allows customer to submit a bespoke custom suit request', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke three-piece midnight navy tuxedo for a charity gala at the Royal Opera House.',
        occasion: 'Black Tie Gala',
        budgetRange: '$2,500 - $3,500',
        fabricPreference: 'Super 160s English Barathea Wool',
        stylePreference: 'Wide peak lapel with silk grosgrain finish, double-breasted vest',
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);

    const customOrder = body.data;
    createdCustomOrderId = customOrder.id;
    createdOrderIds.push(createdCustomOrderId);

    expect(customOrder.orderNumber).toMatch(/^CO-\d{4}-[0-9A-F]{6}$/);
    expect(customOrder.status).toBe(CustomOrderStatus.SUBMITTED);
    expect(customOrder.statusHistory.length).toBeGreaterThanOrEqual(1);
    expect(customOrder.statusHistory[0].toStatus).toBe(CustomOrderStatus.SUBMITTED);
  });

  it('enforces assertOwnerOrAdmin: Customer B cannot view Customer A bespoke order', async () => {
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
      },
    });

    const res = await getCustomOrderById(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(403);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
  });

  it('allows Customer A to view their bespoke order', async () => {
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
      },
    });

    const res = await getCustomOrderById(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(createdCustomOrderId);
  });

  it('rejects price quotation attempt by customer: 422 on customer PATCH, 403 on admin PATCH', async () => {
    // A. Attempting to pass quotedPriceInCents on PATCH /api/custom-orders/[id] is rejected with 422
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        quotedPriceInCents: 280000,
      }),
    });

    const res = await customerEditCustomOrder(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);

    // B. Attempting to call PATCH /api/admin/custom-orders/[id] as Customer returns 403 Forbidden
    const adminReq = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        quotedPriceInCents: 280000,
      }),
    });
    const adminRes = await adminUpdateCustomOrder(adminReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(adminRes.status).toBe(403);
  });

  it('enforces owner-only on customer PATCH /api/custom-orders/[id] (admin gets 403, cross-customer gets 403, owner edit writes audit with changed field names only)', async () => {
    // 1. ADMIN calling customer PATCH /api/custom-orders/[id] receives 403 Forbidden
    const adminOnCustomerRouteReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Admin attempting customer edit',
      }),
    });
    const adminOnCustomerRes = await customerEditCustomOrder(adminOnCustomerRouteReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(adminOnCustomerRes.status).toBe(403);
    const adminErrJson = await adminOnCustomerRes.json();
    expect(adminErrJson.error.message).toContain('Customer edit route is reserved strictly for order owners');

    // 2. Customer B (non-owner) receives 403 Forbidden
    const customerBReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Customer B attempting edit',
      }),
    });
    const customerBRes = await customerEditCustomOrder(customerBReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(customerBRes.status).toBe(403);

    // 3. Customer A (owner) edit succeeds while order is SUBMITTED
    const validEditReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Customer A updated bespoke suit description',
      }),
    });
    const validEditRes = await customerEditCustomOrder(validEditReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(validEditRes.status).toBe(200);

    // 4. Assert audit entry was written in the same transaction listing changed FIELD NAMES only, NO values
    const auditEntries = await prisma.auditLog.findMany({
      where: {
        action: 'CUSTOM_ORDER_CUSTOMER_EDIT',
        entityId: createdCustomOrderId,
      },
      orderBy: { timestamp: 'desc' },
      take: 1,
    });
    expect(auditEntries.length).toBe(1);
    const audit = auditEntries[0];
    expect(audit.actorId).toBe(customerAId);
    const metadata = audit.metadata as Record<string, unknown>;
    expect(metadata.changedFields).toBeDefined();
    expect(Array.isArray(metadata.changedFields)).toBe(true);
    expect(metadata.changedFields).toEqual(['description']);
    // Assert NO values leaked in metadata
    expect(JSON.stringify(metadata)).not.toContain('Customer A updated bespoke suit description');
  });

  it('allows ADMIN to quote price on bespoke order and transitions status to QUOTED via /api/admin/custom-orders/[id]', async () => {
    // 1. Transition from SUBMITTED to IN_REVIEW per central state machine
    await prisma.customOrder.update({
      where: { id: createdCustomOrderId },
      data: { status: CustomOrderStatus.IN_REVIEW },
    });

    const req = new NextRequest(`http://localhost:3000/api/admin/custom-orders/${createdCustomOrderId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        quotedPriceInCents: 280000, // $2,800.00
        notes: 'Hand-canvassed English barathea wool with Dormeuil silk facings confirmed.',
      }),
    });

    const res = await adminUpdateCustomOrder(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.quotedPriceInCents).toBe(280000);
    expect(body.data.status).toBe(CustomOrderStatus.QUOTED);
  });

  it('allows Customer A to ACCEPT the formal quotation via POST /api/custom-orders/[id]/accept', async () => {
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/accept`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        expectedPriceInCents: 280000,
        notes: 'Quotation accepted, ready for initial fitting schedule.',
      }),
    });

    const res = await acceptCustomOrder(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.status).toBe(CustomOrderStatus.ACCEPTED);
  });

  it('lists custom orders filtered to the authenticated customer on /api/custom-orders', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
      },
    });

    const res = await listCustomOrders(req, {} as never);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    for (const item of body.data) {
      expect(item.profileId).toBe(customerAId);
    }
  });

  // ==============================================================================
  // 2. Acceptance: Invalid Measurements Validation
  // ==============================================================================

  it('rejects custom suit request with negative measurement value', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke two-piece charcoal business suit with hand-stitched pick lapels.',
        measurements: [
          { key: 'chest', value: -42, unit: 'inches' },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  it('rejects custom suit request with zero measurement value', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke two-piece charcoal business suit with hand-stitched pick lapels.',
        measurements: [
          { key: 'waist', value: 0, unit: 'cm' },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  it('rejects custom suit request with measurement exceeding plausible bounds', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke two-piece charcoal business suit with hand-stitched pick lapels.',
        measurements: [
          { key: 'waist', value: 9999, unit: 'cm' },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  it('rejects custom suit request with invalid measurement unit', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke two-piece charcoal business suit with hand-stitched pick lapels.',
        measurements: [
          { key: 'chest', value: 42, unit: 'lightyears' },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  it('rejects structured measurements with negative or out-of-range bounds', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke two-piece charcoal business suit with hand-stitched pick lapels.',
        measurements: {
          unit: 'inches',
          chest: -10,
        },
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  // ==============================================================================
  // 3. Field-Level Encryption & Decryption Verification
  // ==============================================================================

  it('encrypts measurements and customer notes at field level in the database, decrypting upon retrieval', async () => {
    const privateNote = 'Strictly confidential customer requests: subtle monogram inside left breast pocket.';
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Custom bespoke midnight navy dinner jacket with silk satin shawl collar.',
        notes: privateNote,
        measurements: [
          { key: 'chest', value: 42, unit: 'inches' },
          { key: 'waist', value: 34, unit: 'inches' },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);
    const orderId = body.data.id;
    createdOrderIds.push(orderId);

    // 1. Verify API response returns decrypted values
    expect(body.data.notes).toBe(privateNote);
    expect(body.data.measurements.length).toBe(2);
    const chestM = body.data.measurements.find((m: { key: string }) => m.key === 'chest');
    expect(chestM.value).toBe('42');

    // 2. Direct DB verification: verify raw stored values start with AES-256-GCM 'enc:v1:' prefix
    const rawDbOrder = await prisma.customOrder.findUnique({
      where: { id: orderId },
      include: { measurements: true, statusHistory: true },
    });
    expect(rawDbOrder?.notes?.startsWith('enc:')).toBe(true);

    for (const m of rawDbOrder!.measurements) {
      expect(m.value.startsWith('enc:')).toBe(true);
    }

    for (const h of rawDbOrder!.statusHistory) {
      if (h.note) {
        expect(h.note.startsWith('enc:')).toBe(true);
      }
    }

    // 3. GET endpoint returns decrypted representation
    const getReq = new NextRequest(`http://localhost:3000/api/custom-orders/${orderId}`, {
      headers: { 'Authorization': `Bearer ${customerAToken}` },
    });
    const getRes = await getCustomOrderById(getReq, { params: Promise.resolve({ id: orderId }) });
    expect(getRes.status).toBe(200);
    const getBody = await getRes.json();
    expect(getBody.data.notes).toBe(privateNote);
    expect(getBody.data.measurements.find((m: { key: string }) => m.key === 'chest').value).toBe('42');
  });

  // ==============================================================================
  // 4. Acceptance: Attachment Ownership & Foreign IDs Validation
  // ==============================================================================

  it('generates signed upload URL for custom-orders reference image via /api/uploads', async () => {
    const req = new NextRequest('http://localhost:3000/api/uploads', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: 'tuxedo-lapel-sketch.jpg',
        mimeType: 'image/jpeg',
        size: 1024 * 1024,
        folder: 'custom-orders',
      }),
    });

    const res = await initiateUpload(req, {} as never);
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.storagePath).toMatch(new RegExp(`^custom-orders/${customerAId}/[0-9a-f-]+\\.jpg$`));
    expect(body.data.signedUrl).toBeDefined();
    expect(body.data.expiresIn).toBe(60);
  });

  it('rejects custom suit request with foreign storagePath belonging to another user', async () => {
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke tuxedo trying to reference another customer uploaded file.',
        attachments: [
          {
            storagePath: `custom-orders/${customerBId}/confidential-sketch.jpg`,
            fileName: 'confidential-sketch.jpg',
            mimeType: 'image/jpeg',
            size: 2048,
          },
        ],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(403);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    expect(body.error.message).toContain('Storage path must reside within your authorized user upload directory');
  });

  it('rejects custom suit request referencing foreign attachmentIds belonging to another user', async () => {
    // 1. Create a custom order for Customer B with an attachment
    const bOrder = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-TEST-B-${Date.now()}`,
        profileId: customerBId,
        description: 'Customer B order for foreign attachment test',
        status: CustomOrderStatus.SUBMITTED,
        attachments: {
          create: {
            fileName: 'customer-b-reference.jpg',
            mimeType: 'image/jpeg',
            size: 2048,
            storagePath: `custom-orders/${customerBId}/customer-b-reference.jpg`,
          },
        },
      },
      include: { attachments: true },
    });
    createdOrderIds.push(bOrder.id);
    const foreignAttachmentId = bOrder.attachments[0].id;

    // 2. Customer A attempts to submit custom order referencing Customer B's attachment ID
    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Customer A order maliciously referencing Customer B attachment ID.',
        attachmentIds: [foreignAttachmentId],
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(403);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.FORBIDDEN);
    expect(body.error.message).toContain('Attachment does not belong to the authenticated user');
  });

  it('rejects custom suit request with more than 5 reference images', async () => {
    const attachments = Array.from({ length: 6 }, (_, i) => ({
      storagePath: `custom-orders/${customerAId}/photo-${i + 1}.jpg`,
      fileName: `photo-${i + 1}.jpg`,
      mimeType: 'image/jpeg' as const,
      size: 1024,
    }));

    const req = new NextRequest('http://localhost:3000/api/custom-orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: 'Bespoke request attempting to attach 6 reference photos.',
        attachments,
      }),
    });

    const res = await createCustomOrder(req, {} as never);
    expect(res.status).toBe(422);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.VALIDATION_ERROR);
  });

  // ==============================================================================
  // 5. Acceptance: Cross-User Access Isolation
  // ==============================================================================

  it('enforces cross-user isolation: Customer B cannot add note, message, or attachment to Customer A order', async () => {
    // 1. Customer B attempts to add note to Customer A order
    const noteReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/notes`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ note: 'Intruder note from Customer B' }),
    });
    const noteRes = await addCustomOrderNote(noteReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(noteRes.status).toBe(403);

    // 2. Customer B attempts to add message to Customer A order
    const msgReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ message: 'Intruder message from Customer B' }),
    });
    const msgRes = await addCustomOrderMessage(msgReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(msgRes.status).toBe(403);

    // 3. Customer B attempts to upload attachment to Customer A order
    const attReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        storagePath: `custom-orders/${customerBId}/intruder.jpg`,
        fileName: 'intruder.jpg',
        mimeType: 'image/jpeg',
        size: 1024,
      }),
    });
    const attRes = await addAttachment(attReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(attRes.status).toBe(403);

    // 4. Customer B attempts to withdraw Customer A order
    const withdrawReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/withdraw`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerBToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason: 'Malicious withdrawal attempt' }),
    });
    const withdrawRes = await withdrawCustomOrder(withdrawReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(withdrawRes.status).toBe(403);
  });

  // ==============================================================================
  // 6. Customer Follow-up Notes & Messages Flow
  // ==============================================================================

  it('allows Customer A to add a follow-up note and message to their custom order', async () => {
    // 1. Customer adds note via /notes
    const noteText = 'Can we arrange a secondary fitting for sleeve pitch adjustments?';
    const noteReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/notes`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ note: noteText }),
    });
    const noteRes = await addCustomOrderNote(noteReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(noteRes.status).toBe(200);

    const noteBody = await noteRes.json();
    expect(noteBody.success).toBe(true);
    expect(noteBody.data.notes).toContain(noteText);

    // 2. Customer adds message via /messages
    const msgText = 'Please ensure horn buttons with matte finish are utilized.';
    const msgReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ message: msgText }),
    });
    const msgRes = await addCustomOrderMessage(msgReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(msgRes.status).toBe(200);

    const msgBody = await msgRes.json();
    expect(msgBody.success).toBe(true);
    expect(msgBody.data.notes).toContain(msgText);
  });

  // ==============================================================================
  // 7. Customer Request Withdrawal Lifecycle
  // ==============================================================================

  it('allows Customer A to withdraw their custom suit request before production', async () => {
    const reasonText = 'Event moved to next spring; will re-book closer to date.';
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/withdraw`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason: reasonText }),
    });

    const res = await withdrawCustomOrder(req, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.status).toBe(CustomOrderStatus.REJECTED);

    // Status history includes withdrawal note
    const latestHistory = body.data.statusHistory[0];
    expect(latestHistory.toStatus).toBe(CustomOrderStatus.REJECTED);
    expect(latestHistory.note).toContain(reasonText);

    // Second withdrawal attempt rejected as already closed
    const repeatReq = new NextRequest(`http://localhost:3000/api/custom-orders/${createdCustomOrderId}/withdraw`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
        'Content-Type': 'application/json',
      },
    });
    const repeatRes = await withdrawCustomOrder(repeatReq, { params: Promise.resolve({ id: createdCustomOrderId }) });
    expect(repeatRes.status).toBe(409);
    const repeatBody = await repeatRes.json();
    expect(repeatBody.error.code).toBe(ErrorCode.CONFLICT);
  });

  it('prevents customer from withdrawing an order once in production via POST /withdraw', async () => {
    // 1. Create a fresh order and place it into IN_PRODUCTION
    const prodOrder = await prisma.customOrder.create({
      data: {
        orderNumber: `CO-PROD-${Date.now()}`,
        profileId: customerAId,
        description: 'Bespoke cashmere overcoat in production',
        status: CustomOrderStatus.IN_PRODUCTION,
      },
    });
    createdOrderIds.push(prodOrder.id);

    // 2. Customer A attempts withdrawal via POST /api/custom-orders/[id]/withdraw
    const req = new NextRequest(`http://localhost:3000/api/custom-orders/${prodOrder.id}/withdraw`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${customerAToken}`,
      },
    });

    const res = await withdrawCustomOrder(req, { params: Promise.resolve({ id: prodOrder.id }) });
    expect(res.status).toBe(409);

    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe(ErrorCode.CONFLICT);
  });
});

