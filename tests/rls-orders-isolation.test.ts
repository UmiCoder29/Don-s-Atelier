import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { prisma } from '@/lib/db/prisma';
import { createSupabaseUserClient, supabaseAdmin } from '@/lib/db/supabase';
import { env } from '@/lib/validation/env';
import { generateOrderNumber } from '@/lib/crypto';
import { OrderStatus } from '@prisma/client';

describe('Supabase Row Level Security (RLS) - Order Isolation Acceptance', () => {
  const customerAEmail = 'james.harrington@example.com';
  const customerBEmail = 'clara.beaumont@example.com';
  const customerPassword = process.env.SEED_CUSTOMER_PASSWORD || 'DonAtelierCustomer2026!Secure';

  let customerAToken: string;
  let customerBToken: string;
  let customerAProfileId: string;
  let customerBProfileId: string;
  let customerAOrderId: string;
  let customerBOrderId: string;

  beforeAll(async () => {
    // 1. Authenticate Customer A against Supabase Auth
    const { data: authDataA, error: authErrorA } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerAEmail,
      password: customerPassword,
    });

    if (authErrorA || !authDataA.session) {
      throw new Error(`Failed to sign in customer A: ${authErrorA?.message}`);
    }
    customerAToken = authDataA.session.access_token;
    customerAProfileId = authDataA.user.id;

    // 2. Authenticate Customer B against Supabase Auth
    const { data: authDataB, error: authErrorB } = await createSupabaseUserClient().auth.signInWithPassword({
      email: customerBEmail,
      password: customerPassword,
    });

    if (authErrorB || !authDataB.session) {
      throw new Error(`Failed to sign in customer B: ${authErrorB?.message}`);
    }
    customerBToken = authDataB.session.access_token;
    customerBProfileId = authDataB.user.id;

    // 3. Create a test order for Customer A (using Prisma server client)
    const orderA = await prisma.order.create({
      data: {
        orderNumber: generateOrderNumber(),
        profileId: customerAProfileId,
        status: OrderStatus.PAID,
        subtotalInCents: 185000,
        shippingInCents: 0,
        totalInCents: 185000,
        shippingAddress: {
          recipientName: 'James Harrington',
          line1: '10 Savile Row',
          city: 'London',
          state: 'Greater London',
          postalCode: 'W1S 3PB',
          country: 'GB',
        },
      },
    });
    customerAOrderId = orderA.id;

    // 4. Create a test order for Customer B
    const orderB = await prisma.order.create({
      data: {
        orderNumber: generateOrderNumber(),
        profileId: customerBProfileId,
        status: OrderStatus.PROCESSING,
        subtotalInCents: 145000,
        shippingInCents: 2500,
        totalInCents: 147500,
        shippingAddress: {
          recipientName: 'Clara Beaumont',
          line1: '25 Place Vendome',
          city: 'Paris',
          state: 'Ile-de-France',
          postalCode: '75001',
          country: 'FR',
        },
      },
    });
    customerBOrderId = orderB.id;

    // 5. Create test OrderStatusHistory records
    await prisma.orderStatusHistory.create({
      data: {
        orderId: customerAOrderId,
        fromStatus: OrderStatus.PENDING,
        toStatus: OrderStatus.PAID,
        changedBy: customerAProfileId,
        note: 'Initial payment confirmation for Customer A',
      },
    });

    await prisma.orderStatusHistory.create({
      data: {
        orderId: customerBOrderId,
        fromStatus: OrderStatus.PENDING,
        toStatus: OrderStatus.PROCESSING,
        changedBy: customerBProfileId,
        note: 'Processing start for Customer B',
      },
    });

    // 6. Create test ProcessedWebhookEvent record (server-only table)
    await prisma.processedWebhookEvent.create({
      data: {
        provider: 'mock_stripe',
        eventId: 'evt_rls_test_123',
        eventType: 'payment_intent.succeeded',
      },
    });
  });

  afterAll(async () => {
    // Clean up created orders, status history, and webhook events
    await prisma.processedWebhookEvent.deleteMany({
      where: { eventId: 'evt_rls_test_123' },
    });
    if (customerAOrderId || customerBOrderId) {
      await prisma.orderStatusHistory.deleteMany({
        where: { orderId: { in: [customerAOrderId, customerBOrderId].filter(Boolean) } },
      });
      await prisma.order.deleteMany({
        where: { id: { in: [customerAOrderId, customerBOrderId].filter(Boolean) } },
      });
    }
  });

  it('ACCEPTANCE: Customer B CANNOT read Customer A order via Supabase client directly (permission denied 42501)', async () => {
    // Instantiate Supabase client acting as Customer B with their authenticated JWT
    const supabaseClientB = createSupabaseUserClient(customerBToken);

    // Customer B attempts to directly query Customer A's order by ID
    const { data: targetOrderData, error } = await supabaseClientB
      .from('orders')
      .select('*')
      .eq('id', customerAOrderId);

    // Direct table SELECT revoked: PostgREST returns 42501 permission denied
    expect(error).toBeDefined();
    expect(error?.code).toBe('42501');
    expect(targetOrderData).toBeNull();
  });

  it('Customer B CANNOT read orders directly via Supabase client (all reads must go through server API)', async () => {
    const supabaseClientB = createSupabaseUserClient(customerBToken);

    const { data, error } = await supabaseClientB
      .from('orders')
      .select('*')
      .eq('id', customerBOrderId);

    expect(error).toBeDefined();
    expect(error?.code).toBe('42501');
    expect(data).toBeNull();
  });

  it('Customer A CANNOT read orders directly via Supabase client (all reads must go through server API)', async () => {
    const supabaseClientA = createSupabaseUserClient(customerAToken);

    const { data, error } = await supabaseClientA
      .from('orders')
      .select('*')
      .eq('id', customerAOrderId);

    expect(error).toBeDefined();
    expect(error?.code).toBe('42501');
    expect(data).toBeNull();
  });

  it('Customer A CANNOT read Customer B order via Supabase client directly (permission denied 42501)', async () => {
    const supabaseClientA = createSupabaseUserClient(customerAToken);

    const { data, error } = await supabaseClientA
      .from('orders')
      .select('*')
      .eq('id', customerBOrderId);

    expect(error).toBeDefined();
    expect(error?.code).toBe('42501');
    expect(data).toBeNull();
  });

  it('Unauthenticated anonymous client CANNOT read any orders via Supabase client directly (permission denied 42501)', async () => {
    const anonClient = createSupabaseUserClient(); // No auth JWT provided

    const { data, error } = await anonClient
      .from('orders')
      .select('*');

    expect(error).toBeDefined();
    expect(error?.code).toBe('42501');
    expect(data).toBeNull();
  });

  it('Public catalog items (categories, active products) ARE readable by unauthenticated client, while inactive products are hidden', async () => {
    const anonClient = createSupabaseUserClient();

    // 1. Categories are readable
    const { data: categories, error: catError } = await anonClient
      .from('categories')
      .select('name, slug');

    expect(catError).toBeNull();
    expect(categories!.length).toBeGreaterThanOrEqual(5);

    // 2. Active products are readable
    const { data: products, error: prodError } = await anonClient
      .from('products')
      .select('name, brand, status')
      .eq('status', 'ACTIVE');

    expect(prodError).toBeNull();
    expect(products!.length).toBeGreaterThanOrEqual(12);
    expect(products![0].brand).toBe("Don's Atelier");

    // 3. Create an inactive product to assert anon cannot read inactive ones
    const inactiveProduct = await prisma.product.create({
      data: {
        name: `Inactive Hidden Suit Test ${Date.now()}`,
        slug: `inactive-hidden-suit-${Date.now()}`,
        description: 'Test inactive suit for RLS isolation',
        categoryId: (await prisma.category.findFirstOrThrow()).id,
        fabric: '100% Wool',
        fit: 'Slim Fit',
        status: 'ARCHIVED',
      },
    });

    try {
      const { data: hiddenData, error: hiddenError } = await anonClient
        .from('products')
        .select('*')
        .eq('id', inactiveProduct.id);

      expect(hiddenError).toBeNull();
      // RLS policy products_select_active_or_admin hides non-ACTIVE products from anon (0 rows returned)
      expect(hiddenData).toHaveLength(0);
    } finally {
      await prisma.product.delete({ where: { id: inactiveProduct.id } }).catch(() => {});
    }
  });

  describe('order_status_history RLS Isolation', () => {
    it('Customer A CANNOT read order status history via direct Supabase client (permission denied 42501)', async () => {
      const supabaseClientA = createSupabaseUserClient(customerAToken);

      const { data, error } = await supabaseClientA
        .from('order_status_history')
        .select('*')
        .eq('orderId', customerAOrderId);

      expect(error).toBeDefined();
      expect(error?.code).toBe('42501');
      expect(data).toBeNull();
    });

    it('Customer B CANNOT read Customer A order status history (permission denied 42501)', async () => {
      const supabaseClientB = createSupabaseUserClient(customerBToken);

      const { data, error } = await supabaseClientB
        .from('order_status_history')
        .select('*')
        .eq('orderId', customerAOrderId);

      expect(error).toBeDefined();
      expect(error?.code).toBe('42501');
      expect(data).toBeNull();
    });

    it('Customer CANNOT insert into order_status_history via client (no client write policy)', async () => {
      const supabaseClientA = createSupabaseUserClient(customerAToken);

      const { data, error } = await supabaseClientA
        .from('order_status_history')
        .insert({
          orderId: customerAOrderId,
          toStatus: 'DELIVERED',
          changedBy: customerAProfileId,
        })
        .select();

      // Client write must fail with RLS violation error or return 0 inserted rows
      expect(error !== null || !data || data.length === 0).toBe(true);
    });
  });

  describe('processed_webhook_events RLS Isolation (Server-Only Table)', () => {
    it('Customer A CANNOT read processed_webhook_events (RLS with zero policies)', async () => {
      const supabaseClientA = createSupabaseUserClient(customerAToken);

      const { data, error } = await supabaseClientA
        .from('processed_webhook_events')
        .select('*');

      // Table has REVOKE ALL from authenticated, so PostgREST returns 42501 permission denied or empty rows
      expect(error !== null || !data || data.length === 0).toBe(true);
    });

    it('Customer B CANNOT read processed_webhook_events', async () => {
      const supabaseClientB = createSupabaseUserClient(customerBToken);

      const { data, error } = await supabaseClientB
        .from('processed_webhook_events')
        .select('*');

      // Table has REVOKE ALL from authenticated, so PostgREST returns 42501 permission denied or empty rows
      expect(error !== null || !data || data.length === 0).toBe(true);
    });

    it('Unauthenticated client CANNOT read processed_webhook_events', async () => {
      const anonClient = createSupabaseUserClient();

      const { data, error } = await anonClient
        .from('processed_webhook_events')
        .select('*');

      // Table has REVOKE ALL from anon, so PostgREST returns 42501 permission denied or empty rows
      expect(error !== null || !data || data.length === 0).toBe(true);
    });

    it('Client CANNOT insert into processed_webhook_events directly', async () => {
      const supabaseClientA = createSupabaseUserClient(customerAToken);

      const { data, error } = await supabaseClientA
        .from('processed_webhook_events')
        .insert({
          provider: 'mock_stripe',
          eventId: 'evt_client_forged_123',
          eventType: 'payment_intent.succeeded',
        })
        .select();

      expect(error !== null || !data || data.length === 0).toBe(true);
    });
  });

  describe('Direct Client Write Attacks Lockdown (Server-Authoritative Writes Only)', () => {
    it('DEFENSE IN DEPTH: customer A client CANNOT directly SELECT orders or profiles (42501 permission denied)', async () => {
      const clientA = createSupabaseUserClient(customerAToken);

      // Customer A direct read on orders is blocked at the table grant level
      const { data: orderData, error: orderError } = await clientA
        .from('orders')
        .select('*')
        .eq('id', customerAOrderId);

      expect(orderError).toBeDefined();
      expect(orderError?.code).toBe('42501');
      expect(orderData).toBeNull();

      // Customer A direct read on profiles is blocked at the table grant level
      const { data: profileData, error: profileError } = await clientA
        .from('profiles')
        .select('*')
        .eq('id', customerAProfileId);

      expect(profileError).toBeDefined();
      expect(profileError?.code).toBe('42501');
      expect(profileData).toBeNull();
    });

    it('rejects customer from directly setting own profiles.role to ADMIN', async () => {
      const clientA = createSupabaseUserClient(customerAToken);
      const { data, error } = await clientA
        .from('profiles')
        .update({ role: 'ADMIN' })
        .eq('id', customerAProfileId)
        .select();

      expect(error !== null || !data || data.length === 0).toBe(true);

      // Re-read with Prisma to verify role is still CUSTOMER
      const profile = await prisma.profile.findUnique({
        where: { id: customerAProfileId },
      });
      expect(profile!.role).toBe('CUSTOMER');
    });

    it('rejects customer from updating own order status and totalInCents', async () => {
      const clientA = createSupabaseUserClient(customerAToken);
      const { data, error } = await clientA
        .from('orders')
        .update({ status: 'DELIVERED', totalInCents: 0 })
        .eq('id', customerAOrderId)
        .select();

      expect(error !== null || !data || data.length === 0).toBe(true);

      // Re-read with Prisma to verify order is unchanged
      const order = await prisma.order.findUnique({
        where: { id: customerAOrderId },
      });
      expect(order!.status).toBe(OrderStatus.PAID);
      expect(order!.totalInCents).toBe(185000);
    });

    it('rejects customer from directly inserting an order', async () => {
      const clientA = createSupabaseUserClient(customerAToken);
      const attackOrderNumber = `ATTACK-${Date.now()}`;
      const { data, error } = await clientA
        .from('orders')
        .insert({
          orderNumber: attackOrderNumber,
          profileId: customerAProfileId,
          status: 'PAID',
          subtotalInCents: 0,
          shippingInCents: 0,
          totalInCents: 0,
        })
        .select();

      expect(error !== null || !data || data.length === 0).toBe(true);

      // Re-read with Prisma to prove no such order exists
      const forgedOrder = await prisma.order.findUnique({
        where: { orderNumber: attackOrderNumber },
      });
      expect(forgedOrder).toBeNull();
    });

    it('rejects customer from directly inserting order_items', async () => {
      const clientA = createSupabaseUserClient(customerAToken);
      const fakeItemId = '00000000-0000-0000-0000-000000000001';
      const { data, error } = await clientA
        .from('order_items')
        .insert({
          orderId: customerAOrderId,
          productVariantId: fakeItemId,
          quantity: 99,
          unitPriceInCents: 0,
          totalPriceInCents: 0,
        })
        .select();

      expect(error !== null || !data || data.length === 0).toBe(true);

      const items = await prisma.orderItem.findMany({
        where: { orderId: customerAOrderId },
      });
      expect(items.some((i) => i.quantity === 99)).toBe(false);
    });

    it('rejects customer from updating own custom_orders quote or status', async () => {
      const customOrder = await prisma.customOrder.create({
        data: {
          orderNumber: `CO-ATTACK-${Date.now()}`,
          profileId: customerAProfileId,
          description: 'Direct attack probe bespoke suit',
          status: 'SUBMITTED',
        },
      });

      try {
        const clientA = createSupabaseUserClient(customerAToken);
        const { data, error } = await clientA
          .from('custom_orders')
          .update({ status: 'ACCEPTED', quotedPriceInCents: 100 })
          .eq('id', customOrder.id)
          .select();

        expect(error !== null || !data || data.length === 0).toBe(true);

        const freshCustom = await prisma.customOrder.findUnique({
          where: { id: customOrder.id },
        });
        expect(freshCustom!.status).toBe('SUBMITTED');
        expect(freshCustom!.quotedPriceInCents).toBeNull();
      } finally {
        await prisma.customOrder.delete({ where: { id: customOrder.id } }).catch(() => {});
      }
    });

    it('rejects customer from directly inserting or updating measurements', async () => {
      const customOrder = await prisma.customOrder.create({
        data: {
          orderNumber: `CO-MEAS-${Date.now()}`,
          profileId: customerAProfileId,
          description: 'Measurement attack probe bespoke suit',
          status: 'SUBMITTED',
        },
      });

      const measurement = await prisma.measurement.create({
        data: {
          customOrderId: customOrder.id,
          key: 'chest',
          value: '40',
          unit: 'inches',
        },
      });

      try {
        const clientA = createSupabaseUserClient(customerAToken);

        // 1. Direct update attempt
        const updateRes = await clientA
          .from('measurements')
          .update({ value: '99' })
          .eq('id', measurement.id)
          .select();
        expect(updateRes.error !== null || !updateRes.data || updateRes.data.length === 0).toBe(true);

        // 2. Direct insert attempt
        const insertRes = await clientA
          .from('measurements')
          .insert({
            customOrderId: customOrder.id,
            key: 'waist',
            value: '99',
            unit: 'inches',
          })
          .select();
        expect(insertRes.error !== null || !insertRes.data || insertRes.data.length === 0).toBe(true);

        // Re-read with Prisma
        const fresh = await prisma.measurement.findUnique({ where: { id: measurement.id } });
        expect(fresh!.value).toBe('40');

        const forged = await prisma.measurement.findFirst({
          where: { customOrderId: customOrder.id, key: 'waist' },
        });
        expect(forged).toBeNull();
      } finally {
        await prisma.customOrder.delete({ where: { id: customOrder.id } }).catch(() => {});
      }
    });

    it('rejects customer from directly inserting or updating addresses', async () => {
      const address = await prisma.address.create({
        data: {
          profileId: customerAProfileId,
          recipientName: 'Original Recipient',
          line1: '10 Savile Row',
          city: 'London',
          state: 'Greater London',
          postalCode: 'W1S 3PB',
          country: 'GB',
        },
      });

      try {
        const clientA = createSupabaseUserClient(customerAToken);

        // Direct update attempt
        const updateRes = await clientA
          .from('addresses')
          .update({ recipientName: 'Tampered Hacker' })
          .eq('id', address.id)
          .select();
        expect(updateRes.error !== null || !updateRes.data || updateRes.data.length === 0).toBe(true);

        // Direct insert attempt
        const insertRes = await clientA
          .from('addresses')
          .insert({
            profileId: customerAProfileId,
            recipientName: 'Direct Forged Address',
            line1: 'Fake Alley',
            city: 'Nowhere',
            state: 'None',
            postalCode: '00000',
            country: 'GB',
          })
          .select();
        expect(insertRes.error !== null || !insertRes.data || insertRes.data.length === 0).toBe(true);

        // Re-read with Prisma
        const fresh = await prisma.address.findUnique({ where: { id: address.id } });
        expect(fresh!.recipientName).toBe('Original Recipient');

        const forged = await prisma.address.findFirst({ where: { recipientName: 'Direct Forged Address' } });
        expect(forged).toBeNull();
      } finally {
        await prisma.address.delete({ where: { id: address.id } }).catch(() => {});
      }
    });

    it('rejects customer from directly inserting or updating cart_items', async () => {
      const cart = await prisma.cart.upsert({
        where: { profileId: customerAProfileId },
        create: { profileId: customerAProfileId },
        update: {},
      });

      const variant = await prisma.productVariant.findFirst({ where: { active: true } });
      if (!variant) throw new Error('Active variant required');

      const cartItem = await prisma.cartItem.upsert({
        where: {
          cartId_productVariantId: {
            cartId: cart.id,
            productVariantId: variant.id,
          },
        },
        create: {
          cartId: cart.id,
          productVariantId: variant.id,
          quantity: 1,
        },
        update: {
          quantity: 1,
        },
      });

      try {
        const clientA = createSupabaseUserClient(customerAToken);

        // Direct update attempt
        const updateRes = await clientA
          .from('cart_items')
          .update({ quantity: 999 })
          .eq('id', cartItem.id)
          .select();
        expect(updateRes.error !== null || !updateRes.data || updateRes.data.length === 0).toBe(true);

        // Direct insert attempt
        const insertRes = await clientA
          .from('cart_items')
          .insert({
            cartId: cart.id,
            productVariantId: variant.id,
            quantity: 50,
          })
          .select();
        expect(insertRes.error !== null || !insertRes.data || insertRes.data.length === 0).toBe(true);

        // Re-read with Prisma
        const fresh = await prisma.cartItem.findUnique({ where: { id: cartItem.id } });
        expect(fresh!.quantity).toBe(1);
      } finally {
        await prisma.cartItem.delete({ where: { id: cartItem.id } }).catch(() => {});
      }
    });
  });
});

