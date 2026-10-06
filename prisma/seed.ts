import { PrismaClient, Role, ProductStatus } from '@prisma/client';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

// Node 20 compatibility: SupabaseClient checks for WebSocket constructor
if (typeof globalThis.WebSocket === 'undefined') {
  // @ts-expect-error fallback placeholder for environments without realtime ws
  globalThis.WebSocket = class WebSocketDummy {};
}

// Enforce non-negotiable rule: Passwords must come from environment variables, never hardcoded
const adminPassword = process.env.SEED_ADMIN_PASSWORD;
const customerPassword = process.env.SEED_CUSTOMER_PASSWORD;

if (!adminPassword) {
  throw new Error(
    'CRITICAL SECURITY ERROR: SEED_ADMIN_PASSWORD environment variable is missing. ' +
    'Passwords must be configured in .env and never hardcoded in source code.'
  );
}

if (!customerPassword) {
  throw new Error(
    'CRITICAL SECURITY ERROR: SEED_CUSTOMER_PASSWORD environment variable is missing. ' +
    'Passwords must be configured in .env and never hardcoded in source code.'
  );
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceRoleKey) {
  throw new Error('CRITICAL ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env');
}

// Service role Supabase client for administrative provisioning of auth users
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Database pooler or direct connection
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DIRECT_URL || process.env.DATABASE_URL,
    },
  },
});

interface SeedUser {
  email: string;
  name: string;
  role: Role;
  password: string;
}

const SEED_USERS: SeedUser[] = [
  {
    email: 'admin@dons-atelier.com',
    name: "Don's Master Tailor",
    role: Role.ADMIN,
    password: adminPassword,
  },
  {
    email: 'james.harrington@example.com',
    name: 'James Harrington',
    role: Role.CUSTOMER,
    password: customerPassword,
  },
  {
    email: 'clara.beaumont@example.com',
    name: 'Clara Beaumont',
    role: Role.CUSTOMER,
    password: customerPassword,
  },
];

const SEED_CATEGORIES = [
  {
    name: 'Tuxedos & Black Tie',
    slug: 'tuxedos-black-tie',
    description: "Exquisite evening wear, silk-faced lapels, and bespoke formal attire by Don's Atelier.",
  },
  {
    name: 'Business Classic',
    slug: 'business-classic',
    description: "Impeccably structured two-piece and three-piece suits crafted from Super 150s Merino wool.",
  },
  {
    name: 'Bespoke Contemporary',
    slug: 'bespoke-contemporary',
    description: "Modern soft-tailored cuts and breathable wool-silk fabrics for discerning sartorialists.",
  },
  {
    name: 'Seasonal & Linen',
    slug: 'seasonal-linen',
    description: "Lightweight Irish linen and unlined summer tailoring, handcrafted for warm climates.",
  },
  {
    name: 'Evening & Velvet',
    slug: 'evening-velvet',
    description: "Opulent Italian velvet smoking jackets and midnight ceremonial jackets with silk grosgrain trim.",
  },
];

interface VariantSeed {
  size: string;
  color: string;
  sku: string;
  priceInCents: number;
  stockQuantity: number;
}

interface ProductSeed {
  categorySlug: string;
  name: string;
  slug: string;
  description: string;
  fabric: string;
  fit: string;
  images: Array<{ storagePath: string; altText: string; sortOrder: number }>;
  variants: VariantSeed[];
}

const SEED_PRODUCTS: ProductSeed[] = [
  // Category 1: Tuxedos & Black Tie (3 suits)
  {
    categorySlug: 'tuxedos-black-tie',
    name: 'The Mayfair Peak Lapel Tuxedo',
    slug: 'the-mayfair-peak-lapel-tuxedo',
    description: "Handcrafted by Don's Atelier from Super 160s barathea wool, featuring pure mulberry silk grosgrain peak lapels and covered buttons.",
    fabric: 'Super 160s English Barathea Wool & Mulberry Silk',
    fit: 'Slim Fit',
    images: [
      { storagePath: 'catalog/mayfair-tuxedo-front.webp', altText: "Don's Atelier Mayfair Peak Lapel Tuxedo Front View", sortOrder: 0 },
      { storagePath: 'catalog/mayfair-tuxedo-lapel.webp', altText: "Don's Atelier Mayfair Lapel Detail", sortOrder: 1 },
    ],
    variants: [
      { size: '38R', color: 'Midnight Navy', sku: 'DA-MAYFAIR-NVY-38R', priceInCents: 185000, stockQuantity: 6 },
      { size: '40R', color: 'Midnight Navy', sku: 'DA-MAYFAIR-NVY-40R', priceInCents: 185000, stockQuantity: 10 },
      { size: '42R', color: 'Midnight Navy', sku: 'DA-MAYFAIR-NVY-42R', priceInCents: 185000, stockQuantity: 8 },
      { size: '44L', color: 'Midnight Navy', sku: 'DA-MAYFAIR-NVY-44L', priceInCents: 195000, stockQuantity: 4 },
    ],
  },
  {
    categorySlug: 'tuxedos-black-tie',
    name: 'The Savoy Shawl Collar Dinner Suit',
    slug: 'the-savoy-shawl-collar-dinner-suit',
    description: "Classic black-tie grandeur from Don's Atelier. Single-button silhouette with a soft curved silk shawl collar and braided trouser outseams.",
    fabric: 'Super 150s Worsted Wool & Satin Silk',
    fit: 'Classic Fit',
    images: [
      { storagePath: 'catalog/savoy-dinner-suit-front.webp', altText: "Don's Atelier Savoy Dinner Suit Front", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Obsidian Black', sku: 'DA-SAVOY-BLK-38R', priceInCents: 175000, stockQuantity: 7 },
      { size: '40R', color: 'Obsidian Black', sku: 'DA-SAVOY-BLK-40R', priceInCents: 175000, stockQuantity: 12 },
      { size: '42R', color: 'Obsidian Black', sku: 'DA-SAVOY-BLK-42R', priceInCents: 175000, stockQuantity: 9 },
    ],
  },
  {
    categorySlug: 'tuxedos-black-tie',
    name: 'The Monte Carlo Ivory Dinner Suit',
    slug: 'the-monte-carlo-ivory-dinner-suit',
    description: "Distinguished warm-climate formalwear with an ivory dinner jacket and contrasting jet-black wool trousers by Don's Atelier.",
    fabric: 'Tropical Weave Merino Wool & Silk Faille',
    fit: 'Modern Fit',
    images: [
      { storagePath: 'catalog/monte-carlo-front.webp', altText: "Don's Atelier Monte Carlo Dinner Suit Front", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Ivory & Black', sku: 'DA-MC-IVO-38R', priceInCents: 195000, stockQuantity: 5 },
      { size: '40R', color: 'Ivory & Black', sku: 'DA-MC-IVO-40R', priceInCents: 195000, stockQuantity: 8 },
      { size: '42R', color: 'Ivory & Black', sku: 'DA-MC-IVO-42R', priceInCents: 195000, stockQuantity: 6 },
    ],
  },

  // Category 2: Business Classic (3 suits)
  {
    categorySlug: 'business-classic',
    name: 'The Regent Navy Pinstripe Two-Piece',
    slug: 'the-regent-navy-pinstripe-two-piece',
    description: "Command the boardroom with Don's Atelier's iconic navy pinstripe suit, cut with roped shoulders and natural horn buttons.",
    fabric: 'Super 140s Wool Chalkstripe',
    fit: 'Classic Fit',
    images: [
      { storagePath: 'catalog/regent-navy-front.webp', altText: "Don's Atelier Regent Pinstripe Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Navy Chalkstripe', sku: 'DA-REGENT-NVY-38R', priceInCents: 145000, stockQuantity: 9 },
      { size: '40R', color: 'Navy Chalkstripe', sku: 'DA-REGENT-NVY-40R', priceInCents: 145000, stockQuantity: 14 },
      { size: '42R', color: 'Navy Chalkstripe', sku: 'DA-REGENT-NVY-42R', priceInCents: 145000, stockQuantity: 11 },
      { size: '44R', color: 'Navy Chalkstripe', sku: 'DA-REGENT-NVY-44R', priceInCents: 145000, stockQuantity: 5 },
    ],
  },
  {
    categorySlug: 'business-classic',
    name: 'The Westminster Charcoal Three-Piece Suit',
    slug: 'the-westminster-charcoal-three-piece-suit',
    description: "A commanding three-piece ensemble including tailored matching vest. Tailored by Don's Atelier from durable four-season twill.",
    fabric: 'Super 150s Australian Merino Wool Twill',
    fit: 'Modern Fit',
    images: [
      { storagePath: 'catalog/westminster-charcoal-front.webp', altText: "Don's Atelier Westminster Three-Piece Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Charcoal Grey', sku: 'DA-WEST-CH-38R', priceInCents: 165000, stockQuantity: 8 },
      { size: '40R', color: 'Charcoal Grey', sku: 'DA-WEST-CH-40R', priceInCents: 165000, stockQuantity: 15 },
      { size: '42R', color: 'Charcoal Grey', sku: 'DA-WEST-CH-42R', priceInCents: 165000, stockQuantity: 10 },
    ],
  },
  {
    categorySlug: 'business-classic',
    name: 'The Knightsbridge Oxford Blue Herringbone',
    slug: 'the-knightsbridge-oxford-blue-herringbone',
    description: "Subtle micro-herringbone weave provides sophisticated texture in this quintessential Don's Atelier city suit.",
    fabric: 'Super 130s English Mill Wool Herringbone',
    fit: 'Slim Fit',
    images: [
      { storagePath: 'catalog/knightsbridge-blue-front.webp', altText: "Don's Atelier Knightsbridge Herringbone Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Oxford Blue', sku: 'DA-KB-BLU-38R', priceInCents: 135000, stockQuantity: 10 },
      { size: '40R', color: 'Oxford Blue', sku: 'DA-KB-BLU-40R', priceInCents: 135000, stockQuantity: 12 },
      { size: '42R', color: 'Oxford Blue', sku: 'DA-KB-BLU-42R', priceInCents: 135000, stockQuantity: 8 },
    ],
  },

  // Category 3: Bespoke Contemporary (2 suits)
  {
    categorySlug: 'bespoke-contemporary',
    name: 'The Belgravia Unstructured Wool Suit',
    slug: 'the-belgravia-unstructured-wool-suit',
    description: "Neapolitan-inspired soft shoulder construction with patch pockets. Modern Italian luxury redefined by Don's Atelier.",
    fabric: 'High-Twist Wool & Silk Fresco',
    fit: 'Slim Fit',
    images: [
      { storagePath: 'catalog/belgravia-green-front.webp', altText: "Don's Atelier Belgravia Unstructured Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Forest Green', sku: 'DA-BEL-GRN-38R', priceInCents: 155000, stockQuantity: 6 },
      { size: '40R', color: 'Forest Green', sku: 'DA-BEL-GRN-40R', priceInCents: 155000, stockQuantity: 9 },
      { size: '42R', color: 'Forest Green', sku: 'DA-BEL-GRN-42R', priceInCents: 155000, stockQuantity: 7 },
    ],
  },
  {
    categorySlug: 'bespoke-contemporary',
    name: 'The Chelsea Double-Breasted Flannel Suit',
    slug: 'the-chelsea-double-breasted-flannel-suit',
    description: "6x2 button stance with broad peak lapels and ticket pocket. An aristocratic statement piece from Don's Atelier.",
    fabric: 'Fox Brothers Wool Flannel',
    fit: 'Classic Fit',
    images: [
      { storagePath: 'catalog/chelsea-tan-front.webp', altText: "Don's Atelier Chelsea Double-Breasted Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Camel Tan', sku: 'DA-CHEL-TAN-38R', priceInCents: 170000, stockQuantity: 5 },
      { size: '40R', color: 'Camel Tan', sku: 'DA-CHEL-TAN-40R', priceInCents: 170000, stockQuantity: 8 },
      { size: '42R', color: 'Camel Tan', sku: 'DA-CHEL-TAN-42R', priceInCents: 170000, stockQuantity: 6 },
    ],
  },

  // Category 4: Seasonal & Linen (2 suits)
  {
    categorySlug: 'seasonal-linen',
    name: 'The Portofino Pure Irish Linen Suit',
    slug: 'the-portofino-pure-irish-linen-suit',
    description: "Breathable heavy Irish linen that develops effortless drape with every wear. Unlined jacket for maximum summer air flow.",
    fabric: 'Spence Bryson Pure Irish Linen',
    fit: 'Modern Fit',
    images: [
      { storagePath: 'catalog/portofino-linen-front.webp', altText: "Don's Atelier Portofino Linen Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Sand Dune', sku: 'DA-PORTO-SND-38R', priceInCents: 125000, stockQuantity: 8 },
      { size: '40R', color: 'Sand Dune', sku: 'DA-PORTO-SND-40R', priceInCents: 125000, stockQuantity: 12 },
      { size: '42R', color: 'Sand Dune', sku: 'DA-PORTO-SND-42R', priceInCents: 125000, stockQuantity: 10 },
      { size: '44R', color: 'Sand Dune', sku: 'DA-PORTO-SND-44R', priceInCents: 125000, stockQuantity: 4 },
    ],
  },
  {
    categorySlug: 'seasonal-linen',
    name: 'The Amalfi Wool-Silk-Linen Blend Suit',
    slug: 'the-amalfi-wool-silk-linen-blend-suit',
    description: "The Holy Trinity of summer fabrics: wool for wrinkle resistance, silk for sheen, and linen for ventilation. Handcrafted by Don's Atelier.",
    fabric: 'Loro Piana Wool-Silk-Linen Blend',
    fit: 'Slim Fit',
    images: [
      { storagePath: 'catalog/amalfi-blue-front.webp', altText: "Don's Atelier Amalfi Summer Blend Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Amalfi Blue', sku: 'DA-AMALFI-BLU-38R', priceInCents: 160000, stockQuantity: 6 },
      { size: '40R', color: 'Amalfi Blue', sku: 'DA-AMALFI-BLU-40R', priceInCents: 160000, stockQuantity: 10 },
      { size: '42R', color: 'Amalfi Blue', sku: 'DA-AMALFI-BLU-42R', priceInCents: 160000, stockQuantity: 7 },
    ],
  },

  // Category 5: Evening & Velvet (2 suits)
  {
    categorySlug: 'evening-velvet',
    name: 'The St. James Royal Navy Velvet Tuxedo',
    slug: 'the-st-james-royal-navy-velvet-tuxedo',
    description: "Sumptuous Italian cotton velvet dinner jacket paired with jet-black wool barathea trousers. Pure opulence from Don's Atelier.",
    fabric: 'Pontoglio Cotton Velvet & Worsted Wool',
    fit: 'Slim Fit',
    images: [
      { storagePath: 'catalog/st-james-velvet-front.webp', altText: "Don's Atelier St. James Velvet Dinner Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Royal Navy Velvet', sku: 'DA-STJ-VEL-38R', priceInCents: 210000, stockQuantity: 5 },
      { size: '40R', color: 'Royal Navy Velvet', sku: 'DA-STJ-VEL-40R', priceInCents: 210000, stockQuantity: 7 },
      { size: '42R', color: 'Royal Navy Velvet', sku: 'DA-STJ-VEL-42R', priceInCents: 210000, stockQuantity: 5 },
    ],
  },
  {
    categorySlug: 'evening-velvet',
    name: 'The Burgundy Sovereign Smoking Jacket Suit',
    slug: 'the-burgundy-sovereign-smoking-jacket-suit',
    description: "Deep burgundy velvet with quilted black satin shawl lapels and frog fasteners, finished with side-stripe trousers by Don's Atelier.",
    fabric: 'Italian Deep-Pile Cotton Velvet & Quilted Satin',
    fit: 'Classic Fit',
    images: [
      { storagePath: 'catalog/burgundy-sovereign-front.webp', altText: "Don's Atelier Sovereign Smoking Jacket Suit", sortOrder: 0 },
    ],
    variants: [
      { size: '38R', color: 'Deep Burgundy', sku: 'DA-SOV-BUR-38R', priceInCents: 225000, stockQuantity: 4 },
      { size: '40R', color: 'Deep Burgundy', sku: 'DA-SOV-BUR-40R', priceInCents: 225000, stockQuantity: 6 },
      { size: '42R', color: 'Deep Burgundy', sku: 'DA-SOV-BUR-42R', priceInCents: 225000, stockQuantity: 4 },
    ],
  },
];

async function seedUsers() {
  console.log('--- Provisioning Users in Supabase Auth & Postgres Profiles ---');
  for (const userDef of SEED_USERS) {
    // 1. Create or retrieve user in Supabase Auth
    let authUser: { id: string; email?: string } | null = null;

    // Check if auth user already exists by listing
    const { data: listData, error: listError } = await supabaseAdmin.auth.admin.listUsers();
    if (listError) {
      console.warn(`Could not list Supabase auth users: ${listError.message}`);
    } else {
      authUser = listData.users.find(u => u.email?.toLowerCase() === userDef.email.toLowerCase()) || null;
    }

    if (!authUser) {
      console.log(`Creating Supabase Auth user: ${userDef.email} (${userDef.role})...`);
      const { data: createData, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email: userDef.email,
        password: userDef.password,
        email_confirm: true,
        user_metadata: { name: userDef.name },
      });

      if (createError) {
        throw new Error(`Failed to create Supabase auth user ${userDef.email}: ${createError.message}`);
      }
      authUser = createData.user;
    } else {
      console.log(`Supabase Auth user already exists: ${userDef.email} (id: ${authUser.id}). Updating password...`);
      await supabaseAdmin.auth.admin.updateUserById(authUser.id, {
        password: userDef.password,
        user_metadata: { name: userDef.name },
      });
    }

    // 2. Upsert profile in PostgreSQL
    await prisma.profile.upsert({
      where: { id: authUser.id },
      create: {
        id: authUser.id,
        email: userDef.email,
        name: userDef.name,
        role: userDef.role,
      },
      update: {
        email: userDef.email,
        name: userDef.name,
        role: userDef.role,
      },
    });

    // 3. Ensure a shopping cart exists for customers
    if (userDef.role === Role.CUSTOMER) {
      await prisma.cart.upsert({
        where: { profileId: authUser.id },
        create: { profileId: authUser.id },
        update: {},
      });
    }

    console.log(`✓ Profile ready for ${userDef.email} [${userDef.role}]`);
  }
}

async function seedCatalog() {
  console.log('--- Provisioning Catalog (5 Categories & 12 Suits) ---');

  // Seed Categories
  const categoryMap = new Map<string, string>();
  for (const cat of SEED_CATEGORIES) {
    const record = await prisma.category.upsert({
      where: { slug: cat.slug },
      create: {
        name: cat.name,
        slug: cat.slug,
        description: cat.description,
      },
      update: {
        name: cat.name,
        description: cat.description,
      },
    });
    categoryMap.set(cat.slug, record.id);
    console.log(`✓ Category: ${record.name} (${record.slug})`);
  }

  // Seed 12 Suits & Variants
  for (const productData of SEED_PRODUCTS) {
    const categoryId = categoryMap.get(productData.categorySlug);
    if (!categoryId) {
      throw new Error(`Category not found for slug: ${productData.categorySlug}`);
    }

    const product = await prisma.product.upsert({
      where: { slug: productData.slug },
      create: {
        categoryId,
        name: productData.name,
        slug: productData.slug,
        description: productData.description,
        fabric: productData.fabric,
        fit: productData.fit,
        brand: "Don's Atelier",
        status: ProductStatus.ACTIVE,
      },
      update: {
        categoryId,
        name: productData.name,
        description: productData.description,
        fabric: productData.fabric,
        fit: productData.fit,
        brand: "Don's Atelier",
        status: ProductStatus.ACTIVE,
      },
    });

    // Images
    for (const img of productData.images) {
      const existingImg = await prisma.productImage.findFirst({
        where: { productId: product.id, storagePath: img.storagePath },
      });
      if (!existingImg) {
        await prisma.productImage.create({
          data: {
            productId: product.id,
            storagePath: img.storagePath,
            altText: img.altText,
            sortOrder: img.sortOrder,
          },
        });
      }
    }

    // Variants
    for (const v of productData.variants) {
      await prisma.productVariant.upsert({
        where: { sku: v.sku },
        create: {
          productId: product.id,
          size: v.size,
          color: v.color,
          sku: v.sku,
          priceInCents: v.priceInCents,
          stockQuantity: v.stockQuantity,
          active: true,
        },
        update: {
          size: v.size,
          color: v.color,
          priceInCents: v.priceInCents,
          stockQuantity: v.stockQuantity,
          active: true,
        },
      });
    }

    console.log(`✓ Suit: ${product.name} (${productData.variants.length} variants, category: ${productData.categorySlug})`);
  }
}

async function main() {
  console.log("==================================================================");
  console.log("Don's Atelier (dons-atelier) - Database Seeding");
  console.log("==================================================================");

  try {
    await seedUsers();
    await seedCatalog();
    console.log("==================================================================");
    console.log("Seeding completed successfully!");
    console.log("  - 1 Admin Profile + 2 Customer Profiles provisioned");
    console.log("  - 5 Luxury Categories created");
    console.log("  - 12 Suits with multi-size variants and inventory stock created");
    console.log("==================================================================");
  } catch (error) {
    console.error("Seeding failed with error:", error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
