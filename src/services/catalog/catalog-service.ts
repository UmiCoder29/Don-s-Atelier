import { prisma } from '@/lib/db/prisma';
import { Prisma, ProductStatus } from '@prisma/client';
import { NotFoundError, ConflictError, BadRequestError } from '@/lib/errors/api-error';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import {
  ListProductsQuery,
  PublicProductDto,
  PublicVariantDto,
  CreateProductInput,
  UpdateProductInput,
  CreateVariantInput,
  UpdateVariantInput,
  AdjustStockInput,
} from './types';

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)+/g, '');
}

/**
 * Sanitizes variant for public consumption:
 * Strictly hides exact stock quantity, returning `inStock` boolean and low-stock indicators.
 */
function sanitizeVariantForPublic(variant: {
  id: string;
  productId: string;
  size: string;
  color: string;
  sku: string;
  priceInCents: number;
  stockQuantity: number;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}): PublicVariantDto {
  const { stockQuantity, ...rest } = variant;
  const inStock = stockQuantity > 0;
  const isLowStock = stockQuantity > 0 && stockQuantity <= 3;
  return {
    ...rest,
    inStock,
    isLowStock,
    lowStock: isLowStock,
  };
}

/**
 * Transforms a raw product model into PublicProductDto.
 */
function toPublicProductDto(product: {
  id: string;
  categoryId: string;
  name: string;
  slug: string;
  description: string;
  fabric: string;
  fit: string;
  brand: string;
  status: ProductStatus;
  category?: { id: string; name: string; slug: string } | null;
  images: Array<{ id: string; storagePath: string; altText: string; sortOrder: number }>;
  variants: Array<{
    id: string;
    productId: string;
    size: string;
    color: string;
    sku: string;
    priceInCents: number;
    stockQuantity: number;
    active: boolean;
    createdAt: Date;
    updatedAt: Date;
  }>;
  createdAt: Date;
  updatedAt: Date;
}): PublicProductDto {
  const sanitizedVariants = product.variants.map(sanitizeVariantForPublic);
  const inStock = sanitizedVariants.some((v) => v.inStock);
  const isLowStock = sanitizedVariants.some((v) => v.isLowStock);

  return {
    ...product,
    variants: sanitizedVariants,
    inStock,
    isLowStock,
    lowStock: isLowStock,
  };
}

/**
 * Service handling catalog operations for both Public and Admin APIs.
 * Strictly enforces parameterization, role authorization, and stock count hiding on public endpoints.
 */
export class CatalogService {
  // ===========================================================================
  // PUBLIC ENDPOINTS
  // ===========================================================================

  /**
   * Retrieves all categories along with active product counts.
   */
  async listCategories() {
    return prisma.category.findMany({
      include: {
        _count: {
          select: {
            products: {
              where: { status: ProductStatus.ACTIVE },
            },
          },
        },
      },
      orderBy: { name: 'asc' },
    });
  }

  /**
   * Retrieves paginated active products with optional filters, whitelisted sorting,
   * and stock concealment (hiding exact quantities).
   */
  async listProducts(query: ListProductsQuery): Promise<{
    products: PublicProductDto[];
    pagination: { page: number; limit: number; totalCount: number; totalPages: number };
  }> {
    // 1. Cap pagination
    const limit = Math.min(Math.max(query.limit || 20, 1), 50);
    const page = Math.max(query.page || 1, 1);
    const skip = (page - 1) * limit;

    // 2. Build parameterized WHERE clause
    const whereClause: Prisma.ProductWhereInput = {
      status: ProductStatus.ACTIVE,
    };

    const effectiveCategory = query.categorySlug || query.category;
    if (effectiveCategory) {
      whereClause.category = { slug: effectiveCategory };
    }

    if (query.fit) {
      whereClause.fit = { equals: query.fit, mode: 'insensitive' };
    }

    if (query.fabric) {
      whereClause.fabric = { contains: query.fabric, mode: 'insensitive' };
    }

    const effectiveSearch = query.search || query.q;
    if (effectiveSearch) {
      whereClause.OR = [
        { name: { contains: effectiveSearch, mode: 'insensitive' } },
        { description: { contains: effectiveSearch, mode: 'insensitive' } },
        { fabric: { contains: effectiveSearch, mode: 'insensitive' } },
        { brand: { contains: effectiveSearch, mode: 'insensitive' } },
      ];
    }

    // Variant-level filters (size, color, price range)
    const effectiveMinPrice = query.minPriceInCents ?? query.minPrice;
    const effectiveMaxPrice = query.maxPriceInCents ?? query.maxPrice;

    const variantFilter: Prisma.ProductVariantWhereInput = { active: true };
    let hasVariantFilter = false;

    if (query.size) {
      variantFilter.size = { equals: query.size, mode: 'insensitive' };
      hasVariantFilter = true;
    }

    if (query.color) {
      variantFilter.color = { contains: query.color, mode: 'insensitive' };
      hasVariantFilter = true;
    }

    if (effectiveMinPrice !== undefined || effectiveMaxPrice !== undefined) {
      variantFilter.priceInCents = {};
      if (effectiveMinPrice !== undefined) variantFilter.priceInCents.gte = effectiveMinPrice;
      if (effectiveMaxPrice !== undefined) variantFilter.priceInCents.lte = effectiveMaxPrice;
      hasVariantFilter = true;
    }

    if (hasVariantFilter) {
      whereClause.variants = { some: variantFilter };
    }

    // 3. Whitelisted Sorting (no dynamic column injection)
    let orderBy: Prisma.ProductOrderByWithRelationInput = { createdAt: query.sortOrder };
    if (query.sortBy === 'name') {
      orderBy = { name: query.sortOrder };
    } else if (query.sortBy === 'updatedAt') {
      orderBy = { updatedAt: query.sortOrder };
    } else if (query.sortBy === 'createdAt') {
      orderBy = { createdAt: query.sortOrder };
    }

    // 4. Parameterized Prisma queries
    const [rawProducts, totalCount] = await Promise.all([
      prisma.product.findMany({
        where: whereClause,
        include: {
          category: {
            select: { id: true, name: true, slug: true },
          },
          images: {
            orderBy: { sortOrder: 'asc' },
            take: 2,
          },
          variants: {
            where: { active: true },
            select: {
              id: true,
              productId: true,
              size: true,
              color: true,
              sku: true,
              priceInCents: true,
              stockQuantity: true,
              active: true,
              createdAt: true,
              updatedAt: true,
            },
            orderBy: [{ priceInCents: 'asc' }, { size: 'asc' }],
          },
        },
        skip,
        take: limit,
        orderBy,
      }),
      prisma.product.count({ where: whereClause }),
    ]);

    // 5. Hide exact stock counts from all public outputs
    let products = rawProducts.map(toPublicProductDto);

    // If sorting by price was requested, sort products by their lowest active variant price
    if (query.sortBy === 'price') {
      products.sort((a, b) => {
        const priceA = a.variants[0]?.priceInCents ?? 0;
        const priceB = b.variants[0]?.priceInCents ?? 0;
        return query.sortOrder === 'asc' ? priceA - priceB : priceB - priceA;
      });
    }

    return {
      products,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    };
  }

  /**
   * Retrieves a single active product by unique slug, concealing exact inventory counts.
   */
  async getProductBySlug(slug: string): Promise<PublicProductDto> {
    const product = await prisma.product.findFirst({
      where: {
        slug,
        status: ProductStatus.ACTIVE,
      },
      include: {
        category: true,
        images: {
          orderBy: { sortOrder: 'asc' },
        },
        variants: {
          where: { active: true },
          orderBy: [{ color: 'asc' }, { size: 'asc' }],
        },
      },
    });

    if (!product) {
      throw new NotFoundError(`Suit '${slug}'`);
    }

    return toPublicProductDto(product);
  }

  // ===========================================================================
  // ADMIN ENDPOINTS (Requires ADMIN role, Audit Logged, Exposes exact counts)
  // ===========================================================================

  /**
   * Admin list products: can view DRAFT, ACTIVE, and ARCHIVED items with exact inventory counts.
   */
  async adminListProducts(params: {
    page?: number;
    limit?: number;
    status?: ProductStatus;
    search?: string;
  }) {
    const page = Math.max(params.page || 1, 1);
    const limit = Math.min(Math.max(params.limit || 20, 1), 100);
    const skip = (page - 1) * limit;

    const where: Prisma.ProductWhereInput = {};
    if (params.status) {
      where.status = params.status;
    }
    if (params.search) {
      where.OR = [
        { name: { contains: params.search, mode: 'insensitive' } },
        { slug: { contains: params.search, mode: 'insensitive' } },
        { fabric: { contains: params.search, mode: 'insensitive' } },
      ];
    }

    const [products, totalCount] = await Promise.all([
      prisma.product.findMany({
        where,
        include: {
          category: true,
          variants: {
            orderBy: [{ size: 'asc' }, { color: 'asc' }],
          },
          images: {
            orderBy: { sortOrder: 'asc' },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.product.count({ where }),
    ]);

    return {
      products,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    };
  }

  /**
   * Admin get product by ID with full details and exact inventory counts.
   */
  async adminGetProductById(productId: string) {
    const product = await prisma.product.findUnique({
      where: { id: productId },
      include: {
        category: true,
        variants: {
          orderBy: [{ size: 'asc' }, { color: 'asc' }],
        },
        images: {
          orderBy: { sortOrder: 'asc' },
        },
      },
    });

    if (!product) {
      throw new NotFoundError(`Product '${productId}'`);
    }

    return product;
  }

  /**
   * Admin creates a new catalog product.
   */
  async createProduct(_admin: AuthenticatedUser, input: CreateProductInput) {
    // 1. Verify category exists
    const category = await prisma.category.findUnique({
      where: { id: input.categoryId },
    });
    if (!category) {
      throw new NotFoundError(`Category '${input.categoryId}'`);
    }

    // 2. Generate or validate unique slug
    let slug = input.slug || slugify(input.name);
    const existingSlug = await prisma.product.findUnique({ where: { slug } });
    if (existingSlug) {
      if (input.slug) {
        throw new ConflictError(`Product with slug '${input.slug}' already exists`);
      }
      slug = `${slug}-${Date.now().toString(36)}`;
    }

    // 3. Create product
    const product = await prisma.product.create({
      data: {
        categoryId: input.categoryId,
        name: input.name,
        slug,
        description: input.description,
        fabric: input.fabric,
        fit: input.fit,
        brand: input.brand,
        status: input.status,
        images: input.images
          ? {
              createMany: {
                data: input.images.map((img, idx) => ({
                  storagePath: img.storagePath,
                  altText: img.altText,
                  sortOrder: img.sortOrder ?? idx,
                })),
              },
            }
          : undefined,
      },
      include: {
        category: true,
        images: true,
        variants: true,
      },
    });

    return product;
  }

  /**
   * Admin updates an existing product.
   */
  async updateProduct(_admin: AuthenticatedUser, productId: string, input: UpdateProductInput) {
    const existing = await prisma.product.findUnique({ where: { id: productId } });
    if (!existing) {
      throw new NotFoundError(`Product '${productId}'`);
    }

    if (input.categoryId) {
      const category = await prisma.category.findUnique({ where: { id: input.categoryId } });
      if (!category) {
        throw new NotFoundError(`Category '${input.categoryId}'`);
      }
    }

    if (input.slug && input.slug !== existing.slug) {
      const slugConflict = await prisma.product.findUnique({ where: { slug: input.slug } });
      if (slugConflict) {
        throw new ConflictError(`Product with slug '${input.slug}' already exists`);
      }
    }

    const updated = await prisma.product.update({
      where: { id: productId },
      data: {
        categoryId: input.categoryId,
        name: input.name,
        slug: input.slug,
        description: input.description,
        fabric: input.fabric,
        fit: input.fit,
        brand: input.brand,
        status: input.status,
      },
      include: {
        category: true,
        images: true,
        variants: true,
      },
    });

    return updated;
  }

  /**
   * Admin archives a product (soft delete via ARCHIVED status).
   */
  async archiveProduct(_admin: AuthenticatedUser, productId: string) {
    const existing = await prisma.product.findUnique({ where: { id: productId } });
    if (!existing) {
      throw new NotFoundError(`Product '${productId}'`);
    }

    const archived = await prisma.product.update({
      where: { id: productId },
      data: {
        status: ProductStatus.ARCHIVED,
      },
      include: {
        category: true,
        variants: true,
      },
    });

    return archived;
  }

  /**
   * Admin creates a new variant for a product.
   */
  async createVariant(_admin: AuthenticatedUser, productId: string, input: CreateVariantInput) {
    const product = await prisma.product.findUnique({ where: { id: productId } });
    if (!product) {
      throw new NotFoundError(`Product '${productId}'`);
    }

    // Check SKU uniqueness
    const existingSku = await prisma.productVariant.findUnique({
      where: { sku: input.sku },
    });
    if (existingSku) {
      throw new ConflictError(`Product variant with SKU '${input.sku}' already exists`);
    }

    // Check composite (productId, size, color) uniqueness
    const existingVariant = await prisma.productVariant.findUnique({
      where: {
        productId_size_color: {
          productId,
          size: input.size,
          color: input.color,
        },
      },
    });
    if (existingVariant) {
      throw new ConflictError(
        `Variant for size '${input.size}' and color '${input.color}' already exists on this suit`
      );
    }

    const variant = await prisma.productVariant.create({
      data: {
        productId,
        size: input.size,
        color: input.color,
        sku: input.sku,
        priceInCents: input.priceInCents,
        stockQuantity: input.stockQuantity,
        active: input.active,
      },
    });

    return variant;
  }

  /**
   * Admin updates variant details.
   */
  async updateVariant(_admin: AuthenticatedUser, variantId: string, input: UpdateVariantInput) {
    const existing = await prisma.productVariant.findUnique({ where: { id: variantId } });
    if (!existing) {
      throw new NotFoundError(`Variant '${variantId}'`);
    }

    if (input.sku && input.sku !== existing.sku) {
      const skuConflict = await prisma.productVariant.findUnique({
        where: { sku: input.sku },
      });
      if (skuConflict) {
        throw new ConflictError(`Product variant with SKU '${input.sku}' already exists`);
      }
    }

    const updated = await prisma.productVariant.update({
      where: { id: variantId },
      data: {
        size: input.size,
        color: input.color,
        sku: input.sku,
        priceInCents: input.priceInCents,
        active: input.active,
      },
    });

    return updated;
  }

  /**
   * Admin adjusts variant stock count (atomic adjustment or absolute set).
   */
  async adjustStock(_admin: AuthenticatedUser, variantId: string, input: AdjustStockInput) {
    const existing = await prisma.productVariant.findUnique({ where: { id: variantId } });
    if (!existing) {
      throw new NotFoundError(`Variant '${variantId}'`);
    }

    let newStock: number;
    if (input.adjustment !== undefined) {
      newStock = existing.stockQuantity + input.adjustment;
      if (newStock < 0) {
        throw new BadRequestError(
          `Stock adjustment (${input.adjustment}) would result in negative inventory (${newStock})`
        );
      }
    } else if (input.stockQuantity !== undefined) {
      newStock = input.stockQuantity;
    } else {
      throw new BadRequestError('Either adjustment or stockQuantity must be provided');
    }

    const updated = await prisma.productVariant.update({
      where: { id: variantId },
      data: {
        stockQuantity: newStock,
      },
    });

    return {
      variant: updated,
      previousStock: existing.stockQuantity,
      newStock,
      adjustment: input.adjustment,
      reason: input.reason || 'Inventory adjustment',
    };
  }
}

export const catalogService = new CatalogService();
