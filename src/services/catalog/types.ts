import { z } from 'zod';
import { ProductStatus } from '@prisma/client';
import { uuidSchema, priceInCentsSchema } from '@/lib/validation/zod-helpers';
import { sanitizeText } from '@/lib/validation/sanitizer';

// =============================================================================
// PUBLIC CATALOG SCHEMAS
// =============================================================================

// Whitelisted sort fields to strictly prevent dynamic column injection
export const allowedSortFields = ['createdAt', 'name', 'price', 'updatedAt'] as const;
export const productSortBySchema = z.enum(allowedSortFields).default('createdAt');
export const sortOrderSchema = z.enum(['asc', 'desc']).default('desc');

export const listProductsQuerySchema = z.object({
  page: z.coerce.number().int().min(1, 'Page must be at least 1').default(1),
  limit: z.coerce.number().int().min(1, 'Limit must be at least 1').max(50, 'Page size limit cannot exceed 50 items').default(20),
  categorySlug: z.string().max(100).optional(),
  category: z.string().max(100).optional(),
  fit: z.string().max(50).optional(),
  fabric: z.string().max(100).optional(),
  size: z.string().max(30).optional(),
  color: z.string().max(50).optional(),
  minPrice: z.coerce.number().int().min(0).optional(),
  maxPrice: z.coerce.number().int().min(0).optional(),
  minPriceInCents: z.coerce.number().int().min(0).optional(),
  maxPriceInCents: z.coerce.number().int().min(0).optional(),
  search: z.string().max(100).optional(),
  q: z.string().max(100).optional(),
  sortBy: productSortBySchema,
  sortOrder: sortOrderSchema,
}).strict();

export type ListProductsQuery = z.infer<typeof listProductsQuerySchema>;

export const productSlugParamSchema = z.object({
  slug: z.string().min(1, 'Product slug is required').max(100, 'Slug is too long'),
}).strict();

export const productIdParamSchema = z.object({
  id: uuidSchema,
}).strict();

export const variantIdParamSchema = z.object({
  id: uuidSchema,
}).strict();

// Public sanitized variant representation (hides exact stock quantity)
export interface PublicVariantDto {
  id: string;
  productId: string;
  size: string;
  color: string;
  sku: string;
  priceInCents: number;
  inStock: boolean;
  isLowStock: boolean;
  lowStock: boolean;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// Public sanitized product representation
export interface PublicProductDto {
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
  variants: PublicVariantDto[];
  inStock: boolean;
  isLowStock: boolean;
  lowStock: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// =============================================================================
// ADMIN CATALOG SCHEMAS
// =============================================================================

export const createProductSchema = z.object({
  categoryId: uuidSchema,
  name: z.string().min(2, 'Name is required').max(150, 'Name cannot exceed 150 characters').transform(sanitizeText),
  slug: z.string().min(2).max(150).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'Slug must be lowercase alphanumeric with hyphens').optional(),
  description: z.string().min(10, 'Description is required').max(3000, 'Description cannot exceed 3000 characters').transform(sanitizeText),
  fabric: z.string().min(2).max(150).transform(sanitizeText),
  fit: z.string().min(2).max(100).transform(sanitizeText),
  brand: z.string().min(1).max(100).default("Don's Atelier").transform(sanitizeText),
  status: z.nativeEnum(ProductStatus).default(ProductStatus.DRAFT),
  images: z.array(z.object({
    storagePath: z.string().min(1).max(500),
    altText: z.string().min(1).max(255).transform(sanitizeText),
    sortOrder: z.number().int().min(0).default(0),
  })).optional(),
}).strict();

export type CreateProductInput = z.infer<typeof createProductSchema>;

export const updateProductSchema = z.object({
  categoryId: uuidSchema.optional(),
  name: z.string().min(2).max(150).transform(sanitizeText).optional(),
  slug: z.string().min(2).max(150).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'Slug must be lowercase alphanumeric with hyphens').optional(),
  description: z.string().min(10).max(3000).transform(sanitizeText).optional(),
  fabric: z.string().min(2).max(150).transform(sanitizeText).optional(),
  fit: z.string().min(2).max(100).transform(sanitizeText).optional(),
  brand: z.string().min(1).max(100).transform(sanitizeText).optional(),
  status: z.nativeEnum(ProductStatus).optional(),
}).strict();

export type UpdateProductInput = z.infer<typeof updateProductSchema>;

export const createVariantSchema = z.object({
  productId: uuidSchema.optional(),
  size: z.string().min(1, 'Size is required').max(30).transform(sanitizeText),
  color: z.string().min(1, 'Color is required').max(50).transform(sanitizeText),
  sku: z.string().min(2, 'SKU is required').max(100).transform(sanitizeText),
  priceInCents: priceInCentsSchema,
  stockQuantity: z.number().int().min(0, 'Initial stock cannot be negative').default(0),
  active: z.boolean().default(true),
}).strict();

export type CreateVariantInput = z.infer<typeof createVariantSchema>;

export const updateVariantSchema = z.object({
  size: z.string().min(1).max(30).transform(sanitizeText).optional(),
  color: z.string().min(1).max(50).transform(sanitizeText).optional(),
  sku: z.string().min(2).max(100).transform(sanitizeText).optional(),
  priceInCents: priceInCentsSchema.optional(),
  active: z.boolean().optional(),
}).strict();

export type UpdateVariantInput = z.infer<typeof updateVariantSchema>;

export const adjustStockSchema = z.object({
  adjustment: z.number().int().optional(),
  stockQuantity: z.number().int().min(0, 'Stock quantity cannot be negative').optional(),
  reason: z.string().max(255).transform(sanitizeText).optional(),
}).strict().refine((data) => data.adjustment !== undefined || data.stockQuantity !== undefined, {
  message: 'Either adjustment (delta) or stockQuantity (absolute) must be provided',
});

export type AdjustStockInput = z.infer<typeof adjustStockSchema>;
