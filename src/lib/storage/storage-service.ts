import { supabaseAdmin } from '@/lib/db/supabase';
import { prisma } from '@/lib/db/prisma';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { NotFoundError, InternalServerError } from '@/lib/errors/api-error';
import { logger } from '@/lib/api/logger';
import { STORAGE_BUCKETS } from './buckets';
import {
  validateImageBuffer,
  validateImagePixelLimit,
  stripImageMetadata,
  generateRandomUuidStoragePath,
  MAX_PRODUCT_IMAGE_SIZE_BYTES,
  AllowedImageMimeType,
} from './image-processing';
import {
  createSignedUploadUrl,
  createSignedDownloadUrl,
  getPublicStorageUrl,
  SignedUploadUrlResult,
  SignedDownloadUrlResult,
} from './signed-urls';
import { assertStorageAccess } from './access-control';

export interface UploadProductImageInput {
  buffer: Buffer;
  declaredMimeType?: string;
  productId?: string;
  altText?: string;
  sortOrder?: number;
}

export interface UploadProductImageResult {
  id?: string;
  productId?: string;
  storagePath: string;
  publicUrl: string;
  fileName: string;
  mimeType: AllowedImageMimeType;
  size: number;
  altText?: string;
  sortOrder?: number;
}

export class StorageService {
  /**
   * Admin-only product image upload pipeline:
   * 1. Verifies server-side admin role.
   * 2. Validates image buffer (magic bytes, size <= 5MB, rejects executables/scripts).
   * 3. Strips EXIF/IPTC/XMP camera and personal metadata.
   * 4. Generates an unpredictable random UUID filename.
   * 5. Uploads sanitized buffer directly to 'product-images' bucket.
   * 6. Optionally persists a ProductImage relation in Postgres if productId is supplied.
   */
  public async uploadProductImage(
    adminUser: AuthenticatedUser,
    input: UploadProductImageInput
  ): Promise<UploadProductImageResult> {
    // 1. Role enforcement
    await assertStorageAccess({
      user: adminUser,
      bucket: STORAGE_BUCKETS.PRODUCT_IMAGES,
      operation: 'write',
    });

    // 2. Security validation: rejects executables, oversized buffers, mime mismatches
    const { mimeType, extension } = validateImageBuffer(input.buffer, {
      maxSizeBytes: MAX_PRODUCT_IMAGE_SIZE_BYTES,
      declaredMimeType: input.declaredMimeType,
    });

    // 2b. Dimension security check: rejects oversized pixel counts (> 40 million pixels)
    await validateImagePixelLimit(input.buffer);

    // 3. Strip metadata (EXIF/GPS/XMP) with Sharp limitInputPixels (40M)
    const sanitizedBuffer = await stripImageMetadata(input.buffer, mimeType);

    // 4. Random UUID path (never use client-supplied name)
    const { fileName, storagePath } = generateRandomUuidStoragePath(extension, 'catalog');

    // 5. Upload to Supabase Storage bucket 'product-images'
    const { error: uploadError } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.PRODUCT_IMAGES)
      .upload(storagePath, sanitizedBuffer, {
        contentType: mimeType,
        cacheControl: 'public, max-age=31536000, immutable',
        upsert: false,
      });

    if (uploadError) {
      logger.error('Failed to upload product image to Supabase Storage', {
        storagePath,
        error: uploadError.message,
      });
      throw new InternalServerError('Failed to store image in atelier storage');
    }

    const publicUrl = getPublicStorageUrl(STORAGE_BUCKETS.PRODUCT_IMAGES, storagePath);

    // 6. Optional database registration if associated with a Product
    let productImageId: string | undefined;

    if (input.productId) {
      const product = await prisma.product.findUnique({
        where: { id: input.productId },
        select: { id: true, name: true },
      });

      if (!product) {
        throw new NotFoundError('Suit product');
      }

      const createdImage = await prisma.productImage.create({
        data: {
          productId: input.productId,
          storagePath,
          altText: input.altText || `${product.name} Showcase Image`,
          sortOrder: input.sortOrder ?? 0,
        },
      });

      productImageId = createdImage.id;
    }

    logger.info('Product image securely uploaded and processed', {
      actorId: adminUser.id,
      storagePath,
      mimeType,
      size: sanitizedBuffer.length,
      productId: input.productId,
    });

    return {
      id: productImageId,
      productId: input.productId,
      storagePath,
      publicUrl,
      fileName,
      mimeType,
      size: sanitizedBuffer.length,
      altText: input.altText,
      sortOrder: input.sortOrder,
    };
  }

  /**
   * Generates a signed upload URL with short expiry (default 60s).
   * Validates access control:
   * - 'product-images': admin only.
   * - 'custom-order-uploads': authenticated customer (scoped to own path) or admin.
   */
  public async getSignedUploadUrl(
    user: AuthenticatedUser,
    options: {
      bucket: string;
      storagePath: string;
      expiresIn?: number;
      customOrderId?: string;
    }
  ): Promise<SignedUploadUrlResult> {
    await assertStorageAccess({
      user,
      bucket: options.bucket,
      operation: 'signed_upload',
      storagePath: options.storagePath,
      customOrderId: options.customOrderId,
    });

    return createSignedUploadUrl(options.bucket, options.storagePath, {
      expiresIn: options.expiresIn,
    });
  }

  /**
   * Generates a signed download URL with short expiry (default 60s) for private files.
   * Validates that only the bespoke order owner or atelier administrators can download.
   */
  public async getSignedDownloadUrl(
    user: AuthenticatedUser | null,
    options: {
      bucket: string;
      storagePath: string;
      expiresIn?: number;
      customOrderId?: string;
      download?: boolean | string;
    }
  ): Promise<SignedDownloadUrlResult> {
    await assertStorageAccess({
      user,
      bucket: options.bucket,
      operation: 'signed_download',
      storagePath: options.storagePath,
      customOrderId: options.customOrderId,
    });

    return createSignedDownloadUrl(options.bucket, options.storagePath, {
      expiresIn: options.expiresIn,
      download: options.download,
    });
  }
}

export const storageService = new StorageService();
