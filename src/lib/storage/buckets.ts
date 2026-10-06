import { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '@/lib/db/supabase';
import { logger } from '@/lib/api/logger';

/**
 * Storage bucket identifiers for Don's Atelier.
 * - product-images: Public read access for suit showcase, admin-only write.
 * - custom-order-uploads: Private storage for bespoke suit customer reference files,
 *   accessible only to the owning customer and atelier administrators via short-lived signed URLs.
 */
export const STORAGE_BUCKETS = {
  PRODUCT_IMAGES: 'product-images',
  CUSTOM_ORDER_UPLOADS: 'custom-order-uploads',
} as const;

export type StorageBucket = (typeof STORAGE_BUCKETS)[keyof typeof STORAGE_BUCKETS];

export interface BucketDefinition {
  id: string;
  name: string;
  public: boolean;
  fileSizeLimit: number; // in bytes
  allowedMimeTypes: string[];
}

export const BUCKET_CONFIGS: Record<StorageBucket, BucketDefinition> = {
  [STORAGE_BUCKETS.PRODUCT_IMAGES]: {
    id: STORAGE_BUCKETS.PRODUCT_IMAGES,
    name: STORAGE_BUCKETS.PRODUCT_IMAGES,
    public: true,
    fileSizeLimit: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'],
  },
  [STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS]: {
    id: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
    name: STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS,
    public: false,
    fileSizeLimit: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'],
  },
};

/**
 * Ensures that both Don's Atelier storage buckets exist and match their security profiles:
 * - 'product-images': public read, admin write
 * - 'custom-order-uploads': private (public: false)
 *
 * Idempotent operation: creates missing buckets and updates configurations if needed.
 */
export async function ensureStorageBucketsExist(
  client: SupabaseClient = supabaseAdmin
): Promise<{ success: boolean; buckets: string[] }> {
  const { data: existingBuckets, error: listError } = await client.storage.listBuckets();

  if (listError) {
    logger.error('Failed to query existing Supabase Storage buckets', { error: listError });
    throw new Error(`Failed to list storage buckets: ${listError.message}`);
  }

  const existingMap = new Map((existingBuckets || []).map((b) => [b.name, b]));
  const configuredBuckets: string[] = [];

  for (const [bucketName, config] of Object.entries(BUCKET_CONFIGS)) {
    const existing = existingMap.get(bucketName);

    if (!existing) {
      const { error: createError } = await client.storage.createBucket(bucketName, {
        public: config.public,
        fileSizeLimit: config.fileSizeLimit,
        allowedMimeTypes: [...config.allowedMimeTypes],
      });

      if (createError) {
        logger.error(`Failed to create bucket '${bucketName}'`, { error: createError });
        throw new Error(`Failed to create storage bucket '${bucketName}': ${createError.message}`);
      }

      logger.info(`Created Supabase Storage bucket '${bucketName}'`, {
        public: config.public,
        allowedMimeTypes: config.allowedMimeTypes,
      });
    } else {
      // Update bucket properties (public status, allowedMimeTypes, fileSizeLimit)
      const { error: updateError } = await client.storage.updateBucket(bucketName, {
        public: config.public,
        fileSizeLimit: config.fileSizeLimit,
        allowedMimeTypes: [...config.allowedMimeTypes],
      });

      if (updateError) {
        logger.warn(`Failed to update bucket '${bucketName}' properties`, { error: updateError });
      }
    }

    configuredBuckets.push(bucketName);
  }

  return { success: true, buckets: configuredBuckets };
}
