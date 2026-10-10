-- ==============================================================================
-- PROPOSED MIGRATION 03: Align Storage Bucket Constraint for product-images
-- Description: Updates the storage.buckets table for `product-images` so that
--              `file_size_limit` is aligned with the application runtime constant:
--              MAX_PRODUCT_IMAGE_SIZE_BYTES = 5 * 1024 * 1024 (5242880 bytes / 5MB)
--              in src/lib/storage/image-processing.ts:6.
--              - `custom-order-uploads` bucket is omitted as it is already configured
--                with 10485760 bytes (10MB) and allowed MIME types ['image/jpeg', 'image/png', 'image/webp'].
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

UPDATE storage.buckets
SET
  file_size_limit = 5242880, -- 5MB in bytes (MAX_PRODUCT_IMAGE_SIZE_BYTES)
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp']::text[],
  public = true
WHERE id = 'product-images';

COMMIT;

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

-- Revert product-images settings to previous 10MB limit
UPDATE storage.buckets
SET
  file_size_limit = 10485760, -- 10MB
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp']::text[],
  public = true
WHERE id = 'product-images';

COMMIT;
*/
