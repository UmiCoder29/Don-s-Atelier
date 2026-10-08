-- ==============================================================================
-- PROPOSED MIGRATION 03: Align Supabase Storage Bucket Constraints
-- Description: Updates the storage.buckets table so that `file_size_limit` and
--              `allowed_mime_types` match the application's runtime constants:
--              - `custom-order-uploads`: 10MB (10485760 bytes), allowed MIME types: image/jpeg, image/png, image/webp
--              - `product-images`: 5MB (5242880 bytes, matching MAX_PRODUCT_IMAGE_SIZE_BYTES), allowed MIME types: image/jpeg, image/png, image/webp
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

-- Update custom-order-uploads bucket (private bespoke suit references: 10MB limit)
UPDATE storage.buckets
SET
  file_size_limit = 10485760, -- 10MB in bytes (MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES)
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp']::text[],
  public = false
WHERE id = 'custom-order-uploads';

-- Update product-images bucket (public suit showcase: 5MB limit matching MAX_PRODUCT_IMAGE_SIZE_BYTES)
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

-- Revert custom-order-uploads settings
UPDATE storage.buckets
SET
  file_size_limit = 10485760,
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp']::text[],
  public = false
WHERE id = 'custom-order-uploads';

-- Revert product-images settings to previous 10MB limit
UPDATE storage.buckets
SET
  file_size_limit = 10485760,
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp']::text[],
  public = true
WHERE id = 'product-images';

COMMIT;
*/
