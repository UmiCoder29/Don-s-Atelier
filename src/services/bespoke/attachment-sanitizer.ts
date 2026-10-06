import crypto from 'crypto';
import sharp from 'sharp';
import { supabaseAdmin } from '@/lib/db/supabase';
import { STORAGE_BUCKETS } from '@/lib/storage/buckets';
import { AuthenticatedUser, Role } from '@/lib/auth/supabase-auth';
import { ForbiddenError, ValidationError, InternalServerError } from '@/lib/errors/api-error';
import {
  detectImageMimeType,
  isExecutableOrHostile,
  MAX_IMAGE_PIXELS,
  AllowedImageMimeType,
} from '@/lib/storage/image-processing';
import { logger } from '@/lib/api/logger';

export const MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

/**
 * Strict path matching for bespoke custom order attachments:
 * - Accept exactly one bucket ('custom-order-uploads') and one prefix: custom-orders/{user.id}/.
 * - Reject "..", URL-encoded and double-encoded traversal, backslashes, null bytes, leading slashes,
 *   and any other bucket or prefix.
 * - Rejects any attempt to reference another user's directory.
 */
export function validateCustomOrderStoragePath(
  user: AuthenticatedUser,
  storagePath: string,
  targetProfileId?: string
): void {
  if (!storagePath || typeof storagePath !== 'string') {
    throw new ForbiddenError('Storage path is required');
  }

  // Reject null bytes (raw or encoded)
  if (storagePath.includes('\0') || storagePath.toLowerCase().includes('%00')) {
    throw new ForbiddenError('Invalid storage path: null byte detected');
  }

  // Reject backslashes
  if (storagePath.includes('\\') || storagePath.toLowerCase().includes('%5c')) {
    throw new ForbiddenError('Invalid storage path: backslash characters are not permitted');
  }

  // Reject leading slashes
  if (storagePath.startsWith('/') || storagePath.toLowerCase().startsWith('%2f')) {
    throw new ForbiddenError('Invalid storage path: leading slashes are not permitted');
  }

  // Reject direct traversal
  if (storagePath.includes('..')) {
    throw new ForbiddenError('Invalid storage path: directory traversal is strictly forbidden');
  }

  // Check URL-encoded and double-encoded traversal
  let decoded = storagePath;
  for (let i = 0; i < 3; i++) {
    try {
      const nextDecoded = decodeURIComponent(decoded);
      if (nextDecoded === decoded) break;
      decoded = nextDecoded;
      if (
        decoded.includes('..') ||
        decoded.includes('\\') ||
        decoded.includes('\0') ||
        decoded.startsWith('/')
      ) {
        throw new ForbiddenError('Invalid storage path: encoded directory traversal is strictly forbidden');
      }
    } catch (err) {
      if (err instanceof ForbiddenError) throw err;
      throw new ForbiddenError('Invalid storage path: malformed encoding');
    }
  }

  // Determine authorized owner prefix
  const authorizedId = targetProfileId || user.id;
  const requiredPrefix = `custom-orders/${authorizedId}/`;

  // Path must start strictly with custom-orders/{user.id}/
  // Remove the ${user.id}/... form everywhere: paths without custom-orders/ are rejected
  if (!storagePath.startsWith(requiredPrefix)) {
    throw new ForbiddenError('Storage path must reside within your authorized user upload directory');
  }

  // Reject nested directories (flat folder under custom-orders/{user.id}/ only)
  const relativeFile = storagePath.slice(requiredPrefix.length);
  if (!relativeFile || relativeFile.includes('/') || relativeFile.includes('\\')) {
    throw new ForbiddenError('Invalid storage path: nested directories are not permitted');
  }
}

export interface SanitizedAttachmentResult {
  storagePath: string;
  fileName: string;
  mimeType: AllowedImageMimeType;
  size: number;
}

/**
 * Server-Side Re-Validation Pipeline for Bespoke Custom Order Attachments:
 * 1. Checks object size from storage metadata first without buffering. Rejects > 10MB with 422.
 * 2. Downloads the object and runs the image pipeline: magic bytes, Sharp pixel limit (40M px),
 *    EXIF/metadata strip, re-encode.
 * 3. Writes sanitized file to a NEW server-generated object name (random UUID) under custom-orders/{user.id}/.
 * 4. Deletes the original upload object.
 * 5. On non-image, oversized, or corrupt files: deletes the orphan object and responds with 422.
 */
export async function revalidateAndSanitizeAttachment(
  user: AuthenticatedUser,
  storagePath: string,
  clientFileName?: string | null,
  targetProfileId?: string
): Promise<SanitizedAttachmentResult> {
  const bucket = STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS;
  const ownerId = targetProfileId || user.id;

  // Pre-validate path formatting and ownership
  validateCustomOrderStoragePath(user, storagePath, ownerId);

  // Helper to delete the orphan original upload object
  const deleteOrphan = async () => {
    try {
      await supabaseAdmin.storage.from(bucket).remove([storagePath]);
    } catch (e) {
      logger.warn('Failed to delete orphan storage object', { storagePath, error: e });
    }
  };

  // 1. Read object's byte size from storage metadata first (never buffer more than limit)
  let objectSize: number | undefined;

  try {
    const { data: infoData } = await supabaseAdmin.storage.from(bucket).info(storagePath);
    if (infoData && typeof infoData.size === 'number') {
      objectSize = infoData.size;
    }
  } catch {
    // Info fallback handled below
  }

  if (objectSize === undefined) {
    try {
      const folder = storagePath.substring(0, storagePath.lastIndexOf('/'));
      const fileName = storagePath.substring(storagePath.lastIndexOf('/') + 1);
      const { data: listData } = await supabaseAdmin.storage.from(bucket).list(folder, { search: fileName });
      const match = listData?.find((f) => f.name === fileName);
      if (match?.metadata && typeof match.metadata.size === 'number') {
        objectSize = match.metadata.size;
      } else if (match?.metadata && typeof (match.metadata as any).contentLength === 'number') {
        objectSize = (match.metadata as any).contentLength;
      }
    } catch {
      // List fallback handled below
    }
  }

  // Reject oversized file BEFORE full download
  if (objectSize !== undefined && objectSize > MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES) {
    await deleteOrphan();
    throw new ValidationError(
      [
        {
          field: 'size',
          message: `File size (${objectSize} bytes) exceeds maximum allowed limit of ${MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES} bytes (10MB)`,
        },
      ],
      'File size exceeds maximum allowed limit'
    );
  }

  // 2. Download the object
  const { data: blob, error: downloadError } = await supabaseAdmin.storage.from(bucket).download(storagePath);
  if (downloadError || !blob) {
    await deleteOrphan();
    throw new ValidationError(
      [{ field: 'storagePath', message: 'Uploaded file not found or could not be retrieved from storage' }],
      'File retrieval failed'
    );
  }

  if (blob.size > MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES) {
    await deleteOrphan();
    throw new ValidationError(
      [
        {
          field: 'size',
          message: `File size (${blob.size} bytes) exceeds maximum allowed limit of 10MB`,
        },
      ],
      'File size exceeds maximum allowed limit'
    );
  }

  const rawBuffer = Buffer.from(await blob.arrayBuffer());
  if (rawBuffer.length === 0 || rawBuffer.length > MAX_CUSTOM_ORDER_ATTACHMENT_SIZE_BYTES) {
    await deleteOrphan();
    throw new ValidationError(
      [{ field: 'file', message: 'File is empty or exceeds 10MB limit' }],
      'Invalid file size'
    );
  }

  // 3. Reject executable or hostile binaries
  if (isExecutableOrHostile(rawBuffer)) {
    await deleteOrphan();
    throw new ValidationError(
      [{ field: 'file', message: 'Executables, scripts, and binary programs are strictly forbidden' }],
      'Hostile file rejected'
    );
  }

  // 4. Magic-byte check against image allowlist (JPEG, PNG, WebP)
  const detectedMime = detectImageMimeType(rawBuffer);
  if (!detectedMime) {
    await deleteOrphan();
    throw new ValidationError(
      [
        {
          field: 'file',
          message: 'Unsupported file format or invalid magic bytes. Only JPEG, PNG, and WebP images are permitted',
        },
      ],
      'Unsupported file format'
    );
  }

  // 5. Sharp pixel limit check (40M px) and corruption check
  try {
    const meta = await sharp(rawBuffer, { limitInputPixels: MAX_IMAGE_PIXELS }).metadata();
    if (!meta.width || !meta.height || meta.width * meta.height > MAX_IMAGE_PIXELS) {
      await deleteOrphan();
      throw new ValidationError(
        [
          {
            field: 'file',
            message: `Image dimensions (${meta.width ?? 0}x${meta.height ?? 0}) exceed the maximum allowed limit of 40 megapixels`,
          },
        ],
        'Image dimensions exceed maximum pixel limit'
      );
    }
  } catch (err: unknown) {
    await deleteOrphan();
    if (err instanceof ValidationError) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.toLowerCase().includes('pixel limit') || msg.toLowerCase().includes('exceeds')) {
      throw new ValidationError(
        [{ field: 'file', message: 'Image dimensions exceed the maximum allowed limit of 40 megapixels' }],
        'Image dimensions exceed maximum pixel limit'
      );
    }
    throw new ValidationError(
      [{ field: 'file', message: 'Corrupt image file or invalid image structure' }],
      'Corrupt image file'
    );
  }

  // 6. EXIF/metadata strip and re-encode
  let sanitizedBuffer: Buffer;
  try {
    const pipeline = sharp(rawBuffer, { limitInputPixels: MAX_IMAGE_PIXELS });
    if (detectedMime === 'image/jpeg') {
      sanitizedBuffer = await pipeline.jpeg({ quality: 90 }).toBuffer();
    } else if (detectedMime === 'image/png') {
      sanitizedBuffer = await pipeline.png({ compressionLevel: 8 }).toBuffer();
    } else if (detectedMime === 'image/webp') {
      sanitizedBuffer = await pipeline.webp({ quality: 90 }).toBuffer();
    } else {
      sanitizedBuffer = await pipeline.toBuffer();
    }
  } catch (err) {
    await deleteOrphan();
    throw new ValidationError(
      [{ field: 'file', message: 'Failed to process or re-encode image' }],
      'Corrupt image file'
    );
  }

  // 7. Write sanitized file to a NEW server-generated object name (random UUID, extension from detected type)
  // under custom-orders/{user.id}/
  const newUuid = crypto.randomUUID();
  const ext = detectedMime === 'image/png' ? '.png' : detectedMime === 'image/webp' ? '.webp' : '.jpg';
  const newStoragePath = `custom-orders/${ownerId}/${newUuid}${ext}`;

  const { error: uploadError } = await supabaseAdmin.storage
    .from(bucket)
    .upload(newStoragePath, sanitizedBuffer, {
      contentType: detectedMime,
      upsert: false,
    });

  if (uploadError) {
    logger.error('Failed to upload sanitized custom order attachment', {
      storagePath: newStoragePath,
      error: uploadError.message,
    });
    throw new InternalServerError('Failed to store sanitized image in atelier storage');
  }

  // 8. Delete the original upload object
  await deleteOrphan();

  const finalFileName = clientFileName
    ? clientFileName.endsWith(ext)
      ? clientFileName
      : `${clientFileName}${ext}`
    : `${newUuid}${ext}`;

  return {
    storagePath: newStoragePath,
    fileName: finalFileName,
    mimeType: detectedMime,
    size: sanitizedBuffer.length,
  };
}
