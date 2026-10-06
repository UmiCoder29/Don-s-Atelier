import crypto from 'crypto';
import sharp from 'sharp';
import { ValidationError, PayloadTooLargeError } from '@/lib/errors/api-error';
import { logger } from '@/lib/api/logger';

export const MAX_PRODUCT_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB
export const MAX_IMAGE_PIXELS = 40_000_000; // 40 million pixels (40 megapixels, e.g. ~6324 x 6324)

export const ALLOWED_IMAGE_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
] as const;

export type AllowedImageMimeType = (typeof ALLOWED_IMAGE_MIME_TYPES)[number];

const EXTENSION_MAP: Record<AllowedImageMimeType, string> = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};

/**
 * Detects true image MIME type from binary magic bytes.
 * Never trusts client headers or file extensions.
 */
export function detectImageMimeType(buffer: Buffer): AllowedImageMimeType | null {
  if (!buffer || buffer.length < 12) {
    return null;
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return 'image/png';
  }

  // WebP: RIFF (bytes 0-3) ... WEBP (bytes 8-11)
  if (
    buffer[0] === 0x52 && // R
    buffer[1] === 0x49 && // I
    buffer[2] === 0x46 && // F
    buffer[3] === 0x46 && // F
    buffer[8] === 0x57 && // W
    buffer[9] === 0x45 && // E
    buffer[10] === 0x42 && // B
    buffer[11] === 0x50 // P
  ) {
    return 'image/webp';
  }

  return null;
}

/**
 * Inspects buffer for known executable, script, or hostile payloads.
 */
export function isExecutableOrHostile(buffer: Buffer): boolean {
  if (!buffer || buffer.length < 2) {
    return false;
  }

  // 1. DOS / Windows PE Executable (MZ - 4D 5A)
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
    return true;
  }

  // 2. Linux / Unix ELF Executable (7F 45 4C 46)
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4c &&
    buffer[3] === 0x46
  ) {
    return true;
  }

  // 3. Apple Mach-O Executable
  if (buffer.length >= 4) {
    const b0 = buffer[0];
    const b1 = buffer[1];
    const b2 = buffer[2];
    const b3 = buffer[3];
    if (
      (b0 === 0xfe && b1 === 0xed && b2 === 0xfa && (b3 === 0xce || b3 === 0xcf)) ||
      (b0 === 0xce && b1 === 0xfa && b2 === 0xed && b3 === 0xfe) ||
      (b0 === 0xcf && b1 === 0xfa && b2 === 0xed && b3 === 0xfe)
    ) {
      return true;
    }
  }

  // 4. Shell script shebang (#!)
  if (buffer[0] === 0x23 && buffer[1] === 0x21) {
    return true;
  }

  // 5. Java class file (CA FE BA BE)
  if (
    buffer.length >= 4 &&
    buffer[0] === 0xca &&
    buffer[1] === 0xfe &&
    buffer[2] === 0xba &&
    buffer[3] === 0xbe
  ) {
    return true;
  }

  // 6. Text-based script / HTML payload sniffing
  const preview = buffer.subarray(0, Math.min(buffer.length, 1024)).toString('utf-8').toLowerCase();
  if (
    preview.includes('<script') ||
    preview.includes('<?php') ||
    preview.includes('<html') ||
    preview.includes('eval(') ||
    preview.includes('cmd.exe') ||
    preview.includes('/bin/sh') ||
    preview.includes('/bin/bash')
  ) {
    return true;
  }

  return false;
}

export interface ImageValidationResult {
  mimeType: AllowedImageMimeType;
  extension: string;
  sizeBytes: number;
}

/**
 * Validates image buffer strictly against:
 * 1. Maximum file size (5MB)
 * 2. Executable and hostile script patterns
 * 3. Verified magic bytes matching allowed MIME types (JPEG, PNG, WebP)
 * 4. Declared MIME type consistency (if provided)
 */
export function validateImageBuffer(
  buffer: Buffer,
  options?: {
    maxSizeBytes?: number;
    declaredMimeType?: string;
  }
): ImageValidationResult {
  const maxBytes = options?.maxSizeBytes ?? MAX_PRODUCT_IMAGE_SIZE_BYTES;

  // 1. Oversized check
  if (buffer.length > maxBytes) {
    throw new PayloadTooLargeError(
      `File size (${buffer.length} bytes) exceeds maximum allowed limit of ${maxBytes} bytes (5MB)`
    );
  }

  if (buffer.length === 0) {
    throw new ValidationError(
      [{ field: 'file', message: 'File is empty' }],
      'Image upload validation failed'
    );
  }

  // 2. Reject executables, scripts, and shell files
  if (isExecutableOrHostile(buffer)) {
    throw new ValidationError(
      [{ field: 'file', message: 'Executables, scripts, and binary programs are strictly forbidden' }],
      'Validation failed'
    );
  }

  // 3. True MIME type detection via magic bytes
  const detectedMime = detectImageMimeType(buffer);
  if (!detectedMime) {
    throw new ValidationError(
      [
        {
          field: 'file',
          message:
            'Unsupported file format or invalid magic bytes. Only JPEG, PNG, and WebP images are permitted',
        },
      ],
      'Unsupported file format'
    );
  }

  // 4. Declared MIME type consistency
  if (options?.declaredMimeType) {
    const declared = options.declaredMimeType.trim().toLowerCase();
    if (!ALLOWED_IMAGE_MIME_TYPES.includes(declared as AllowedImageMimeType)) {
      throw new ValidationError(
        [
          {
            field: 'mimeType',
            message: `MIME type '${options.declaredMimeType}' is unsupported. Only JPEG, PNG, and WebP are allowed`,
          },
        ],
        'Unsupported MIME type'
      );
    }

    if (declared !== detectedMime) {
      throw new ValidationError(
        [
          {
            field: 'file',
            message: `Declared MIME type '${options.declaredMimeType}' does not match detected file content ('${detectedMime}')`,
          },
        ],
        'MIME type mismatch'
      );
    }
  }

  return {
    mimeType: detectedMime,
    extension: EXTENSION_MAP[detectedMime],
    sizeBytes: buffer.length,
  };
}

/**
 * Validates that an image buffer does not exceed the maximum allowed pixel count (40 megapixels).
 * Protects against decompression bombs and excessive memory consumption from huge dimensions.
 */
export async function validateImagePixelLimit(
  buffer: Buffer,
  maxPixels: number = MAX_IMAGE_PIXELS
): Promise<{ width?: number; height?: number }> {
  try {
    const meta = await sharp(buffer, { limitInputPixels: maxPixels }).metadata();
    if (meta.width && meta.height && meta.width * meta.height > maxPixels) {
      throw new ValidationError(
        [
          {
            field: 'file',
            message: `Image dimensions (${meta.width}x${meta.height} = ${meta.width * meta.height} pixels) exceed the maximum allowed limit of ${maxPixels} pixels (40 megapixels)`,
          },
        ],
        'Image dimensions exceed maximum pixel limit'
      );
    }
    return { width: meta.width, height: meta.height };
  } catch (err: unknown) {
    if (err instanceof ValidationError) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.toLowerCase().includes('pixel limit') || msg.toLowerCase().includes('exceeds')) {
      throw new ValidationError(
        [
          {
            field: 'file',
            message: `Image dimensions exceed the maximum allowed limit of ${maxPixels} pixels (40 megapixels)`,
          },
        ],
        'Image dimensions exceed maximum pixel limit'
      );
    }
    throw err;
  }
}

/**
 * Strips EXIF, IPTC, and XMP metadata from an image buffer using Sharp.
 * Prevents camera metadata, geolocation coordinates, and personal device information leaks.
 * Enforces limitInputPixels (40 million) to reject oversized-dimension images.
 */
export async function stripImageMetadata(
  buffer: Buffer,
  mimeType: AllowedImageMimeType,
  maxPixels: number = MAX_IMAGE_PIXELS
): Promise<Buffer> {
  try {
    // Sharp strips EXIF, GPS, and metadata by default unless .withMetadata() is explicitly called
    // limitInputPixels restricts input image dimensions to 40 megapixels
    const pipeline = sharp(buffer, { limitInputPixels: maxPixels });

    if (mimeType === 'image/jpeg') {
      return await pipeline.jpeg({ quality: 90 }).toBuffer();
    } else if (mimeType === 'image/png') {
      return await pipeline.png({ compressionLevel: 8 }).toBuffer();
    } else if (mimeType === 'image/webp') {
      return await pipeline.webp({ quality: 90 }).toBuffer();
    }

    return await pipeline.toBuffer();
  } catch (err: unknown) {
    if (err instanceof Error) {
      const msg = err.message.toLowerCase();
      if (msg.includes('pixel limit') || msg.includes('exceeds')) {
        throw new ValidationError(
          [
            {
              field: 'file',
              message: `Image dimensions exceed the maximum allowed limit of ${maxPixels} pixels (40 megapixels)`,
            },
          ],
          'Image dimensions exceed maximum pixel limit'
        );
      }
    }
    logger.warn('Sharp metadata stripping failed or not supported for this buffer; falling back', {
      error: err instanceof Error ? err.message : String(err),
    });
    return buffer;
  }
}

/**
 * Generates an unpredictable, cryptographically random UUID filename
 * and relative Supabase Storage path. Never retains client-supplied filenames.
 */
export function generateRandomUuidStoragePath(
  extension: string,
  prefix: string = 'catalog'
): { fileName: string; storagePath: string } {
  const safeExt = extension.startsWith('.') ? extension : `.${extension}`;
  const uuid = crypto.randomUUID();
  const fileName = `${uuid}${safeExt}`;
  const storagePath = `${prefix}/${fileName}`;

  return { fileName, storagePath };
}
