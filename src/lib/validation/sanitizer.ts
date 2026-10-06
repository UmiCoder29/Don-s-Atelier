import { z } from 'zod';

/**
 * Strips HTML tags, script blocks, style blocks, null bytes, and malicious
 * pseudo-protocols from user-submitted free-text to prevent XSS and injection.
 */
export function sanitizeText(input: unknown): string {
  if (typeof input !== 'string') {
    return '';
  }

  return input
    // 1. Remove null bytes
    .replace(/\0/g, '')
    // 2. Remove <script> tags and all content inside
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    // 3. Remove <style> tags and all content inside
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    // 4. Strip any remaining HTML tags
    .replace(/<[^>]*>?/gm, '')
    // 5. Remove javascript: or vbscript: or data: pseudo-protocols
    .replace(/(javascript|vbscript|data):/gi, '')
    // 6. Normalize Unicode (NFKC)
    .normalize('NFKC')
    // 7. Trim whitespace
    .trim();
}

/**
 * Zod helper that preprocesses and sanitizes strings.
 */
export function sanitizedString(schema: z.ZodString = z.string()) {
  return z.preprocess((val) => (typeof val === 'string' ? sanitizeText(val) : val), schema);
}
