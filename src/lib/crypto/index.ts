import crypto from 'crypto';

/**
 * Generates a unique, high-entropy business order number for Don's Atelier.
 * Format: DA-{YEAR}-{RANDOM_HEX_6} (e.g. DA-2026-8A3F9C)
 */
export function generateOrderNumber(): string {
  const year = new Date().getFullYear();
  const randomSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `DA-${year}-${randomSuffix}`;
}

/**
 * Generates a unique business order number for bespoke custom requests.
 * Format: CO-{YEAR}-{RANDOM_HEX_6} (e.g. CO-2026-F9B2A1)
 */
export function generateCustomOrderNumber(): string {
  const year = new Date().getFullYear();
  const randomSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `CO-${year}-${randomSuffix}`;
}

/**
 * Computes a SHA-256 HMAC digest for webhook verification or signing.
 */
export function computeHmacSha256(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Performs a constant-time comparison to protect against timing attacks.
 */
export function secureTimingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generates a cryptographically random token string.
 */
export function generateSecureToken(byteLength: number = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

export * from './field-encryption';

