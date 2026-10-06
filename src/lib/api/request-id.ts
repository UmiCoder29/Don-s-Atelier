import { randomUUID } from 'crypto';
import { NextRequest } from 'next/server';

export const REQUEST_ID_HEADER = 'x-request-id';

/**
 * Extracts an existing request ID from headers or generates a secure UUIDv4.
 */
export function getOrCreateRequestId(req?: NextRequest): string {
  if (req) {
    const existingId = req.headers.get(REQUEST_ID_HEADER);
    if (existingId && isValidRequestId(existingId)) {
      return existingId;
    }
  }
  return randomUUID();
}

/**
 * Validates request ID to ensure it is safe and does not contain malicious characters.
 */
function isValidRequestId(id: string): boolean {
  // Allow alphanumeric characters, hyphens, and underscores up to 64 chars
  return /^[a-zA-Z0-9\-_]{1,64}$/.test(id);
}
