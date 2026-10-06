import { NextRequest, NextResponse } from 'next/server';
import { AUTH_ACCESS_COOKIE } from '@/lib/auth/cookies';
import { ForbiddenError } from '@/lib/errors/api-error';
import { secureTimingSafeEqual, generateSecureToken } from '@/lib/crypto';

export const CSRF_COOKIE_NAME = 'da-csrf-token';
export const CSRF_HEADER_NAME = 'x-csrf-token';

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Determines whether a request is authenticated via httpOnly session cookie
 * without an explicit Bearer authorization header.
 */
export function isCookieAuthenticatedMutation(req: NextRequest): boolean {
  if (!MUTATION_METHODS.has(req.method.toUpperCase())) {
    return false;
  }

  // If a Bearer Authorization header is explicitly provided, the request is not
  // relying on browser-automatic ambient credentials and is inherently immune to CSRF.
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return false;
  }

  const accessCookie = req.cookies.get(AUTH_ACCESS_COOKIE);
  return Boolean(accessCookie && accessCookie.value);
}

/**
 * Verifies that the Origin or Referer header matches the server's expected origin.
 */
export function verifyOrigin(req: NextRequest): boolean {
  const origin = req.headers.get('origin');
  const referer = req.headers.get('referer');

  const incomingOrigin = origin || (referer ? extractOriginFromUrl(referer) : null);
  if (!incomingOrigin) {
    return false;
  }

  try {
    const incomingUrl = new URL(incomingOrigin);

    // Host matching
    const host = req.headers.get('host') || req.nextUrl.host;
    if (incomingUrl.host === host) {
      return true;
    }

    // Localhost matching for dev/testing
    if (incomingUrl.hostname === 'localhost' || incomingUrl.hostname === '127.0.0.1') {
      return true;
    }

    // Explicit API_BASE_URL matching if configured
    if (process.env.API_BASE_URL) {
      const configuredUrl = new URL(process.env.API_BASE_URL);
      if (incomingUrl.origin === configuredUrl.origin) {
        return true;
      }
    }
  } catch {
    return false;
  }

  return false;
}

function extractOriginFromUrl(urlStr: string): string | null {
  try {
    return new URL(urlStr).origin;
  } catch {
    return null;
  }
}

/**
 * Compares the client's CSRF token header against the anti-CSRF cookie using
 * constant-time equality to prevent timing attacks.
 */
export function verifyCsrfToken(req: NextRequest): boolean {
  const headerToken = req.headers.get(CSRF_HEADER_NAME) || req.headers.get('x-xsrf-token');
  const cookieToken = req.cookies.get(CSRF_COOKIE_NAME)?.value;

  if (!headerToken || !cookieToken) {
    return false;
  }

  return secureTimingSafeEqual(headerToken.trim(), cookieToken.trim());
}

/**
 * Enforces CSRF origin and token checks for cookie-authenticated mutations.
 * Throws ForbiddenError (403) if checks fail.
 */
export function assertCsrfProtection(req: NextRequest): void {
  if (!isCookieAuthenticatedMutation(req)) {
    return;
  }

  // 1. Origin verification
  if (!verifyOrigin(req)) {
    throw new ForbiddenError('CSRF check failed: invalid, mismatched, or missing request origin');
  }

  // 2. Anti-CSRF token verification
  if (!verifyCsrfToken(req)) {
    throw new ForbiddenError('CSRF check failed: missing or invalid CSRF token');
  }
}

/**
 * Generates a cryptographically strong, high-entropy CSRF token.
 */
export function generateCsrfToken(): string {
  return generateSecureToken(32);
}

/**
 * Attaches the CSRF token cookie to an outgoing HTTP response.
 */
export function setCsrfCookie(res: NextResponse, token: string): void {
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookies.set({
    name: CSRF_COOKIE_NAME,
    value: token,
    httpOnly: false, // Must be readable by client JS to send in X-CSRF-Token header
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 3600 * 24, // 24 hours
  });
}
