import { NextRequest, NextResponse } from 'next/server';

export const AUTH_ACCESS_COOKIE = 'sb-access-token';
export const AUTH_REFRESH_COOKIE = 'sb-refresh-token';

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}

/**
 * Attaches secure, httpOnly session cookies to an outgoing HTTP response.
 * Adheres to OWASP cookie security guidelines:
 * - httpOnly prevents XSS theft
 * - secure ensures transmission only over HTTPS in production
 * - sameSite: 'lax' protects against cross-site request forgery
 */
export function setAuthCookies(response: NextResponse, tokens: AuthTokens): void {
  const isProduction = process.env.NODE_ENV === 'production';
  const accessMaxAge = tokens.expiresIn || 3600; // default 1 hour
  const refreshMaxAge = 60 * 60 * 24 * 30; // 30 days

  response.cookies.set({
    name: AUTH_ACCESS_COOKIE,
    value: tokens.accessToken,
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: accessMaxAge,
  });

  if (tokens.refreshToken) {
    response.cookies.set({
      name: AUTH_REFRESH_COOKIE,
      value: tokens.refreshToken,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: refreshMaxAge,
    });
  }
}

/**
 * Invalidates and clears authentication cookies on logout.
 */
export function clearAuthCookies(response: NextResponse): void {
  const isProduction = process.env.NODE_ENV === 'production';

  response.cookies.set({
    name: AUTH_ACCESS_COOKIE,
    value: '',
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });

  response.cookies.set({
    name: AUTH_REFRESH_COOKIE,
    value: '',
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

/**
 * Extracts the user's access token from either:
 * 1. Authorization header: "Bearer <token>"
 * 2. httpOnly cookie: "sb-access-token"
 */
export function getAccessTokenFromRequest(req: NextRequest): string | null {
  // 1. Check Authorization header
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (token) return token;
  }

  // 2. Check httpOnly cookie
  const cookie = req.cookies.get(AUTH_ACCESS_COOKIE);
  if (cookie && cookie.value) {
    return cookie.value.trim();
  }

  return null;
}

/**
 * Extracts the refresh token from either cookie or request body.
 */
export function getRefreshTokenFromRequest(req: NextRequest): string | null {
  const cookie = req.cookies.get(AUTH_REFRESH_COOKIE);
  if (cookie && cookie.value) {
    return cookie.value.trim();
  }
  return null;
}
