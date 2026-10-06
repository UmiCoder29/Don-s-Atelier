import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { generateCsrfToken, setCsrfCookie } from '@/lib/security/csrf';

/**
 * GET /api/auth/csrf
 * Generates an anti-CSRF token and sets the da-csrf-token cookie.
 * Client web applications include this token in the X-CSRF-Token header
 * for any subsequent cookie-authenticated mutation requests.
 */
export const GET = withErrorHandler(async (_req: NextRequest, _context, requestId) => {
  const token = generateCsrfToken();
  const response = successResponse({ csrfToken: token }, requestId);
  setCsrfCookie(response, token);
  return response;
});
