import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { loginSchema } from '@/lib/validation/auth-schemas';
import { setAuthCookies } from '@/lib/auth/cookies';
import { extractClientMetadata } from '@/lib/audit/audit-logger';

/**
 * POST /api/auth/login
 * Authenticates user, returns user profile, and sets httpOnly secure cookies.
 * Adheres to generic error messages to eliminate user enumeration.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const body = await req.json();
  const input = loginSchema.parse(body);
  const clientMeta = extractClientMetadata(req);

  const result = await authService.login(input, clientMeta);
  const response = successResponse(result, requestId);

  if (result.tokens) {
    setAuthCookies(response, result.tokens);
  }

  return response;
});
