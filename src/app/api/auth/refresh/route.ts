import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { getRefreshTokenFromRequest, setAuthCookies } from '@/lib/auth/cookies';
import { refreshTokenSchema } from '@/lib/validation/auth-schemas';
import { UnauthorizedError } from '@/lib/errors/api-error';

/**
 * POST /api/auth/refresh
 * Refreshes an expired access token using httpOnly cookie or body token.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  let refreshToken = getRefreshTokenFromRequest(req);

  // If not found in cookies, check JSON body
  if (!refreshToken) {
    try {
      const body = await req.json();
      const parsed = refreshTokenSchema.parse(body);
      refreshToken = parsed.refreshToken || null;
    } catch {
      // Body may be empty if relying on cookies
    }
  }

  if (!refreshToken) {
    throw new UnauthorizedError('Refresh token is missing');
  }

  const result = await authService.refreshSession(refreshToken);
  const response = successResponse(result, requestId);

  if (result.tokens) {
    setAuthCookies(response, result.tokens);
  }

  return response;
});
