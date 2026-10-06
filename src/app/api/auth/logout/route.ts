import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { getAccessTokenFromRequest, clearAuthCookies } from '@/lib/auth/cookies';
import { extractClientMetadata } from '@/lib/audit/audit-logger';
import { getSession } from '@/lib/auth/supabase-auth';

/**
 * POST /api/auth/logout
 * Invalidates current session and clears httpOnly auth cookies.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const token = getAccessTokenFromRequest(req);
  const clientMeta = extractClientMetadata(req);
  const session = await getSession(req);

  if (token) {
    await authService.logout(token, {
      ...clientMeta,
      actorId: session?.user.id,
    });
  }

  const response = successResponse({ message: 'Successfully logged out' }, requestId);
  clearAuthCookies(response);
  return response;
});
