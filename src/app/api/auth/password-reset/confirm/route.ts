import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { passwordResetConfirmSchema } from '@/lib/validation/auth-schemas';
import { getAccessTokenFromRequest } from '@/lib/auth/cookies';
import { UnauthorizedError } from '@/lib/errors/api-error';

/**
 * POST /api/auth/password-reset/confirm
 * Sets new password using authenticated recovery token.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const token = getAccessTokenFromRequest(req);
  if (!token) {
    throw new UnauthorizedError('Password recovery token is required');
  }

  const body = await req.json();
  const input = passwordResetConfirmSchema.parse(body);

  const result = await authService.confirmPasswordReset(token, input);
  return successResponse(result, requestId);
});
