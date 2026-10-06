import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { passwordResetRequestSchema } from '@/lib/validation/auth-schemas';

/**
 * POST /api/auth/password-reset/request
 * Dispatches password reset email. Generic message prevents user enumeration.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const body = await req.json();
  const input = passwordResetRequestSchema.parse(body);

  const result = await authService.requestPasswordReset(input);
  return successResponse(result, requestId);
});
