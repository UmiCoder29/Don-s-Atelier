import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { authService } from '@/services/auth/auth-service';
import { registerSchema } from '@/lib/validation/auth-schemas';
import { setAuthCookies } from '@/lib/auth/cookies';
import { extractClientMetadata } from '@/lib/audit/audit-logger';

/**
 * POST /api/auth/register
 * Registers a new customer and auto-creates their Profile with role CUSTOMER.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const body = await req.json();
  const input = registerSchema.parse(body);
  const clientMeta = extractClientMetadata(req);

  const result = await authService.register(input, clientMeta);
  const response = successResponse(result, requestId, {}, 201);

  if (result.tokens) {
    setAuthCookies(response, result.tokens);
  }

  return response;
});
