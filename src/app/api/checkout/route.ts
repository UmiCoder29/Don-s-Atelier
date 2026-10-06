import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireVerifiedUser } from '@/lib/auth/supabase-auth';
import { orderService } from '@/services/order/order-service';
import { checkoutSchema } from '@/services/order/types';
import { BadRequestError } from '@/lib/errors/api-error';

/**
 * POST /api/checkout
 * Executes atomic checkout for authenticated & verified customer:
 * - Requires verified user (enforced in requireVerifiedUser)
 * - Requires valid shipping address (validated with strict Zod schema)
 * - Requires Idempotency-Key header (prevents duplicate orders)
 * - Executes in ONE database transaction: re-validates cart, locks/decrements stock,
 *   computes totals server-side, creates Order + OrderItem snapshots, creates Payment.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireVerifiedUser(req);

  // Require idempotency key header
  const idempotencyKey =
    req.headers.get('idempotency-key') ||
    req.headers.get('x-idempotency-key');

  if (!idempotencyKey || idempotencyKey.trim().length < 8) {
    throw new BadRequestError('Idempotency-Key header is required for checkout (minimum 8 characters)');
  }

  const body = await req.json();
  const input = checkoutSchema.parse(body);

  const result = await orderService.checkout(user, input, idempotencyKey);
  return successResponse(result, requestId, {}, 201);
});
