import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { cartService } from '@/services/cart/cart-service';
import { addToCartSchema } from '@/services/cart/types';

/**
 * GET /api/cart
 * Authenticated customer retrieves their current cart with server-computed prices.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const cart = await cartService.getCart(user);
  return successResponse(cart, requestId);
});

/**
 * POST /api/cart
 * Authenticated customer adds an active suit variant to their cart.
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const body = await req.json();
  const input = addToCartSchema.parse(body);

  const cart = await cartService.addItem(user, input);
  return successResponse(cart, requestId, {}, 201);
});

/**
 * DELETE /api/cart
 * Authenticated customer empties their cart.
 */
export const DELETE = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  const cart = await cartService.clearCart(user);
  return successResponse(cart, requestId);
});
