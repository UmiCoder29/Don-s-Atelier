import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';
import { cartService } from '@/services/cart/cart-service';
import { updateCartItemSchema } from '@/services/cart/types';
import { uuidSchema } from '@/lib/validation/zod-helpers';

interface RouteContext {
  params: Promise<{ id: string }>;
}

/**
 * PATCH /api/cart/items/[id]
 * Updates quantity of a specific cart item.
 */
export const PATCH = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const cartItemId = uuidSchema.parse(resolvedParams.id);

  const body = await req.json();
  const input = updateCartItemSchema.parse(body);

  const cart = await cartService.updateItemQuantity(user, cartItemId, input);
  return successResponse(cart, requestId);
});

/**
 * DELETE /api/cart/items/[id]
 * Removes a specific cart item from the customer's cart.
 */
export const DELETE = withErrorHandler<RouteContext>(async (req: NextRequest, context, requestId) => {
  const user = await requireAuth(req);
  const resolvedParams = await context.params;
  const cartItemId = uuidSchema.parse(resolvedParams.id);

  const cart = await cartService.removeItem(user, cartItemId);
  return successResponse(cart, requestId);
});
