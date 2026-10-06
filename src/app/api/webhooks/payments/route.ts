import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { paymentProvider } from '@/services/payment';
import { orderService } from '@/services/order/order-service';
import { BadRequestError } from '@/lib/errors/api-error';

/**
 * POST /api/webhooks/payments
 * Webhook confirmation endpoint with HMAC signature verification:
 * - Validates Stripe-compatible signature header (t=timestamp,v1=signature) or raw HMAC hex
 * - Dispatches payment events (payment_intent.succeeded, payment_intent.payment_failed)
 * - Transitions order status to PAID or CANCELLED (restoring stock)
 * - Structured to allow zero-downtime drop-in of a production Stripe webhook handler
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const signature =
    req.headers.get('stripe-signature') ||
    req.headers.get('x-signature') ||
    req.headers.get('x-webhook-signature');

  if (!signature) {
    throw new BadRequestError('Missing payment provider webhook signature header');
  }

  const rawBody = await req.text();

  const isValid = paymentProvider.verifyWebhookSignature(rawBody, signature);
  if (!isValid) {
    throw new BadRequestError('Invalid payment provider webhook signature');
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    throw new BadRequestError('Invalid JSON in webhook payload');
  }

  const result = await orderService.handlePaymentWebhook(event);
  return successResponse(result, requestId, {}, 200);
});
