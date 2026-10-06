export type PaymentIntentStatus =
  | 'requires_payment_method'
  | 'requires_confirmation'
  | 'processing'
  | 'succeeded'
  | 'canceled'
  | 'failed';

export type PaymentSimulationStatus = 'succeeded' | 'failed' | 'pending';

export interface CreatePaymentIntentParams {
  amountInCents: number;
  currency: string;
  orderId: string;
  customerEmail: string;
  simulation?: PaymentSimulationStatus;
  metadata?: Record<string, string>;
}

export interface PaymentIntent {
  id: string;
  clientSecret: string;
  amountInCents: number;
  currency: string;
  status: PaymentIntentStatus;
  orderId: string;
}

export interface ConfirmPaymentParams {
  paymentIntentId: string;
  paymentMethodId?: string;
  idempotencyKey?: string;
  simulation?: PaymentSimulationStatus;
}

export interface PaymentResult {
  transactionId: string;
  status: 'succeeded' | 'failed';
  amountInCents: number;
  currency: string;
  receiptUrl?: string;
}

export interface RefundParams {
  transactionId: string;
  amountInCents?: number;
  reason?: string;
}

export interface RefundResult {
  refundId: string;
  status: 'succeeded' | 'pending' | 'failed';
  amountInCents: number;
}

export interface WebhookEventObject {
  id: string;
  orderId?: string;
  amountInCents?: number;
  amount?: number;
  currency?: string;
  status?: string;
  metadata?: Record<string, string>;
}

export interface WebhookEvent {
  id: string;
  type: string;
  data: {
    object: WebhookEventObject;
  };
  created: number;
}

/**
 * Stripe-shaped payment provider interface.
 * Adheres strictly to PCI-DSS: never receives or stores raw primary account numbers (PAN).
 */
export interface PaymentProvider {
  readonly providerName: string;

  createPaymentIntent(params: CreatePaymentIntentParams): Promise<PaymentIntent>;

  confirmPayment(params: ConfirmPaymentParams): Promise<PaymentResult>;

  refund(params: RefundParams): Promise<RefundResult>;

  verifyWebhookSignature(payload: string, signature: string, secret?: string): boolean;

  generateWebhookSignature(payload: string, secret?: string, timestamp?: number): string;
}
