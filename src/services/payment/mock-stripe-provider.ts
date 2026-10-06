import { randomUUID, createHmac, timingSafeEqual } from 'crypto';
import {
  PaymentProvider,
  CreatePaymentIntentParams,
  PaymentIntent,
  ConfirmPaymentParams,
  PaymentResult,
  RefundParams,
  RefundResult,
  PaymentSimulationStatus,
} from './types';

export const DEFAULT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || 'whsec_test_secret_dons_atelier_2026';

/**
 * Mock implementation of a Stripe-shaped payment provider for Don's Atelier.
 * Simulates Stripe's PaymentIntent workflow without handling or persisting card data.
 * Supports simulating success, failure, and pending states, as well as webhook signature verification.
 */
export class MockStripePaymentProvider implements PaymentProvider {
  public readonly providerName = 'mock_stripe';
  private defaultSimulation: PaymentSimulationStatus | null = null;

  constructor(initialSimulation: PaymentSimulationStatus | null = null) {
    if (initialSimulation && process.env.NODE_ENV === 'production') {
      throw new Error('Cannot configure payment simulation in production');
    }
    this.defaultSimulation = initialSimulation;
  }

  /**
   * Helper to configure global simulation mode for tests.
   * Throws if called in production environment.
   */
  public setSimulation(simulation: PaymentSimulationStatus | null) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Cannot configure payment simulation in production');
    }
    this.defaultSimulation = simulation;
  }

  async createPaymentIntent(params: CreatePaymentIntentParams): Promise<PaymentIntent> {
    const id = `pi_mock_${randomUUID().replace(/-/g, '').substring(0, 24)}`;
    const secret = `pi_${id}_secret_${randomUUID().replace(/-/g, '').substring(0, 16)}`;

    const simulation =
      params.simulation ||
      (params.metadata?.simulation as PaymentSimulationStatus) ||
      this.defaultSimulation ||
      'pending';

    let status: PaymentIntent['status'] = 'requires_payment_method';
    if (simulation === 'succeeded') {
      status = 'succeeded';
    } else if (simulation === 'failed') {
      status = 'failed';
    } else {
      status = 'requires_payment_method';
    }

    return {
      id,
      clientSecret: secret,
      amountInCents: params.amountInCents,
      currency: params.currency.toLowerCase(),
      status,
      orderId: params.orderId,
    };
  }

  async confirmPayment(params: ConfirmPaymentParams): Promise<PaymentResult> {
    const simulation =
      params.simulation ||
      (params.paymentMethodId === 'pm_card_declined' ? 'failed' : null) ||
      this.defaultSimulation ||
      'succeeded';

    if (simulation === 'failed') {
      const transactionId = `ch_mock_failed_${randomUUID().replace(/-/g, '').substring(0, 20)}`;
      return {
        transactionId,
        status: 'failed',
        amountInCents: 0,
        currency: 'usd',
      };
    }

    const transactionId = `ch_mock_${randomUUID().replace(/-/g, '').substring(0, 24)}`;
    return {
      transactionId,
      status: 'succeeded',
      amountInCents: 10000,
      currency: 'usd',
      receiptUrl: `https://pay.dons-atelier.com/receipts/${transactionId}`,
    };
  }

  async refund(params: RefundParams): Promise<RefundResult> {
    return {
      refundId: `re_mock_${randomUUID().replace(/-/g, '').substring(0, 24)}`,
      status: 'succeeded',
      amountInCents: params.amountInCents ?? 0,
    };
  }

  /**
   * Generates a signed webhook signature using HMAC-SHA256 matching Stripe format:
   * t=timestamp,v1=signature
   */
  generateWebhookSignature(
    payload: string,
    secret: string = DEFAULT_WEBHOOK_SECRET,
    timestamp: number = Math.floor(Date.now() / 1000)
  ): string {
    const signedPayload = `${timestamp}.${payload}`;
    const hmac = createHmac('sha256', secret).update(signedPayload).digest('hex');
    return `t=${timestamp},v1=${hmac}`;
  }

  /**
   * Verifies webhook signature against payload and secret with constant-time equality.
   */
  verifyWebhookSignature(
    payload: string,
    signatureHeader: string,
    secret: string = DEFAULT_WEBHOOK_SECRET
  ): boolean {
    if (!signatureHeader || !payload) return false;

    // Standard Stripe-style signature header: t=timestamp,v1=sig
    if (signatureHeader.includes('v1=')) {
      const parts = signatureHeader.split(',').reduce<Record<string, string>>((acc, part) => {
        const [k, v] = part.split('=');
        if (k && v) acc[k.trim()] = v.trim();
        return acc;
      }, {});

      const timestamp = parts.t;
      const signature = parts.v1;
      if (!timestamp || !signature) return false;

      // Replay attack window: 5 minutes (300 seconds)
      const now = Math.floor(Date.now() / 1000);
      const ts = parseInt(timestamp, 10);
      if (isNaN(ts) || Math.abs(now - ts) > 300) {
        return false;
      }

      const expectedHmac = createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('hex');
      const sigBuf = Buffer.from(signature, 'hex');
      const expectedBuf = Buffer.from(expectedHmac, 'hex');
      if (sigBuf.length !== expectedBuf.length) return false;
      return timingSafeEqual(sigBuf, expectedBuf);
    }

    // Direct hex HMAC fallback
    try {
      const expectedHmac = createHmac('sha256', secret).update(payload).digest('hex');
      const sigBuf = Buffer.from(signatureHeader, 'hex');
      const expectedBuf = Buffer.from(expectedHmac, 'hex');
      if (sigBuf.length !== expectedBuf.length) return false;
      return timingSafeEqual(sigBuf, expectedBuf);
    } catch {
      return false;
    }
  }
}

export const paymentProvider: PaymentProvider = new MockStripePaymentProvider();

