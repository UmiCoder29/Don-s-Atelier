import { describe, it, expect } from 'vitest';
import {
  generateOrderNumber,
  computeHmacSha256,
  secureTimingSafeEqual,
  generateSecureToken,
} from '@/lib/crypto';
import { paymentProvider } from '@/services/payment';
import { suitMeasurementsSchema, shippingAddressSchema } from '@/lib/validation/zod-helpers';

describe('Crypto & Payment Provider Services', () => {
  describe('Crypto Helpers', () => {
    it('generates order numbers in the DA-{YEAR}-{HEX} format', () => {
      const orderNumber = generateOrderNumber();
      const currentYear = new Date().getFullYear();
      expect(orderNumber).toMatch(new RegExp(`^DA-${currentYear}-[0-9A-F]{6}$`));
    });

    it('computes correct HMAC-SHA256 signatures', () => {
      const payload = 'order_123_payload';
      const secret = 'super_secret_webhook_key';
      const hmac = computeHmacSha256(payload, secret);

      expect(hmac).toHaveLength(64); // 32 bytes in hex = 64 characters
      expect(computeHmacSha256(payload, secret)).toBe(hmac);
    });

    it('safely compares tokens using constant-time equality', () => {
      const tokenA = generateSecureToken(32);
      const tokenB = generateSecureToken(32);

      expect(secureTimingSafeEqual(tokenA, tokenA)).toBe(true);
      expect(secureTimingSafeEqual(tokenA, tokenB)).toBe(false);
      expect(secureTimingSafeEqual(tokenA, 'short')).toBe(false);
    });
  });

  describe('Payment Provider (PCI Compliant)', () => {
    it('creates a Stripe-shaped PaymentIntent without handling raw card numbers', async () => {
      const paymentIntent = await paymentProvider.createPaymentIntent({
        amountInCents: 185000, // $1,850.00 for bespoke wool suit
        currency: 'usd',
        orderId: 'order-uuid-1234',
        customerEmail: 'customer@example.com',
      });

      expect(paymentIntent.id).toMatch(/^pi_mock_/);
      expect(paymentIntent.clientSecret).toContain(paymentIntent.id);
      expect(paymentIntent.amountInCents).toBe(185000);
      expect(paymentIntent.currency).toBe('usd');
      expect(paymentIntent.status).toBe('requires_payment_method');
    });

    it('confirms a simulated payment without storing or returning any card data', async () => {
      const result = await paymentProvider.confirmPayment({
        paymentIntentId: 'pi_mock_123',
      });

      expect(result.status).toBe('succeeded');
      expect(result.transactionId).toBeDefined();
      // Enforce zero card data policy: cardLast4 and cardBrand must not exist
      expect('cardLast4' in result).toBe(false);
      expect('cardBrand' in result).toBe(false);
    });
  });

  describe('Suit Validation Schemas', () => {
    it('validates comprehensive bespoke suit measurements', () => {
      const validMeasurements = {
        chestInInches: 40.5,
        waistInInches: 34.0,
        hipsInInches: 41.0,
        shoulderWidthInInches: 18.5,
        sleeveLengthInInches: 25.0,
        jacketLengthInInches: 30.0,
        trouserInseamInInches: 32.0,
        trouserOutseamInInches: 42.0,
      };

      const parsed = suitMeasurementsSchema.safeParse(validMeasurements);
      expect(parsed.success).toBe(true);
    });

    it('rejects negative or missing required measurements', () => {
      const invalidMeasurements = {
        chestInInches: -10,
        waistInInches: 34.0,
      };

      const parsed = suitMeasurementsSchema.safeParse(invalidMeasurements);
      expect(parsed.success).toBe(false);
    });

    it('validates customer shipping addresses', () => {
      const validAddress = {
        recipientName: 'James Bond',
        streetLine1: '30 Savile Row',
        city: 'London',
        stateOrProvince: 'Greater London',
        postalCode: 'W1S 3PT',
        country: 'GB',
        phone: '+442071234567',
      };

      const parsed = shippingAddressSchema.safeParse(validAddress);
      expect(parsed.success).toBe(true);
    });
  });
});
