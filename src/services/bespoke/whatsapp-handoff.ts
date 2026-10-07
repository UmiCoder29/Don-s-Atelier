import { env } from '@/lib/validation/env';

/**
 * Generates a WhatsApp wa.me direct chat link for bespoke suit handoff.
 *
 * Security & Privacy constraints:
 * - The pre-filled text contains ONLY the request reference code and a fixed greeting.
 * - Strictly NO customer name, NO measurements, NO price, NO email, NO customer phone.
 * - Properly URL-encoded using encodeURIComponent.
 * - Business number is read from validated environment variables (digits only with country code).
 *
 * @param referenceCode The unique customer-facing order reference code (e.g., "CO-2026-XXXX")
 * @returns Fully formatted wa.me URL
 */
export function generateWhatsAppHandoffUrl(referenceCode: string): string {
  const businessNumber = env.WHATSAPP_BUSINESS_NUMBER;
  const fixedGreeting = `Hello Don's Atelier, I would like to discuss my bespoke suit request ${referenceCode}.`;
  const encodedText = encodeURIComponent(fixedGreeting);
  return `https://wa.me/${businessNumber}?text=${encodedText}`;
}
