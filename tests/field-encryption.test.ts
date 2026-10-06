import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  encryptField,
  decryptField,
  isEncrypted,
  encryptPhone,
  decryptPhone,
  encryptMeasurementValue,
  decryptMeasurementValue,
  encryptAddressFields,
  decryptAddressFields,
  rotateFieldEncryption,
  setEncryptionKeysForTesting,
  resetEncryptionKeysForTesting,
} from '@/lib/crypto/field-encryption';

describe('Field-Level AES-256-GCM Encryption Utility', () => {
  const testKeyV1Hex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const testKeyV2Hex = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

  beforeEach(() => {
    setEncryptionKeysForTesting(
      {
        v1: testKeyV1Hex,
        v2: testKeyV2Hex,
      },
      'v1'
    );
  });

  afterEach(() => {
    resetEncryptionKeysForTesting();
  });

  describe('Core AES-256-GCM Operations', () => {
    it('encrypts and successfully decrypts string values', () => {
      const sensitiveText = 'Customer Secret Data 2026';
      const encrypted = encryptField(sensitiveText);

      expect(isEncrypted(encrypted)).toBe(true);
      expect(encrypted).toMatch(/^enc:v1:[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/);
      expect(encrypted).not.toContain(sensitiveText);

      const decrypted = decryptField(encrypted);
      expect(decrypted).toBe(sensitiveText);
    });

    it('generates unique ciphertexts for identical plaintexts (random IV requirement)', () => {
      const text = '+44 20 7946 0991';
      const enc1 = encryptField(text);
      const enc2 = encryptField(text);

      expect(enc1).not.toBe(enc2);

      // Both must decrypt to the exact original plaintext
      expect(decryptField(enc1)).toBe(text);
      expect(decryptField(enc2)).toBe(text);
    });

    it('detects tampering and throws an error if ciphertext or tag is modified', () => {
      const encrypted = encryptField('Confidential Bespoke Fitting Notes');
      const parts = encrypted.split(':');

      // Alter the ciphertext portion
      const tamperedCiphertext = parts[4].slice(0, -2) + (parts[4].slice(-2) === 'aa' ? 'bb' : 'aa');
      const tamperedPayload = `${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}:${tamperedCiphertext}`;

      expect(() => decryptField(tamperedPayload)).toThrow(/tampered with or corrupted/);

      // Alter the authentication tag portion
      const tamperedTag = parts[3].slice(0, -2) + (parts[3].slice(-2) === '11' ? '22' : '11');
      const tamperedTagPayload = `${parts[0]}:${parts[1]}:${parts[2]}:${tamperedTag}:${parts[4]}`;

      expect(() => decryptField(tamperedTagPayload)).toThrow(/tampered with or corrupted/);
    });

    it('gracefully returns unencrypted plain text (legacy / non-encrypted data)', () => {
      const plaintext = 'Standard Unencrypted Legacy Address';
      expect(isEncrypted(plaintext)).toBe(false);
      expect(decryptField(plaintext)).toBe(plaintext);
    });
  });

  describe('Entity-Specific Encryption Helpers', () => {
    it('encrypts and decrypts telephone numbers', () => {
      const phone = '+1 (555) 234-5678';
      const encrypted = encryptPhone(phone);
      expect(isEncrypted(encrypted)).toBe(true);
      expect(decryptPhone(encrypted)).toBe(phone);

      expect(encryptPhone(null)).toBeNull();
      expect(decryptPhone(null)).toBeNull();
    });

    it('encrypts and decrypts bespoke anatomical measurements', () => {
      const chestMeasurement = 42.5;
      const encrypted = encryptMeasurementValue(chestMeasurement);
      expect(isEncrypted(encrypted)).toBe(true);

      const decrypted = decryptMeasurementValue(encrypted);
      expect(decrypted).toBe('42.5');
    });

    it('encrypts and decrypts address object sensitive fields while preserving non-sensitive fields', () => {
      const rawAddress = {
        recipientName: 'Lord Alistair Sterling',
        streetLine1: '14 Savile Row',
        streetLine2: 'Suite 3B',
        city: 'London',
        stateOrProvince: 'Greater London',
        postalCode: 'W1S 3JN',
        country: 'GB',
        phone: '+44 20 7123 4567',
        isDefault: true,
      };

      const encrypted = encryptAddressFields(rawAddress);

      // Sensitive fields must be encrypted
      expect(isEncrypted(encrypted.recipientName)).toBe(true);
      expect(isEncrypted(encrypted.streetLine1)).toBe(true);
      expect(isEncrypted(encrypted.streetLine2)).toBe(true);
      expect(isEncrypted(encrypted.city)).toBe(true);
      expect(isEncrypted(encrypted.stateOrProvince)).toBe(true);
      expect(isEncrypted(encrypted.postalCode)).toBe(true);
      expect(isEncrypted(encrypted.phone)).toBe(true);

      // Non-sensitive fields remain unchanged
      expect(encrypted.country).toBe('GB');
      expect(encrypted.isDefault).toBe(true);

      // Decrypt recovers original values
      const decrypted = decryptAddressFields(encrypted);
      expect(decrypted).toEqual(rawAddress);
    });
  });

  describe('Key Versioning and Key Rotation', () => {
    it('supports decrypting payloads encrypted with older key versions', () => {
      // Encrypt with v1
      const payloadV1 = encryptField('Legacy Customer Phone', 'v1');
      expect(payloadV1.startsWith('enc:v1:')).toBe(true);

      // Encrypt with v2
      const payloadV2 = encryptField('New Customer Phone', 'v2');
      expect(payloadV2.startsWith('enc:v2:')).toBe(true);

      // Both can be decrypted concurrently using the keyring
      expect(decryptField(payloadV1)).toBe('Legacy Customer Phone');
      expect(decryptField(payloadV2)).toBe('New Customer Phone');
    });

    it('rotates ciphertext from old key version to target key version', () => {
      const originalText = '40 Savile Row, London';
      const originalV1Payload = encryptField(originalText, 'v1');
      expect(originalV1Payload.startsWith('enc:v1:')).toBe(true);

      // Rotate to v2
      const rotatedV2Payload = rotateFieldEncryption(originalV1Payload, 'v2');
      expect(rotatedV2Payload.startsWith('enc:v2:')).toBe(true);
      expect(rotatedV2Payload).not.toBe(originalV1Payload);

      // Verify decrypted content remains intact
      expect(decryptField(rotatedV2Payload)).toBe(originalText);
    });
  });
});
