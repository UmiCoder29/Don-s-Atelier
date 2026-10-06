import crypto from 'crypto';

/**
 * Don's Atelier - Application-Level AES-256-GCM Field Encryption Utility.
 *
 * Provides cryptographic protection at rest for sensitive data:
 * - Customer telephone numbers
 * - Customer shipping and billing addresses
 * - Bespoke anatomical body measurements
 *
 * Specifications:
 * - Algorithm: AES-256-GCM (Authenticated Encryption with Associated Data)
 * - Key: 256-bit (32 bytes) retrieved from environment variable
 * - IV: 96-bit (12 bytes) cryptographically random per encryption operation
 * - Tag: 128-bit (16 bytes) authentication tag verifying ciphertext integrity
 * - Format: enc:<keyId>:<ivHex>:<tagHex>:<ciphertextHex>
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96 bits standard for AES-GCM
const DEFAULT_KEY_ID = 'v1';

// Internal fallback key for test environments when env var is absent
const TEST_FALLBACK_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Test override state
let testKeysOverride: Record<string, Buffer> | null = null;
let testActiveKeyIdOverride: string | null = null;

/**
 * Normalizes a 32-byte key from either hex, base64, or raw UTF-8 string.
 */
function normalizeKey(rawKey: string): Buffer {
  const trimmed = rawKey.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }
  const base64Buf = Buffer.from(trimmed, 'base64');
  if (base64Buf.length === 32) {
    return base64Buf;
  }
  const utf8Buf = Buffer.from(trimmed, 'utf-8');
  if (utf8Buf.length >= 32) {
    return utf8Buf.subarray(0, 32);
  }
  throw new Error(`Invalid encryption key length: expected 32 bytes (256 bits), received ${utf8Buf.length} bytes`);
}

/**
 * Retrieves the current keyring and active key version.
 */
export function getKeyRing(): { activeKeyId: string; keys: Map<string, Buffer> } {
  if (testKeysOverride && testActiveKeyIdOverride) {
    const keysMap = new Map<string, Buffer>();
    for (const [id, buf] of Object.entries(testKeysOverride)) {
      keysMap.set(id, buf);
    }
    return { activeKeyId: testActiveKeyIdOverride, keys: keysMap };
  }

  const keysMap = new Map<string, Buffer>();
  let activeKeyId = process.env.FIELD_ENCRYPTION_ACTIVE_KEY_ID || DEFAULT_KEY_ID;

  // 1. Check for multi-key JSON dictionary: FIELD_ENCRYPTION_KEYS='{"v1":"...", "v2":"..."}'
  if (process.env.FIELD_ENCRYPTION_KEYS) {
    try {
      const parsed = JSON.parse(process.env.FIELD_ENCRYPTION_KEYS);
      for (const [kId, kVal] of Object.entries(parsed)) {
        if (typeof kVal === 'string') {
          keysMap.set(kId, normalizeKey(kVal));
        }
      }
    } catch {
      // Fall through to single key if JSON parse fails
    }
  }

  // 2. Check for single key in FIELD_ENCRYPTION_KEY
  if (process.env.FIELD_ENCRYPTION_KEY) {
    const raw = process.env.FIELD_ENCRYPTION_KEY.trim();
    if (raw.includes(':') && !raw.startsWith('{')) {
      const [kId, kVal] = raw.split(':');
      keysMap.set(kId, normalizeKey(kVal));
      if (!process.env.FIELD_ENCRYPTION_ACTIVE_KEY_ID) {
        activeKeyId = kId;
      }
    } else {
      keysMap.set(DEFAULT_KEY_ID, normalizeKey(raw));
    }
  }

  // 3. Fallback for test/local development if no keys were configured
  if (keysMap.size === 0) {
    keysMap.set(DEFAULT_KEY_ID, Buffer.from(TEST_FALLBACK_KEY_HEX, 'hex'));
  }

  if (!keysMap.has(activeKeyId)) {
    // If designated activeKeyId is missing, pick the first available
    activeKeyId = Array.from(keysMap.keys())[0];
  }

  return { activeKeyId, keys: keysMap };
}

/**
 * Allows tests to supply explicit mock keys and active key IDs.
 */
export function setEncryptionKeysForTesting(keys: Record<string, string>, activeKeyId: string): void {
  const normalized: Record<string, Buffer> = {};
  for (const [id, val] of Object.entries(keys)) {
    normalized[id] = normalizeKey(val);
  }
  testKeysOverride = normalized;
  testActiveKeyIdOverride = activeKeyId;
}

/**
 * Resets any test key overrides.
 */
export function resetEncryptionKeysForTesting(): void {
  testKeysOverride = null;
  testActiveKeyIdOverride = null;
}

/**
 * Determines whether a string is an encrypted field payload.
 */
export function isEncrypted(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return value.startsWith('enc:') && value.split(':').length === 5;
}

/**
 * Encrypts a plaintext string or number using AES-256-GCM with a random IV.
 * Returns formatted ciphertext: enc:<keyId>:<ivHex>:<tagHex>:<ciphertextHex>
 */
export function encryptField(plaintext: string | number, keyId?: string): string {
  const text = String(plaintext);
  const { activeKeyId, keys } = getKeyRing();
  const selectedKeyId = keyId || activeKeyId;
  const key = keys.get(selectedKeyId);

  if (!key) {
    throw new Error(`Encryption failed: key with ID '${selectedKeyId}' not found in keyring`);
  }

  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([cipher.update(text, 'utf-8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `enc:${selectedKeyId}:${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}

/**
 * Decrypts a ciphertext string created by encryptField.
 * If the value is not encrypted (e.g. unencrypted legacy or seed data), returns it unchanged.
 */
export function decryptField(payload: string): string {
  if (!isEncrypted(payload)) {
    return payload;
  }

  const parts = payload.split(':');
  if (parts.length !== 5) {
    throw new Error('Malformed encrypted payload structure');
  }

  const [, keyId, ivHex, tagHex, ciphertextHex] = parts;
  const { keys } = getKeyRing();
  const key = keys.get(keyId);

  if (!key) {
    throw new Error(`Decryption failed: key with ID '${keyId}' not found in keyring. Rotate or configure key.`);
  }

  try {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(tagHex, 'hex');
    const ciphertext = Buffer.from(ciphertextHex, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf-8');
  } catch (err: unknown) {
    throw new Error('Decryption failed: data may have been tampered with or corrupted (authentication tag mismatch)');
  }
}

/**
 * Encrypts a customer telephone number.
 */
export function encryptPhone(phone: string | null | undefined): string | null {
  if (!phone) return null;
  return encryptField(phone);
}

/**
 * Decrypts a customer telephone number.
 */
export function decryptPhone(phone: string | null | undefined): string | null {
  if (!phone) return null;
  return decryptField(phone);
}

/**
 * Encrypts an anatomical bespoke suit measurement value.
 */
export function encryptMeasurementValue(value: string | number): string {
  return encryptField(String(value));
}

/**
 * Decrypts an anatomical bespoke suit measurement value.
 */
export function decryptMeasurementValue(value: string): string {
  return decryptField(value);
}

/**
 * Fields considered sensitive PII in address structures.
 */
const SENSITIVE_ADDRESS_FIELDS = [
  'recipientName',
  'streetLine1',
  'streetLine2',
  'line1',
  'line2',
  'city',
  'stateOrProvince',
  'state',
  'postalCode',
  'phone',
] as const;

/**
 * Encrypts sensitive fields within an address object before storage.
 */
export function encryptAddressFields<T extends Record<string, unknown>>(address: T): T {
  if (!address || typeof address !== 'object') {
    return address;
  }

  const result: Record<string, unknown> = { ...address };

  for (const field of SENSITIVE_ADDRESS_FIELDS) {
    if (field in result && result[field] !== undefined && result[field] !== null) {
      const val = result[field];
      if (typeof val === 'string' && val.trim().length > 0 && !isEncrypted(val)) {
        result[field] = encryptField(val);
      }
    }
  }

  return result as T;
}

/**
 * Decrypts sensitive fields within an address object when presenting to authorized clients.
 */
export function decryptAddressFields<T extends Record<string, unknown>>(address: T): T {
  if (!address || typeof address !== 'object') {
    return address;
  }

  const result: Record<string, unknown> = { ...address };

  for (const field of SENSITIVE_ADDRESS_FIELDS) {
    if (field in result && result[field] !== undefined && result[field] !== null) {
      const val = result[field];
      if (typeof val === 'string' && isEncrypted(val)) {
        result[field] = decryptField(val);
      }
    }
  }

  return result as T;
}

/**
 * Rotates an encrypted value from its current key version to targetKeyId.
 */
export function rotateFieldEncryption(payload: string, targetKeyId: string): string {
  if (!isEncrypted(payload)) {
    return encryptField(payload, targetKeyId);
  }
  const plaintext = decryptField(payload);
  return encryptField(plaintext, targetKeyId);
}
