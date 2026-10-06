import { describe, it, expect } from 'vitest';
import { validateEnv, envSchema } from '@/lib/validation/env';

describe('Environment Configuration & Validation', () => {
  const validEnv = {
    NODE_ENV: 'test',
    PORT: '3000',
    API_BASE_URL: 'http://localhost:3000',
    DATABASE_URL: 'postgresql://postgres:pass@localhost:5432/postgres?sslmode=require',
    SUPABASE_URL: 'https://test-project.supabase.co',
    SUPABASE_ANON_KEY: 'test-anon-key-12345',
    SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key-67890',
  };

  it('successfully validates complete and correct environment variables', () => {
    const result = validateEnv(validEnv);
    expect(result.NODE_ENV).toBe('test');
    expect(result.PORT).toBe(3000);
    expect(result.SUPABASE_URL).toBe('https://test-project.supabase.co');
    expect(result.SUPABASE_ANON_KEY).toBe('test-anon-key-12345');
    expect(result.SUPABASE_SERVICE_ROLE_KEY).toBe('test-service-role-key-67890');
    expect(result.DATABASE_URL).toContain('postgresql://');
  });

  it('fails fast and throws when required variables are missing', () => {
    const incompleteEnv = {
      NODE_ENV: 'test',
      // Missing DATABASE_URL, SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
    };

    expect(() => validateEnv(incompleteEnv)).toThrowError(
      /Missing or invalid configuration in environment variables/
    );
  });

  it('fails fast when SUPABASE_URL is not a valid URL', () => {
    const invalidUrlEnv = {
      ...validEnv,
      SUPABASE_URL: 'not-a-valid-url',
    };

    expect(() => validateEnv(invalidUrlEnv)).toThrowError(/SUPABASE_URL must be a valid URL/);
  });

  it('fails fast when empty string is passed for secrets', () => {
    const emptyKeyEnv = {
      ...validEnv,
      SUPABASE_SERVICE_ROLE_KEY: '',
    };

    expect(() => validateEnv(emptyKeyEnv)).toThrowError(/SUPABASE_SERVICE_ROLE_KEY cannot be empty/);
  });

  it('validates TRUSTED_IP_HEADER with allowed values and defaults to none', () => {
    // Default
    const defaultRes = validateEnv(validEnv);
    expect(defaultRes.TRUSTED_IP_HEADER).toBe('none');

    // Allowed values
    const allowed = ['none', 'x-vercel-forwarded-for', 'cf-connecting-ip', 'x-real-ip'] as const;
    for (const val of allowed) {
      const res = validateEnv({ ...validEnv, TRUSTED_IP_HEADER: val });
      expect(res.TRUSTED_IP_HEADER).toBe(val);
    }

    // Invalid value rejected
    expect(() => validateEnv({ ...validEnv, TRUSTED_IP_HEADER: 'invalid-header' })).toThrow();
  });
});
