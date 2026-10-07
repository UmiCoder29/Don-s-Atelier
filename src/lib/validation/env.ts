import { z } from 'zod';
import dotenv from 'dotenv';

// Ensure .env is loaded when running outside Next.js (e.g., test runner, scripts)
dotenv.config();

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  API_BASE_URL: z.string().url().default('http://localhost:3000'),

  // Supabase PostgreSQL Database (Prisma)
  DATABASE_URL: z
    .string({ required_error: 'DATABASE_URL is required' })
    .min(1, 'DATABASE_URL cannot be empty'),
  DIRECT_URL: z.string().optional(),

  // Supabase Auth and Storage API
  SUPABASE_URL: z
    .string({ required_error: 'SUPABASE_URL is required' })
    .url('SUPABASE_URL must be a valid URL'),
  SUPABASE_ANON_KEY: z
    .string({ required_error: 'SUPABASE_ANON_KEY is required' })
    .min(1, 'SUPABASE_ANON_KEY cannot be empty'),
  SUPABASE_SERVICE_ROLE_KEY: z
    .string({ required_error: 'SUPABASE_SERVICE_ROLE_KEY is required' })
    .min(1, 'SUPABASE_SERVICE_ROLE_KEY cannot be empty'),

  // Application-level AES-256-GCM Field Encryption
  FIELD_ENCRYPTION_KEY: z.string().min(32, 'FIELD_ENCRYPTION_KEY must be at least 32 characters').optional(),
  FIELD_ENCRYPTION_KEYS: z.string().optional(),
  FIELD_ENCRYPTION_ACTIVE_KEY_ID: z.string().optional(),

  // Client IP Resolution
  TRUSTED_IP_HEADER: z
    .enum(['none', 'x-vercel-forwarded-for', 'cf-connecting-ip', 'x-real-ip'])
    .default('none'),

  // WhatsApp Business Integration (digits only with country code, 7-15 digits per E.164)
  WHATSAPP_BUSINESS_NUMBER: z
    .string()
    .regex(/^\d{7,15}$/, 'WHATSAPP_BUSINESS_NUMBER must contain digits only with country code')
    .default('442079460999'),
});

export type Env = z.infer<typeof envSchema>;

/**
 * Validates environment variables and throws an informative fail-fast error
 * if required variables are missing or invalid.
 */
export function validateEnv(rawEnv: Record<string, unknown> = process.env): Env {
  const parsed = envSchema.safeParse(rawEnv);

  if (!parsed.success) {
    const errorList = parsed.error.issues
      .map((issue) => `  • [${issue.path.join('.')}]: ${issue.message}`)
      .join('\n');

    const message = `[FATAL] Missing or invalid configuration in environment variables:\n${errorList}\nCheck your .env file or refer to .env.example.`;
    throw new Error(message);
  }

  return parsed.data;
}

// Fail-fast validation on module load
export const env: Env = validateEnv();
