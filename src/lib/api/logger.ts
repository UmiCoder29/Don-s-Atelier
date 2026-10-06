import { env } from '@/lib/validation/env';

export interface LogContext {
  requestId?: string;
  method?: string;
  path?: string;
  statusCode?: number;
  durationMs?: number;
  error?: unknown;
  [key: string]: unknown;
}

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'password',
  'secret',
  'token',
  'apikey',
  'service_role',
  'cardnumber',
  'cvv',
  'cardlast4',
  'cardbrand',
  // Sensitive PII & biometrics designated for encryption at rest
  'phone',
  'phonenumber',
  'shippingaddress',
  'measurements',
  'streetline1',
  'streetline2',
  'postalcode',
  'recipientname',
]);

/**
 * Sanitizes an object to redact any sensitive credentials or keys.
 */
function sanitize(obj: unknown): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitize);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = sanitize(value);
    }
  }
  return sanitized;
}

export const logger = {
  info(message: string, context?: LogContext): void {
    const payload = {
      level: 'info',
      service: "Don's Atelier",
      timestamp: new Date().toISOString(),
      message,
      ...(context ? (sanitize(context) as object) : {}),
    };
    console.log(JSON.stringify(payload));
  },

  warn(message: string, context?: LogContext): void {
    const payload = {
      level: 'warn',
      service: "Don's Atelier",
      timestamp: new Date().toISOString(),
      message,
      ...(context ? (sanitize(context) as object) : {}),
    };
    console.warn(JSON.stringify(payload));
  },

  error(message: string, context?: LogContext): void {
    const errObj = context?.error;
    const errorDetails =
      errObj instanceof Error
        ? {
            name: errObj.name,
            message: errObj.message,
            stack: env.NODE_ENV !== 'production' ? errObj.stack : undefined,
          }
        : errObj;

    const payload = {
      level: 'error',
      service: "Don's Atelier",
      timestamp: new Date().toISOString(),
      message,
      ...(context ? (sanitize({ ...context, error: errorDetails }) as object) : {}),
    };
    console.error(JSON.stringify(payload));
  },
};
