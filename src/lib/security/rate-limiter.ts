import { NextRequest } from 'next/server';
import { RateLimitError } from '@/lib/errors/api-error';
import { AUTH_ACCESS_COOKIE } from '@/lib/auth/cookies';

export interface RateLimitRule {
  maxRequests: number;
  windowSeconds: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number; // Unix timestamp in seconds
  retryAfter: number; // Seconds until reset
  limitedBy?: 'ip' | 'user';
}

export type RateLimitGroup = 'auth' | 'checkout' | 'upload' | 'webhook' | 'default';

/**
 * In-memory sliding-window rate limiter for Don's Atelier.
 * Tracks request counts per IP and per authenticated user.
 */
export class RateLimiter {
  private windows = new Map<string, number[]>();
  private emailFailures = new Map<string, number[]>();

  public static readonly MAX_EMAIL_LOGIN_FAILURES = 5;
  public static readonly EMAIL_LOGIN_WINDOW_SECONDS = 15 * 60; // 15 minutes (900s)

  private rules: Record<RateLimitGroup, RateLimitRule> = {
    auth: { maxRequests: 10, windowSeconds: 60 },
    checkout: { maxRequests: 10, windowSeconds: 60 },
    upload: { maxRequests: 30, windowSeconds: 60 },
    webhook: { maxRequests: 60, windowSeconds: 60 },
    default: { maxRequests: 60, windowSeconds: 60 },
  };

  /**
   * Configures a rate limiting rule for a specific route group.
   */
  public setRule(group: RateLimitGroup, rule: RateLimitRule): void {
    this.rules[group] = { ...rule };
  }

  /**
   * Retrieves the active rule for a route group.
   */
  public getRule(group: RateLimitGroup): RateLimitRule {
    return this.rules[group] || this.rules.default;
  }

  /**
   * Resets all in-memory rate limiting counters (useful for unit tests).
   */
  public reset(): void {
    this.windows.clear();
    this.emailFailures.clear();
  }

  /**
   * Checks whether the target email has exceeded the 5 failed login attempts in 15 minutes.
   */
  public isEmailThrottled(email: string): boolean {
    const normalized = email.trim().toLowerCase();
    const windowMs = RateLimiter.EMAIL_LOGIN_WINDOW_SECONDS * 1000;
    const now = Date.now();
    const timestamps = (this.emailFailures.get(normalized) || []).filter(
      (ts) => now - ts < windowMs
    );
    this.emailFailures.set(normalized, timestamps);
    return timestamps.length >= RateLimiter.MAX_EMAIL_LOGIN_FAILURES;
  }

  /**
   * Records a failed login attempt for a normalized email.
   * Applies identically to both existing and non-existing email addresses.
   */
  public recordEmailFailure(email: string): void {
    const normalized = email.trim().toLowerCase();
    const windowMs = RateLimiter.EMAIL_LOGIN_WINDOW_SECONDS * 1000;
    const now = Date.now();
    const timestamps = (this.emailFailures.get(normalized) || []).filter(
      (ts) => now - ts < windowMs
    );
    timestamps.push(now);
    this.emailFailures.set(normalized, timestamps);
  }

  /**
   * Resets failed login counters for an email upon successful login.
   */
  public resetEmailFailures(email: string): void {
    const normalized = email.trim().toLowerCase();
    this.emailFailures.delete(normalized);
  }

  /**
   * Checks whether a request should be rate-limited, checking both IP and User buckets.
   */
  public check(group: RateLimitGroup, ip: string, userId?: string | null): RateLimitResult {
    const rule = this.getRule(group);
    const windowMs = rule.windowSeconds * 1000;
    const now = Date.now();

    // 1. Check IP bucket
    const ipKey = `ip:${group}:${ip}`;
    const ipResult = this.checkBucket(ipKey, rule.maxRequests, windowMs, now);
    if (!ipResult.allowed) {
      return {
        ...ipResult,
        limitedBy: 'ip',
      };
    }

    // 2. Check User bucket (if user is authenticated)
    if (userId) {
      const userKey = `user:${group}:${userId}`;
      const userResult = this.checkBucket(userKey, rule.maxRequests, windowMs, now);
      if (!userResult.allowed) {
        return {
          ...userResult,
          limitedBy: 'user',
        };
      }
    }

    // Both passed: return remaining from the more constrained bucket
    return ipResult;
  }

  /**
   * Enforces rate limiting on a request. Throws RateLimitError (429) if exceeded.
   */
  public assertRateLimit(
    req: NextRequest,
    options?: { group?: RateLimitGroup; userId?: string | null }
  ): RateLimitResult {
    const pathname = req.nextUrl?.pathname || '';
    const method = req.method.toUpperCase();

    const group = options?.group || getRateLimitGroup(pathname, method);
    if (!group) {
      // Not a rate-limited route
      return { allowed: true, limit: 100, remaining: 100, resetAt: 0, retryAfter: 0 };
    }

    const ip = getClientIp(req);
    const userId = options?.userId !== undefined ? options.userId : extractUserIdFromRequest(req);

    const result = this.check(group, ip, userId);
    if (!result.allowed) {
      const target = result.limitedBy === 'user' ? 'account' : 'IP address';
      throw new RateLimitError(
        result.retryAfter,
        `Too many requests from this ${target}. Please retry in ${result.retryAfter} seconds.`
      );
    }

    return result;
  }

  private checkBucket(key: string, maxRequests: number, windowMs: number, now: number): RateLimitResult {
    const timestamps = this.windows.get(key) || [];
    const windowStart = now - windowMs;

    // Prune timestamps older than current sliding window
    const activeTimestamps = timestamps.filter((t) => t > windowStart);

    if (activeTimestamps.length >= maxRequests) {
      const oldestActive = activeTimestamps[0];
      const resetTimeMs = oldestActive + windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetTimeMs - now) / 1000));
      const resetAt = Math.ceil(resetTimeMs / 1000);

      this.windows.set(key, activeTimestamps);

      return {
        allowed: false,
        limit: maxRequests,
        remaining: 0,
        resetAt,
        retryAfter: retryAfterSeconds,
      };
    }

    // Record this request
    activeTimestamps.push(now);
    this.windows.set(key, activeTimestamps);

    const remaining = maxRequests - activeTimestamps.length;
    const resetAt = Math.ceil((now + windowMs) / 1000);

    return {
      allowed: true,
      limit: maxRequests,
      remaining,
      resetAt,
      retryAfter: 0,
    };
  }
}

export const rateLimiter = new RateLimiter();

/**
 * Resolves client IP strictly based on TRUSTED_IP_HEADER configuration.
 *
 * Rules:
 * - Allowed values: 'none', 'x-vercel-forwarded-for', 'cf-connecting-ip', 'x-real-ip'. Default: 'none'.
 * - Must read ONLY the single header named there.
 * - With 'none', use the connection IP (`req.ip`), else '127.0.0.1'.
 * - If set to a header name, read ONLY that single header. If absent/empty, fall back to connection IP, else '127.0.0.1'.
 * - Unconditional reading of the other headers and all X-Forwarded-For parsing is removed.
 */
export function getClientIp(req: NextRequest): string {
  const trustedHeader = (
    process.env.TRUSTED_IP_HEADER ||
    'none'
  ).trim().toLowerCase();

  if (trustedHeader !== 'none') {
    const headerVal = req.headers.get(trustedHeader);
    if (headerVal && headerVal.trim()) {
      const clientIp = headerVal.split(',')[0].trim();
      if (clientIp) {
        return clientIp;
      }
    }
  }

  // With 'none' (or if the configured header is absent): use connection IP, else '127.0.0.1'
  const connectionIp = (req as Request & { ip?: string }).ip;
  if (typeof connectionIp === 'string' && connectionIp.trim()) {
    return connectionIp.trim();
  }

  return '127.0.0.1';
}

/**
 * Extracts user ID from Supabase JWT without database round-trip.
 */
export function extractUserIdFromRequest(req: NextRequest): string | null {
  // Check authorization header
  const authHeader = req.headers.get('authorization');
  let token: string | null = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else {
    // Check httpOnly cookie
    const cookie = req.cookies.get(AUTH_ACCESS_COOKIE);
    if (cookie && cookie.value) {
      token = cookie.value.trim();
    }
  }

  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length === 3) {
      const payloadJson = Buffer.from(parts[1], 'base64').toString('utf-8');
      const payload = JSON.parse(payloadJson);
      return payload.sub || null;
    }
  } catch {
    // Malformed token, cannot extract user id
  }

  return null;
}

/**
 * Classifies a route into its rate limit group, or returns null if not rate-limited.
 */
export function getRateLimitGroup(pathname: string, method: string): RateLimitGroup | null {
  const upperMethod = method.toUpperCase();

  // Auth routes (all mutations or login/register/refresh/password-reset)
  if (
    pathname.startsWith('/api/auth/login') ||
    pathname.startsWith('/api/auth/register') ||
    pathname.startsWith('/api/auth/password-reset') ||
    pathname.startsWith('/api/auth/refresh')
  ) {
    return 'auth';
  }

  // Checkout routes: POST /api/orders and POST /api/checkout
  if ((pathname === '/api/orders' || pathname === '/api/checkout') && upperMethod === 'POST') {
    return 'checkout';
  }

  // Upload routes: /api/uploads, custom-orders attachments, or product images
  if (
    pathname.startsWith('/api/uploads') ||
    pathname.includes('/attachments') ||
    pathname.includes('/images')
  ) {
    return 'upload';
  }

  // Webhook routes: /api/webhooks/*
  if (pathname.startsWith('/api/webhooks')) {
    return 'webhook';
  }

  return null;
}

/**
 * Checks whether a given path and method are subject to rate limiting.
 */
export function isRateLimitedRoute(pathname: string, method: string): boolean {
  return getRateLimitGroup(pathname, method) !== null;
}
