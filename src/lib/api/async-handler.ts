import { NextRequest, NextResponse } from 'next/server';
import { ZodError } from 'zod';
import { ApiError, ValidationError, PayloadTooLargeError, BadRequestError } from '@/lib/errors/api-error';
import { getOrCreateRequestId } from './request-id';
import { logger } from './logger';
import { errorResponse } from './response';
import { assertCsrfProtection } from '@/lib/security/csrf';
import { rateLimiter } from '@/lib/security/rate-limiter';

export type RouteHandler<TContext = unknown> = (
  req: NextRequest,
  context: TContext,
  requestId: string
) => Promise<NextResponse>;

// Maximum allowed payload sizes (100KB for standard JSON endpoints, 20KB for file upload metadata, 5MB for direct product image uploads)
export const MAX_JSON_PAYLOAD_BYTES = 100 * 1024; // 100KB
export const MAX_UPLOAD_PAYLOAD_BYTES = 20 * 1024; // 20KB (only carries JSON metadata; files use direct signed URLs)
export const MAX_IMAGE_PAYLOAD_BYTES = 5 * 1024 * 1024; // 5MB for direct product image uploads

/**
 * Higher-order wrapper for Next.js App Router API route handlers.
 * Provides:
 * - Deterministic Request-ID tracking (X-Request-Id)
 * - Automatic execution timing and structured logging
 * - Oversized payload rejection (413 Payload Too Large)
 * - CSRF origin and token enforcement on cookie-authenticated mutations (403 Forbidden)
 * - Rate limiting on auth, checkout, and upload routes (429 Too Many Requests + Retry-After)
 * - Unified Zod validation error transformation (422 Unprocessable Entity)
 * - Safe error response formatting with zero internal information leakage
 */
export interface AsyncHandlerOptions {
  skipCsrf?: boolean;
}

export function withErrorHandler<TContext = unknown>(
  handler: RouteHandler<TContext>,
  options?: AsyncHandlerOptions
) {
  return async (req: NextRequest, context: TContext): Promise<NextResponse> => {
    const requestId = getOrCreateRequestId(req);
    const start = performance.now();
    const pathname = req.nextUrl ? req.nextUrl.pathname : 'unknown';
    const method = req.method;

    logger.info(`Started ${method} ${pathname}`, {
      requestId,
      method,
      path: pathname,
    });

    try {
      // 1. Oversized Payload Protection
      const contentLengthHeader = req.headers.get('content-length');
      if (contentLengthHeader) {
        const contentLength = parseInt(contentLengthHeader, 10);
        if (!isNaN(contentLength)) {
          const isImageUploadRoute = pathname.includes('/images');
          const isUploadMetadataRoute =
            (pathname.includes('/attachments') || pathname.includes('/uploads')) && !isImageUploadRoute;
          const maxBytes = isImageUploadRoute
            ? MAX_IMAGE_PAYLOAD_BYTES
            : isUploadMetadataRoute
            ? MAX_UPLOAD_PAYLOAD_BYTES
            : MAX_JSON_PAYLOAD_BYTES;

          if (contentLength > maxBytes) {
            throw new PayloadTooLargeError(
              `Request payload size (${contentLength} bytes) exceeds maximum allowed limit (${maxBytes} bytes)`
            );
          }
        }
      }

      // 2. CSRF Origin & Token Enforcement on Cookie-Authenticated Mutations (exempt on webhooks and internal jobs)
      if (
        !options?.skipCsrf &&
        !pathname.startsWith('/api/webhooks') &&
        !pathname.startsWith('/api/internal/jobs')
      ) {
        assertCsrfProtection(req);
      }

      // 3. Rate Limiting Protection (Auth, Checkout, Webhooks, Uploads per IP and User)
      rateLimiter.assertRateLimit(req);

      // 4. Execute Route Handler
      const response = await handler(req, context, requestId);
      const durationMs = Math.round(performance.now() - start);

      logger.info(`Completed ${method} ${pathname} ${response.status}`, {
        requestId,
        method,
        path: pathname,
        statusCode: response.status,
        durationMs,
      });

      return response;
    } catch (err: unknown) {
      const durationMs = Math.round(performance.now() - start);
      let operationalError: unknown = err;

      // Automatically translate Zod errors to standardized ValidationError
      if (err instanceof ZodError) {
        const details = err.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));
        operationalError = new ValidationError(details, 'Request validation failed');
      } else if (err instanceof SyntaxError) {
        operationalError = new BadRequestError('Malformed JSON payload in request body');
      }

      logger.error(`Failed ${method} ${pathname}`, {
        requestId,
        method,
        path: pathname,
        durationMs,
        error: operationalError,
      });

      return errorResponse(operationalError, requestId);
    }
  };
}
