import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { orderService } from '@/services/order/order-service';
import { systemActor } from '@/lib/auth/actor';
import { logAuditEvent } from '@/lib/audit/audit-logger';
import {
  UnauthorizedError,
  ServiceUnavailableError,
  MethodNotAllowedError,
} from '@/lib/errors/api-error';

/**
 * Validates the CRON_SECRET environment variable and constant-time Bearer token.
 * Fail-closed with 503 if CRON_SECRET is unset or shorter than 32 characters.
 * Rejects missing or invalid tokens with 401. Rejects cookie auth with 401.
 */
function authenticateCronRequest(req: NextRequest): void {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret || cronSecret.length < 32) {
    throw new ServiceUnavailableError(
      'Scheduled job service unavailable: CRON_SECRET is not configured or too short'
    );
  }

  const authHeader = req.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new UnauthorizedError('Missing or invalid Authorization header');
  }

  const providedSecret = authHeader.slice(7).trim();
  const expectedBuf = Buffer.from(cronSecret, 'utf8');
  const providedBuf = Buffer.from(providedSecret, 'utf8');

  if (
    expectedBuf.length !== providedBuf.length ||
    !crypto.timingSafeEqual(expectedBuf, providedBuf)
  ) {
    throw new UnauthorizedError('Invalid authorization secret');
  }
}

/**
 * POST /api/internal/jobs/cancel-expired-orders
 * Scheduled job endpoint to cancel stale PENDING orders older than 30 minutes.
 * - Authenticated via Bearer CRON_SECRET header only
 * - Machine-to-machine (CSRF exempt)
 * - Returns COUNTS only (zero order numbers or customer PII)
 * - Writes one audit entry per execution with actorKind SYSTEM
 */
export const POST = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  authenticateCronRequest(req);

  const actor = systemActor('system_scheduler');
  const result = await orderService.cancelExpiredPendingOrders(30);

  // Write one audit entry per run with actorKind SYSTEM
  await logAuditEvent({
    actor,
    action: 'SCHEDULED_CANCEL_EXPIRED_ORDERS',
    entity: 'Order',
    entityId: 'system_batch',
    metadata: {
      cancelledCount: result.cancelledCount,
      totalFound: result.totalFound,
    },
  });

  return successResponse(
    {
      cancelledCount: result.cancelledCount,
    },
    requestId,
    {},
    200
  );
}, { skipCsrf: true });

export const GET = withErrorHandler(async () => {
  throw new MethodNotAllowedError('GET is not supported on this endpoint');
});

export const PUT = withErrorHandler(async () => {
  throw new MethodNotAllowedError('PUT is not supported on this endpoint');
});

export const PATCH = withErrorHandler(async () => {
  throw new MethodNotAllowedError('PATCH is not supported on this endpoint');
});

export const DELETE = withErrorHandler(async () => {
  throw new MethodNotAllowedError('DELETE is not supported on this endpoint');
});
