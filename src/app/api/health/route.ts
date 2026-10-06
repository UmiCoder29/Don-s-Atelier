import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { env } from '@/lib/validation/env';

const startTime = Date.now();

export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);

  const healthData = {
    status: 'ok',
    service: "Don's Atelier API",
    package: 'dons-atelier',
    version: '0.1.0',
    environment: env.NODE_ENV,
    uptimeSeconds,
    timestamp: new Date().toISOString(),
  };

  return successResponse(healthData, requestId, { cached: false });
});

export const HEAD = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  return successResponse({ status: 'ok' }, requestId);
});
