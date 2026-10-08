import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';

export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const healthData = {
    status: 'ok',
    timestamp: new Date().toISOString(),
  };

  return successResponse(healthData, requestId, { cached: false });
});

export const HEAD = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  return successResponse({ status: 'ok' }, requestId);
});
