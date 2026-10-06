import { NextRequest } from 'next/server';
import { withErrorHandler } from '@/lib/api/async-handler';
import { successResponse } from '@/lib/api/response';
import { requireAuth } from '@/lib/auth/supabase-auth';

/**
 * GET /api/auth/session
 * Returns authenticated user's current session and profile.
 */
export const GET = withErrorHandler(async (req: NextRequest, _context, requestId) => {
  const user = await requireAuth(req);
  return successResponse({ user }, requestId);
});
