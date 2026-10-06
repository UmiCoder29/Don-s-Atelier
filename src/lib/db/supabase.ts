import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { env } from '@/lib/validation/env';

// Node 20 compatibility: SupabaseClient checks for WebSocket constructor
if (typeof globalThis.WebSocket === 'undefined') {
  // @ts-expect-error fallback placeholder for environments without realtime ws
  globalThis.WebSocket = class WebSocketDummy {};
}

/**
 * Creates a server-side Supabase client using the SERVICE_ROLE_KEY.
 * WARNING: This client bypasses Row Level Security (RLS).
 * It must NEVER be exposed to the client or browser context.
 */
export function createSupabaseServiceClient(): SupabaseClient {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

/**
 * Creates a Supabase client using the public ANON_KEY, optionally bound
 * to an authenticated user's JWT access token for RLS enforcement.
 */
export function createSupabaseUserClient(accessToken?: string): SupabaseClient {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    global: accessToken
      ? {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      : undefined,
  });
}

// Default export: service client for server-side API operations
export const supabaseAdmin = createSupabaseServiceClient();
