import { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '@/lib/db/supabase';
import { BadRequestError, InternalServerError, NotFoundError } from '@/lib/errors/api-error';
import { logger } from '@/lib/api/logger';

export const DEFAULT_SIGNED_URL_EXPIRY_SECONDS = 60; // 60 seconds (short expiry)
export const MAX_SIGNED_URL_EXPIRY_SECONDS = 300; // 5 minutes maximum allowable window

export interface SignedUploadUrlResult {
  signedUrl: string;
  path: string;
  token: string;
  expiresIn: number;
}

export interface SignedDownloadUrlResult {
  signedUrl: string;
  expiresIn: number;
}

/**
 * Creates a short-lived signed upload URL for direct client-to-storage uploads.
 * Restricts upload lifetime to a short window (default: 60s).
 */
export async function createSignedUploadUrl(
  bucket: string,
  path: string,
  options?: {
    expiresIn?: number;
    upsert?: boolean;
    client?: SupabaseClient;
  }
): Promise<SignedUploadUrlResult> {
  const client = options?.client ?? supabaseAdmin;
  const expiresIn = options?.expiresIn ?? DEFAULT_SIGNED_URL_EXPIRY_SECONDS;

  if (expiresIn <= 0 || expiresIn > MAX_SIGNED_URL_EXPIRY_SECONDS) {
    throw new BadRequestError(
      `Signed URL expiry must be between 1 and ${MAX_SIGNED_URL_EXPIRY_SECONDS} seconds`
    );
  }

  const { data, error } = await client.storage
    .from(bucket)
    .createSignedUploadUrl(path, {
      upsert: options?.upsert ?? false,
    });

  if (error || !data) {
    logger.error('Failed to create signed upload URL', {
      bucket,
      path,
      error: error?.message,
    });
    throw new InternalServerError('Failed to generate secure upload credentials');
  }

  return {
    signedUrl: data.signedUrl,
    path: data.path,
    token: data.token,
    expiresIn,
  };
}

/**
 * Creates a short-lived signed download URL for private files (e.g. custom bespoke order attachments).
 * Restricts download lifetime to a short window (default: 60s).
 */
export async function createSignedDownloadUrl(
  bucket: string,
  path: string,
  options?: {
    expiresIn?: number;
    download?: boolean | string;
    client?: SupabaseClient;
  }
): Promise<SignedDownloadUrlResult> {
  const client = options?.client ?? supabaseAdmin;
  const expiresIn = options?.expiresIn ?? DEFAULT_SIGNED_URL_EXPIRY_SECONDS;

  if (expiresIn <= 0 || expiresIn > MAX_SIGNED_URL_EXPIRY_SECONDS) {
    throw new BadRequestError(
      `Signed URL expiry must be between 1 and ${MAX_SIGNED_URL_EXPIRY_SECONDS} seconds`
    );
  }

  const { data, error } = await client.storage
    .from(bucket)
    .createSignedUrl(path, expiresIn, {
      download: options?.download,
    });

  if (error || !data) {
    if (
      error?.message?.toLowerCase().includes('not found') ||
      error?.message?.toLowerCase().includes('not_found')
    ) {
      throw new NotFoundError(`File '${path}' was not found in storage bucket '${bucket}'`);
    }
    logger.error('Failed to create signed download URL', {
      bucket,
      path,
      error: error?.message,
    });
    throw new InternalServerError('Failed to generate secure download credentials');
  }

  return {
    signedUrl: data.signedUrl,
    expiresIn,
  };
}

/**
 * Retrieves the public access URL for items stored in public buckets (e.g. product-images).
 */
export function getPublicStorageUrl(
  bucket: string,
  path: string,
  client: SupabaseClient = supabaseAdmin
): string {
  const { data } = client.storage.from(bucket).getPublicUrl(path);
  return data.publicUrl;
}
