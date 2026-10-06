import { NextResponse } from 'next/server';
import { ApiError, RateLimitError } from '@/lib/errors/api-error';
import { ErrorCode } from '@/lib/errors/error-codes';
import { REQUEST_ID_HEADER } from './request-id';

export interface ApiResponseMeta {
  requestId: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface ApiSuccessResponse<T> {
  success: true;
  data: T;
  meta: ApiResponseMeta;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiErrorPayload;
  meta: ApiResponseMeta;
}

/**
 * Creates a standardized API success response.
 */
export function successResponse<T>(
  data: T,
  requestId: string,
  meta?: Record<string, unknown>,
  status = 200
): NextResponse<ApiSuccessResponse<T>> {
  const payload: ApiSuccessResponse<T> = {
    success: true,
    data,
    meta: {
      requestId,
      timestamp: new Date().toISOString(),
      ...meta,
    },
  };

  return NextResponse.json(payload, {
    status,
    headers: {
      [REQUEST_ID_HEADER]: requestId,
      'Content-Type': 'application/json',
    },
  });
}

/**
 * Creates a standardized API error response.
 * Strictly adheres to security rules: never leaks internal database errors,
 * SQL queries, raw paths, or stack traces.
 */
export function errorResponse(
  error: unknown,
  requestId: string
): NextResponse<ApiErrorResponse> {
  let statusCode = 500;
  let code: string = ErrorCode.INTERNAL_SERVER_ERROR;
  let message = 'An unexpected internal error occurred. Please try again later.';
  let details: unknown = undefined;

  if (error instanceof ApiError) {
    statusCode = error.statusCode;
    code = error.code;
    message = error.message;
    details = error.details;
  }

  const payload: ApiErrorResponse = {
    success: false,
    error: {
      code,
      message,
      ...(details !== undefined ? { details } : {}),
    },
    meta: {
      requestId,
      timestamp: new Date().toISOString(),
    },
  };

  const headers: Record<string, string> = {
    [REQUEST_ID_HEADER]: requestId,
    'Content-Type': 'application/json',
  };

  if (error instanceof RateLimitError) {
    headers['Retry-After'] = String(error.retryAfter);
  }

  return NextResponse.json(payload, {
    status: statusCode,
    headers,
  });
}
