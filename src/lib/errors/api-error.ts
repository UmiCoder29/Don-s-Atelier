import { ErrorCode, ErrorCodeType } from './error-codes';

export interface ValidationErrorDetail {
  field: string;
  message: string;
}

/**
 * Base operational API Error for Don's Atelier.
 * Operational errors are expected errors (e.g. invalid input, unauthorized access)
 * whose messages are safe to return to the client.
 */
export class ApiError extends Error {
  public readonly statusCode: number;
  public readonly code: ErrorCodeType;
  public readonly details?: ValidationErrorDetail[] | Record<string, unknown>;
  public readonly isOperational: boolean;

  constructor(
    message: string,
    statusCode: number = 500,
    code: ErrorCodeType = ErrorCode.INTERNAL_SERVER_ERROR,
    details?: ValidationErrorDetail[] | Record<string, unknown>
  ) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;

    // Maintain accurate stack trace in V8 environments
    Error.captureStackTrace(this, this.constructor);
  }
}

export class BadRequestError extends ApiError {
  constructor(message = 'Bad request', details?: Record<string, unknown>) {
    super(message, 400, ErrorCode.BAD_REQUEST, details);
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message = 'Authentication required to access this resource') {
    super(message, 401, ErrorCode.UNAUTHORIZED);
  }
}

export class ForbiddenError extends ApiError {
  constructor(message = 'You do not have permission to perform this action') {
    super(message, 403, ErrorCode.FORBIDDEN);
  }
}

export class NotFoundError extends ApiError {
  constructor(resource = 'Resource') {
    super(`${resource} not found`, 404, ErrorCode.NOT_FOUND);
  }
}

export class ConflictError extends ApiError {
  constructor(message = 'Resource already exists or conflict occurred', details?: ValidationErrorDetail[] | Record<string, unknown>) {
    super(message, 409, ErrorCode.CONFLICT, details);
  }
}

export class ValidationError extends ApiError {
  constructor(details: ValidationErrorDetail[], message = 'Validation failed') {
    super(message, 422, ErrorCode.VALIDATION_ERROR, details);
  }
}

export class RateLimitError extends ApiError {
  public readonly retryAfter: number;

  constructor(retryAfterSeconds: number = 60, message?: string) {
    super(
      message || `Rate limit exceeded. Too many requests. Please retry in ${retryAfterSeconds} seconds.`,
      429,
      ErrorCode.RATE_LIMITED
    );
    this.retryAfter = retryAfterSeconds;
  }
}

export class PayloadTooLargeError extends ApiError {
  constructor(message = 'Payload size exceeds the maximum allowed limit') {
    super(message, 413, ErrorCode.PAYLOAD_TOO_LARGE);
  }
}

export class InternalServerError extends ApiError {
  constructor(message = 'An unexpected internal error occurred') {
    // Non-operational / sanitized message
    super(message, 500, ErrorCode.INTERNAL_SERVER_ERROR);
  }
}

