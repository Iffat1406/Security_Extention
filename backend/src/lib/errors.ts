import { ERROR_CODE_HTTP_STATUS, type ErrorCode } from '@guardtab/shared';

/**
 * Thrown anywhere in the request lifecycle. The Fastify error handler
 * (see app.ts) turns this into the standard error envelope from §25.5,
 * never a bare stack trace or a raw dependency error.
 */
export class AppError extends Error {
  readonly code: ErrorCode;
  readonly httpStatus: number;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.httpStatus = ERROR_CODE_HTTP_STATUS[code];
    this.details = details;
  }
}
