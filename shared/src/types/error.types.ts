/**
 * Standard error codes returned by the GuardTab API.
 * See GuardTab-Technical-Requirements-v3.docx §25.5 "Standard error envelope".
 *
 * Codes are grouped by the phase that first produces them; every code is
 * declared up front so the contract does not grow ad hoc as phases land.
 */
export const ERROR_CODES = [
  // Phase 2 — Authentication & RBAC
  'AUTH_REQUIRED',
  'AUTH_INVALID',
  'TOKEN_REUSE_DETECTED',
  'FORBIDDEN',
  // Phase 1 — URL normalisation & safety
  'INVALID_URL',
  'UNSUPPORTED_SCHEME',
  'BLOCKED_TARGET',
  'URL_TOO_LONG',
  'UNRESOLVABLE_HOST',
  // General
  'SCAN_NOT_FOUND',
  'VALIDATION_ERROR',
  'RATE_LIMITED',
  'QUOTA_EXCEEDED',
  'EXTERNAL_SERVICE_UNAVAILABLE',
  'INTERNAL_ERROR',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

/** Maps every error code to the HTTP status it must be returned with. */
export const ERROR_CODE_HTTP_STATUS: Record<ErrorCode, number> = {
  AUTH_REQUIRED: 401,
  AUTH_INVALID: 401,
  TOKEN_REUSE_DETECTED: 401,
  FORBIDDEN: 403,
  SCAN_NOT_FOUND: 404,
  INVALID_URL: 400,
  UNSUPPORTED_SCHEME: 400,
  BLOCKED_TARGET: 400,
  URL_TOO_LONG: 400,
  UNRESOLVABLE_HOST: 400,
  VALIDATION_ERROR: 400,
  RATE_LIMITED: 429,
  QUOTA_EXCEEDED: 429,
  EXTERNAL_SERVICE_UNAVAILABLE: 503,
  INTERNAL_ERROR: 500,
};

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    requestId: string;
    details?: Record<string, unknown>;
  };
}
