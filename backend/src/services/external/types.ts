import { AppError } from '../../lib/errors';
import { safeFetch } from '../url-safety.service';

/**
 * Outcome of one external lookup. Never thrown — a dependency failing is
 * a per-check status, not a failed scan (§24.3, §30.3 "Never show
 * 'Scan failed'").
 */
export type ExternalOutcome<T> =
  | { status: 'OK'; data: T; cached: boolean }
  | { status: 'UNAVAILABLE'; reason: string }
  | { status: 'SKIPPED'; reason: string }
  | { status: 'NOT_SUPPORTED'; reason: string };

export interface HttpResponse {
  status: number;
  body: string;
}

export interface HttpRequest {
  method: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
}

/** Injected so tests can simulate success, errors, timeouts and 429s without the network (§26.3). */
export type HttpClient = (url: string, request: HttpRequest) => Promise<HttpResponse>;

/** Production client: every call goes through the SSRF guard (§20.4), even to fixed third-party hosts. */
export const defaultHttpClient: HttpClient = async (url, request) => {
  const response = await safeFetch(url, {
    method: request.method,
    headers: request.headers,
    body: request.body,
    timeoutMs: request.timeoutMs,
  });
  return { status: response.statusCode, body: response.body.toString('utf8') };
};

export class ExternalHttpError extends Error {
  constructor(
    readonly service: string,
    readonly statusCode: number
  ) {
    super(`${service} responded ${statusCode}`);
    this.name = 'ExternalHttpError';
  }
}

/** Maps any thrown error to a short, key-free reason string (§28.1 "Error objects from external clients are unwrapped to code and message only"). */
export function reasonFor(error: unknown): string {
  if (error instanceof ExternalHttpError) return error.statusCode === 429 ? 'RATE_LIMITED' : `HTTP_${error.statusCode}`;
  if (error instanceof AppError) {
    const detail = typeof error.details?.reason === 'string' ? error.details.reason : null;
    return detail ?? error.code;
  }
  if (error instanceof Error && error.name === 'CircuitOpenError') return 'CIRCUIT_OPEN';
  return 'EXTERNAL_SERVICE_UNAVAILABLE';
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
