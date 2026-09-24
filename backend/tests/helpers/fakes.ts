import { randomUUID } from 'node:crypto';
import type { HttpClient, HttpRequest, HttpResponse } from '../../src/services/external/types';
import type { DnsLookup } from '../../src/services/url-safety.service';

/**
 * §26.3 "External APIs are intercepted ... recorded success responses,
 * error responses, timeouts, and rate-limit responses". §26.6: fixtures use
 * reserved domains (example.com, *.test) and never make a live request.
 */
export type FakeReply = HttpResponse | 'timeout' | 'network-error';

export interface FakeHttpHandlers {
  safeBrowsing?: (body: unknown) => FakeReply;
  virusTotal?: (url: string) => FakeReply;
  rdap?: (domain: string) => FakeReply;
}

export const RESPONSES = {
  sbClean: (): HttpResponse => ({ status: 200, body: '{}' }),
  sbMalicious: (threatType = 'SOCIAL_ENGINEERING'): HttpResponse => ({
    status: 200,
    body: JSON.stringify({ matches: [{ threatType, platformType: 'ANY_PLATFORM', threat: { url: 'x' } }] }),
  }),
  vtStats: (malicious: number): HttpResponse => ({
    status: 200,
    body: JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 10 } } } }),
  }),
  vtNotFound: (): HttpResponse => ({ status: 404, body: '{}' }),
  rdapAge: (daysOld: number): HttpResponse => ({
    status: 200,
    body: JSON.stringify({
      events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - daysOld * 86_400_000).toISOString() }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar, Inc.']]] }],
    }),
  }),
  rateLimited: (): HttpResponse => ({ status: 429, body: '{}' }),
  serverError: (): HttpResponse => ({ status: 503, body: '{}' }),
};

export function createFakeHttp(handlers: FakeHttpHandlers = {}) {
  const calls: Array<{ service: 'safeBrowsing' | 'virusTotal' | 'rdap' | 'other'; url: string; request: HttpRequest }> = [];
  const resolve = async (reply: FakeReply): Promise<HttpResponse> => {
    if (reply === 'timeout') throw Object.assign(new Error('timeout'), { name: 'AbortError' });
    if (reply === 'network-error') throw new Error('ECONNRESET');
    return reply;
  };

  const client: HttpClient = async (url, request) => {
    if (url.startsWith('https://safebrowsing.googleapis.com/')) {
      calls.push({ service: 'safeBrowsing', url, request });
      return resolve((handlers.safeBrowsing ?? RESPONSES.sbClean)(request.body ? JSON.parse(request.body) : null));
    }
    if (url.startsWith('https://www.virustotal.com/')) {
      calls.push({ service: 'virusTotal', url, request });
      return resolve((handlers.virusTotal ?? RESPONSES.vtNotFound)(url));
    }
    if (url.includes('/domain/')) {
      calls.push({ service: 'rdap', url, request });
      const domain = decodeURIComponent(url.split('/domain/')[1] ?? '');
      return resolve((handlers.rdap ?? (() => RESPONSES.rdapAge(4000)))(domain));
    }
    calls.push({ service: 'other', url, request });
    throw new Error(`unexpected outbound call in a test: ${url}`);
  };

  return { client, calls, count: (service: string) => calls.filter((c) => c.service === service).length };
}

/**
 * Deterministic DNS: every name resolves to a public documentation-adjacent
 * address unless mapped. The real SSRF guard then runs on these answers.
 */
export function createFakeDns(overrides: Record<string, string> = {}): DnsLookup {
  return async (hostname) => {
    const address = overrides[hostname];
    if (address === 'NXDOMAIN') throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return [{ address: address ?? '93.184.216.34', family: (address ?? '').includes(':') ? 6 : 4 }];
  };
}

/**
 * A fresh reserved-TLD registrable domain per test (§26.6), so parallel files
 * never share a dedup key or domain row. `.test` isn't in the Public Suffix
 * List, so `<label>-<id>.test` is its own registrable domain.
 */
export function uniqueHost(label = 'site'): string {
  return `${label}-${randomUUID().slice(0, 8)}.test`;
}

export const cleanChecks = {
  ssl: {
    status: 'OK',
    protocol: 'https:',
    isHTTP: false,
    isValid: true,
    certError: null,
    certificateDetail: 'NOT_SUPPORTED',
    issuer: null,
    expiresAt: null,
    daysLeft: null,
  },
  headers: {
    status: 'OK',
    grade: 'A',
    score: 100,
    present: ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'],
    missing: [],
    invalid: [],
    details: {},
  },
  trackers: {
    status: 'OK',
    trackerCount: 0,
    trackers: [],
    intensity: 'none',
    categories: {},
    thirdPartyRequests: 0,
    totalRequests: 8,
  },
} as const;

export function submission(url: string, checks: Record<string, unknown> = cleanChecks, extra: Record<string, unknown> = {}) {
  return { url, schemaVersion: 1, scannerVersion: '1.0.0', checks, ...extra };
}
