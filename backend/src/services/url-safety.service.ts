import dns from 'node:dns/promises';
import { Agent, request as undiciRequest, type Dispatcher } from 'undici';
import { URL_SAFETY_ALLOWED_SCHEMES, type AllowedScheme } from '@guardtab/shared';
import { AppError } from '../lib/errors';
import { canonicalizeIpLiteral, isBlockedIp } from '../lib/ip-utils';

/**
 * url-safety.service.ts — §20.4 SSRF protection.
 *
 * The backend does not fetch arbitrary user-supplied URLs yet (Phase 1 has
 * no feature that needs to). This guard is built anyway, now, because "the
 * guard is written after the first fetching feature" is exactly how SSRF
 * gets into production systems (§20.4 warning box). Every future outbound
 * call derived from a user-supplied URL — favicon fetches, redirect-chain
 * following, TLS probes — must go through `safeFetch` below, no exceptions.
 */

const DEFAULT_PORTS: Record<AllowedScheme, number> = { 'http:': 80, 'https:': 443 };

const DENIED_HOSTNAME_SUFFIXES = ['.localhost', '.local', '.internal'];
const DENIED_HOSTNAMES_EXACT = new Set(['localhost', 'metadata.google.internal']);

function isDeniedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (DENIED_HOSTNAMES_EXACT.has(lower)) return true;
  return DENIED_HOSTNAME_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

function isAllowedScheme(scheme: string): scheme is AllowedScheme {
  return (URL_SAFETY_ALLOWED_SCHEMES as readonly string[]).includes(scheme);
}

export interface ValidatedOutboundUrl {
  protocol: AllowedScheme;
  hostname: string;
  port: number;
  /** The IP this request must connect to — resolved once and pinned, so a
   * second DNS lookup between validation and connection can't rebind it. */
  pinnedIp: string;
  ipFamily: 4 | 6;
}

/**
 * Validates a URL against every rule in §20.4 and, for a real hostname,
 * resolves it and checks every returned address. Throws an AppError with
 * the exact code from §20.5 on any failure — callers must never attempt
 * the request anyway on catch.
 */
export async function validateOutboundUrl(rawUrl: string): Promise<ValidatedOutboundUrl> {
  if (rawUrl.length > 2048) {
    throw new AppError('URL_TOO_LONG', 'URL exceeds 2048 characters');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new AppError('INVALID_URL', 'URL could not be parsed');
  }

  if (parsed.username || parsed.password) {
    throw new AppError('INVALID_URL', 'Credentials in the URL are not allowed');
  }

  if (!isAllowedScheme(parsed.protocol)) {
    throw new AppError('UNSUPPORTED_SCHEME', `Scheme "${parsed.protocol}" is not allowed`, {
      scheme: parsed.protocol,
    });
  }

  // `hostname` wraps IPv6 literals in brackets ("[::1]"); strip them before
  // any IP-family check.
  const hostname = parsed.hostname.startsWith('[') ? parsed.hostname.slice(1, -1) : parsed.hostname;

  if (isDeniedHostname(hostname)) {
    throw new AppError('BLOCKED_TARGET', `Hostname "${hostname}" is on the deny-list`);
  }

  const port = parsed.port ? Number(parsed.port) : DEFAULT_PORTS[parsed.protocol];

  // IP literal (including decimal/octal/hex/IPv4-mapped-IPv6 obfuscations,
  // §20.4 "Encoded bypasses") — check directly, no DNS lookup needed or possible.
  const literal = canonicalizeIpLiteral(hostname);
  if (literal) {
    if (isBlockedIp(literal.ip)) {
      throw new AppError('BLOCKED_TARGET', `IP literal "${literal.ip}" is not a public address`);
    }
    return { protocol: parsed.protocol, hostname, port, pinnedIp: literal.ip, ipFamily: literal.family };
  }

  // A real hostname: resolve it and validate every A/AAAA record (§20.4
  // "DNS resolution check") — a public name resolving to a private address
  // is rejected even though the hostname itself looked fine.
  let addresses: { address: string; family: number }[];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    throw new AppError('UNRESOLVABLE_HOST', `Hostname "${hostname}" could not be resolved`);
  }
  if (addresses.length === 0) {
    throw new AppError('UNRESOLVABLE_HOST', `Hostname "${hostname}" resolved to no addresses`);
  }

  const blocked = addresses.find((address) => isBlockedIp(address.address));
  if (blocked) {
    throw new AppError(
      'BLOCKED_TARGET',
      `Hostname "${hostname}" resolves to a private/internal address (${blocked.address})`
    );
  }

  const chosen = addresses[0]!;
  return {
    protocol: parsed.protocol,
    hostname,
    port,
    pinnedIp: chosen.address,
    ipFamily: chosen.family as 4 | 6,
  };
}

const MAX_RESPONSE_BYTES = 1024 * 1024; // 1MB cap (§20.4)
const MAX_REDIRECTS = 5;
const CONNECT_TIMEOUT_MS = 5000;
const TOTAL_TIMEOUT_MS = 10000;

export interface SafeFetchResult {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  finalUrl: string;
}

/**
 * Fetches a user-supplied URL through the full SSRF guard: validates and
 * pins an IP before every hop, never follows a redirect automatically
 * (each hop is re-validated from scratch), and enforces the timeout and
 * response-size caps from §20.4.
 */
export async function safeFetch(
  initialUrl: string,
  init: { method?: Dispatcher.HttpMethod; headers?: Record<string, string> } = {}
): Promise<SafeFetchResult> {
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;
  let currentUrl = initialUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', 'Outbound request exceeded the total time budget');
    }

    // Re-validated on every hop, including the first — a redirect target is
    // just as untrusted as the original input (§20.4 "Redirect handling").
    const validated = await validateOutboundUrl(currentUrl);
    const parsedUrl = new URL(currentUrl);

    const agent = new Agent({
      connect: {
        timeout: CONNECT_TIMEOUT_MS,
        // DNS-rebinding protection: connect to the address validated above;
        // never resolve again between the check and the connection.
        lookup: (_hostname, _options, callback) => {
          callback(null, validated.pinnedIp, validated.ipFamily);
        },
      },
    });

    try {
      const response = await undiciRequest(parsedUrl, {
        method: init.method ?? 'GET',
        headers: { ...init.headers, host: parsedUrl.host },
        dispatcher: agent,
        maxRedirections: 0,
        bodyTimeout: Math.min(remaining, TOTAL_TIMEOUT_MS),
        headersTimeout: Math.min(remaining, TOTAL_TIMEOUT_MS),
      });

      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.body.destroy();
        const location = response.headers.location;
        const locationValue = Array.isArray(location) ? location[0] : location;
        if (!locationValue) {
          throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', 'Redirect response had no Location header');
        }
        currentUrl = new URL(locationValue, parsedUrl).toString();
        continue;
      }

      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of response.body) {
        total += (chunk as Buffer).length;
        if (total > MAX_RESPONSE_BYTES) {
          response.body.destroy();
          throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', 'Response exceeded the 1MB cap');
        }
        chunks.push(chunk as Buffer);
      }

      return { statusCode: response.statusCode, headers: response.headers, body: Buffer.concat(chunks), finalUrl: currentUrl };
    } finally {
      await agent.close();
    }
  }

  throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', `Too many redirects (max ${MAX_REDIRECTS})`);
}
