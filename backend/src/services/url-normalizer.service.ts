import { domainToUnicode } from 'node:url';
import psl from 'psl';
import {
  MAX_NORMALIZED_PATH_LENGTH,
  MAX_URL_LENGTH,
  URL_SAFETY_ALLOWED_SCHEMES,
  type AllowedScheme,
  type NormalizedUrl,
} from '@guardtab/shared';
import { AppError } from '../lib/errors';

/**
 * url-normalizer.service.ts — §20.1/§20.2.
 *
 * Produces the canonical, privacy-safe representation of a URL used for
 * storage and deduplication. Never persists the full URL or query string
 * (§17.2, §25.1) — callers that need the full URL in memory (e.g. to hand
 * to Safe Browsing) must read it from the original input themselves; it is
 * not part of this module's return value.
 */

const DEFAULT_PORTS: Record<AllowedScheme, string> = { 'http:': '80', 'https:': '443' };

// Path segments shaped like opaque tokens/identifiers are redacted before
// storage (§20.1 step 7, §20.2 example "/u/9f8c…2b/edit" -> "/u/:redacted/edit").
const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i;
const LONG_NUMERIC_SEGMENT = /^[0-9]{8,}$/;
// Alphanumeric run of 20+ chars mixing letters and digits — the shape of a
// session id / API token / short-link slug rather than a real word.
const LONG_TOKEN_SEGMENT = /^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_-]{20,}$/;

function isHighEntropySegment(segment: string): boolean {
  return (
    UUID_SEGMENT.test(segment) ||
    LONG_HEX_SEGMENT.test(segment) ||
    LONG_NUMERIC_SEGMENT.test(segment) ||
    LONG_TOKEN_SEGMENT.test(segment)
  );
}

// A deliberately conservative set of scripts checked for homoglyph mixing.
// A label that combines two of these is a lookalike-domain candidate
// (§20.2 "exаmple.com" with Cyrillic а) and is flagged, not rejected, until
// the lookalike detector ships (§31.2, Phase 9).
const SCRIPT_PATTERNS: Record<string, RegExp> = {
  Latin: /\p{Script=Latin}/u,
  Cyrillic: /\p{Script=Cyrillic}/u,
  Greek: /\p{Script=Greek}/u,
  Armenian: /\p{Script=Armenian}/u,
  Hebrew: /\p{Script=Hebrew}/u,
  Arabic: /\p{Script=Arabic}/u,
  Han: /\p{Script=Han}/u,
  Hiragana: /\p{Script=Hiragana}/u,
  Katakana: /\p{Script=Katakana}/u,
  Hangul: /\p{Script=Hangul}/u,
  Devanagari: /\p{Script=Devanagari}/u,
  Thai: /\p{Script=Thai}/u,
};

function hasMixedScript(unicodeHost: string): boolean {
  for (const label of unicodeHost.split('.')) {
    const scriptsPresent = new Set<string>();
    for (const [script, pattern] of Object.entries(SCRIPT_PATTERNS)) {
      if (pattern.test(label)) scriptsPresent.add(script);
    }
    if (scriptsPresent.size > 1) return true;
  }
  return false;
}

// Percent-encoded unreserved characters (RFC 3986 §2.3: A-Z a-z 0-9 - . _ ~)
// are decoded for a canonical form. Everything else (notably %2F, %3F, and
// non-ASCII escapes) stays encoded so the path never becomes ambiguous.
const UNRESERVED_PERCENT_ESCAPE = /%(2[146]|3[0-9]|4[1-9A-F]|5[0-9A]|6[1-9A-F]|7[0-9A])/gi;

function normalizePath(pathname: string): string | null {
  const decoded = pathname.replace(UNRESERVED_PERCENT_ESCAPE, (match) => {
    const ch = String.fromCharCode(parseInt(match.slice(1), 16));
    return /[A-Za-z0-9\-._~]/.test(ch) ? ch : match;
  });

  // Dot-segment resolution (./ and ../) is already performed by the WHATWG
  // URL parser. Only repeated-slash collapsing is left to do here.
  const collapsed = decoded.replace(/\/{2,}/g, '/');

  const rebuilt = collapsed
    .split('/')
    .map((segment) => (isHighEntropySegment(segment) ? ':redacted' : segment))
    .join('/');

  const truncated = rebuilt.length > MAX_NORMALIZED_PATH_LENGTH ? rebuilt.slice(0, MAX_NORMALIZED_PATH_LENGTH) : rebuilt;

  return truncated === '/' || truncated === '' ? null : truncated;
}

function isAllowedScheme(scheme: string): scheme is AllowedScheme {
  return (URL_SAFETY_ALLOWED_SCHEMES as readonly string[]).includes(scheme);
}

export function normalizeUrl(rawUrl: string): NormalizedUrl {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    throw new AppError('INVALID_URL', 'URL must be a non-empty string');
  }
  if (rawUrl.length > MAX_URL_LENGTH) {
    throw new AppError('URL_TOO_LONG', `URL exceeds ${MAX_URL_LENGTH} characters`);
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new AppError('INVALID_URL', 'URL could not be parsed');
  }

  if (!isAllowedScheme(parsed.protocol)) {
    throw new AppError('UNSUPPORTED_SCHEME', `Scheme "${parsed.protocol}" is not allowed`, {
      scheme: parsed.protocol,
    });
  }

  if (parsed.username || parsed.password) {
    throw new AppError('INVALID_URL', 'Credentials in the URL are not allowed');
  }

  // The URL parser already lowercases scheme + host and IDNA-encodes the
  // host to punycode (§20.1 steps 2–3); `hostname` never includes the port.
  const host = parsed.hostname;
  const unicodeHost = domainToUnicode(host);
  const mixedScriptHost = hasMixedScript(unicodeHost);

  const path = normalizePath(parsed.pathname);

  const registrableDomain = psl.get(host) ?? host;

  const isDefaultPort = parsed.port === '' || DEFAULT_PORTS[parsed.protocol] === parsed.port;
  const hostForUrl = isDefaultPort ? host : `${host}:${parsed.port}`;
  // Fragment (never leaves the browser) and query string (dropped before
  // persistence, §20.1 steps 5–6) are absent from `normalizedUrl` because we
  // build it from scheme + host + path only — never from `parsed.href`.
  // A null `path` (root, or fully redacted) still renders as "/" here, per
  // the §20.2 example "https://example.com?token=abc" -> "https://example.com/".
  const normalizedUrl = `${parsed.protocol}//${hostForUrl}${path ?? '/'}`;

  return { host, registrableDomain, path, normalizedUrl, mixedScriptHost };
}
