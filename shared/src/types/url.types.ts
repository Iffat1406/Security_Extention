/**
 * Result of url-normalizer.service.ts.
 * See GuardTab-Technical-Requirements-v3.docx §20.1 "url-normalizer.service.ts".
 *
 * `fullUrl` is intentionally NOT part of this type. Per §20.1/§25.1 the full
 * URL (with query string) exists only in memory for the duration of a
 * request — it is never persisted and never crosses the shared/ contract.
 */
export interface NormalizedUrl {
  /** Full hostname including subdomain, lowercased, punycode form. */
  host: string;
  /** Public-Suffix-List registrable domain, e.g. "example.com". */
  registrableDomain: string;
  /** Normalised path: collapsed, resolved, redacted, truncated to 200 chars. Null for "/". */
  path: string | null;
  /** scheme://host[/path] — no port (if default), no query, no fragment. */
  normalizedUrl: string;
  /**
   * True when the hostname mixes Unicode scripts (e.g. Latin + Cyrillic) —
   * a homoglyph/lookalike-domain signal. Flagged, not rejected, until the
   * lookalike detector ships (§31.2, Phase 9).
   */
  mixedScriptHost: boolean;
}

export const URL_SAFETY_ALLOWED_SCHEMES = ['http:', 'https:'] as const;
export type AllowedScheme = (typeof URL_SAFETY_ALLOWED_SCHEMES)[number];

export const MAX_URL_LENGTH = 2048;
export const MAX_NORMALIZED_PATH_LENGTH = 200;
