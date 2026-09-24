/**
 * Versions that are stamped on every scan (§19.7, §27.3 "Every release
 * records the backend version, risk_engine_version and scanner_version
 * together").
 *
 * SCANNER_VERSION identifies the extension checker logic that produced the
 * raw results; bump it whenever a checker's output could change for the
 * same page (new tracker list, new grading rule, new brand list).
 */
export const SCANNER_VERSION = '1.0.0';

/** Payload contract version (§25.1 schema_version) — lets the backend accept older extension builds. */
export const SCHEMA_VERSION = 1;

export const API_PREFIX = '/api/v1';

/** §12 "Scan result for current domain — 30 minutes". */
export const EXTENSION_SCAN_CACHE_TTL_MS = 30 * 60 * 1000;

/** §12 "User profile (id, email, displayName) — 24 hours". */
export const EXTENSION_PROFILE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/** §23.4 "excluded_domains ... max 200 entries". */
export const MAX_EXCLUDED_DOMAINS = 200;

/** §24.2 "the extension polls GET /scans/:id once, after 1.5 seconds, and gives up after two attempts". */
export const AI_POLL_DELAY_MS = 1500;
export const AI_POLL_MAX_ATTEMPTS = 2;
