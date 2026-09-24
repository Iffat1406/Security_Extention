/**
 * risk-engine/weights.ts — every number the deterministic risk engine uses
 * (§19.2 security signals, §19.3 privacy signals, §19.4 bands and blend).
 *
 * VERSIONING RULE (§19.7, enforced in CI by scripts/check-risk-engine-version.mjs):
 *   - changing any weight or threshold  -> minor bump (1.0.0 -> 1.1.0)
 *   - changing a band boundary or the security/privacy blend -> major bump
 * A score is only ever interpreted together with the version that produced
 * it, and historic scans are never silently rescored.
 */
export const RISK_ENGINE_VERSION = '1.0.0';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** §19.2 — security penalty points. Security score = 100 − min(100, Σ points). */
export const SECURITY_SIGNALS = {
  SAFE_BROWSING_MALICIOUS: { points: 60, severity: 'critical' },
  VIRUSTOTAL_MALICIOUS: { points: 20, severity: 'critical' },
  VIRUSTOTAL_SUSPICIOUS: { points: 10, severity: 'high' },
  SERVED_OVER_HTTP: { points: 15, severity: 'high' },
  CERT_INVALID: { points: 20, severity: 'critical' },
  CERT_EXPIRED: { points: 20, severity: 'critical' },
  CERT_EXPIRING_SOON: { points: 5, severity: 'low' },
  DOMAIN_VERY_YOUNG: { points: 10, severity: 'high' },
  DOMAIN_YOUNG: { points: 5, severity: 'medium' },
  JS_VULN_CRITICAL: { points: 20, severity: 'critical' },
  JS_VULN_HIGH: { points: 10, severity: 'high' },
  JS_VULN_MEDIUM: { points: 5, severity: 'medium' },
  MIXED_CONTENT_ACTIVE: { points: 10, severity: 'high' },
  MIXED_CONTENT_PASSIVE: { points: 3, severity: 'low' },
  MISSING_CSP: { points: 5, severity: 'low' },
  MISSING_HSTS: { points: 3, severity: 'low' },
  /** +1 per missing header among X-Frame-Options, X-Content-Type-Options, Referrer-Policy. */
  MISSING_OTHER_HEADERS: { points: 1, severity: 'low' },
  LOOKALIKE_DOMAIN: { points: 25, severity: 'critical' },
  SUSPICIOUS_REDIRECT_CHAIN: { points: 10, severity: 'high' },
  COMMUNITY_THREAT_REPORTS: { points: 10, severity: 'high' },
} as const satisfies Record<string, { points: number; severity: Severity }>;

/** §19.3 — privacy penalty points. Privacy score = 100 − min(100, Σ points). */
export const PRIVACY_SIGNALS = {
  /** +2 per unique tracker domain, capped (see THRESHOLDS.TRACKER_POINTS_CAP). */
  TRACKERS: { points: 2, severity: 'medium' },
  ADVERTISING_TRACKERS: { points: 10, severity: 'medium' },
  FINGERPRINTING: { points: 20, severity: 'high' },
  CRYPTOMINING: { points: 30, severity: 'critical' },
  THIRD_PARTY_RATIO_HIGH: { points: 10, severity: 'medium' },
  NO_REFERRER_POLICY: { points: 5, severity: 'low' },
  SESSION_RECORDING: { points: 10, severity: 'medium' },
} as const satisfies Record<string, { points: number; severity: Severity }>;

export const THRESHOLDS = {
  /** §19.2 "≥ 3 engines flag the URL. +10 if 1–2 engines flag it". */
  VT_MALICIOUS_MIN_ENGINES: 3,
  CERT_EXPIRY_WARNING_DAYS: 14,
  DOMAIN_VERY_YOUNG_DAYS: 30,
  DOMAIN_YOUNG_DAYS: 90,
  /** §19.2 "Other missing headers ... (max +3)". */
  MISSING_OTHER_HEADERS_MAX: 3,
  /** §31.2 "Only matches at similarity ≥ 0.90 add points". */
  LOOKALIKE_MIN_SIMILARITY: 0.9,
  /** §19.2 "Weighted confidence ≥ 0.8 from ≥ 5 unique users". */
  COMMUNITY_MIN_CONFIDENCE: 0.8,
  COMMUNITY_MIN_REPORTERS: 5,
  /** §19.3 "Capped at +30". */
  TRACKER_POINTS_CAP: 30,
  /** §19.3 "Third-party request ratio > 50%". */
  THIRD_PARTY_RATIO: 0.5,
  /** Below this many sub-resource requests the ratio is noise, not a signal. */
  THIRD_PARTY_RATIO_MIN_REQUESTS: 5,
} as const;

/** §19.4 — overall score bands, highest first. Lower bound inclusive. */
export const BANDS = [
  { band: 'SAFE', min: 80 },
  { band: 'LOW', min: 60 },
  { band: 'MEDIUM', min: 40 },
  { band: 'HIGH', min: 20 },
  { band: 'CRITICAL', min: 0 },
] as const;

/** §19.4 "Overall = round(0.7 × security + 0.3 × privacy)". */
export const BLEND = { security: 0.7, privacy: 0.3 } as const;
