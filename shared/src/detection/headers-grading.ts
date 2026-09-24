import { SECURITY_HEADERS, type HeadersCheck, type SecurityHeader } from '../schemas/checks.schema';

/**
 * Feature 4 — HTTP security header grading.
 *
 * "Weighted scoring: CSP (30 pts), HSTS (25 pts), X-Frame-Options (20 pts),
 * X-Content-Type-Options (15 pts), Referrer-Policy (5 pts),
 * Permissions-Policy (5 pts). Total maps to A–F."
 *
 * Pure function over the raw response headers, so it's unit-tested against
 * §26.2's "Grade boundaries A–F, malformed header values, duplicate headers,
 * case-insensitive names".
 */
export const HEADER_WEIGHTS: Record<SecurityHeader, number> = {
  'content-security-policy': 30,
  'strict-transport-security': 25,
  'x-frame-options': 20,
  'x-content-type-options': 15,
  'referrer-policy': 5,
  'permissions-policy': 5,
};

/** Score → grade. Lower bound inclusive. */
export const GRADE_THRESHOLDS: ReadonlyArray<[grade: HeadersCheck['grade'] & string, minScore: number]> = [
  ['A', 90],
  ['B', 75],
  ['C', 60],
  ['D', 40],
  ['F', 0],
];

export function scoreToGrade(score: number): NonNullable<HeadersCheck['grade']> {
  for (const [grade, min] of GRADE_THRESHOLDS) if (score >= min) return grade;
  return 'F';
}

const REFERRER_POLICY_TOKENS = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);

/** A present-but-malformed header protects nothing, so it scores 0 and is listed as `invalid`. */
const VALIDATORS: Record<SecurityHeader, (value: string) => boolean> = {
  'content-security-policy': (v) => /[a-z-]+-src|default-src|frame-ancestors|upgrade-insecure-requests|sandbox/i.test(v),
  'strict-transport-security': (v) => {
    const m = /max-age\s*=\s*"?(\d+)"?/i.exec(v);
    return m !== null && Number(m[1]) > 0;
  },
  'x-frame-options': (v) => /^\s*(deny|sameorigin)\s*$/i.test(v),
  'x-content-type-options': (v) => /^\s*nosniff\s*$/i.test(v),
  // The header may carry a comma-separated fallback list; the last valid token wins in browsers.
  'referrer-policy': (v) =>
    v.split(',').some((token) => REFERRER_POLICY_TOKENS.has(token.trim().toLowerCase())),
  'permissions-policy': (v) => /[a-z-]+\s*=\s*(\(|\*|self)/i.test(v),
};

export type RawHeaders = ReadonlyArray<{ name: string; value?: string }> | Readonly<Record<string, string>>;

/** Case-insensitive, duplicate-aware header lookup. Duplicates are joined with ", " per RFC 9110 §5.3. */
export function collectHeaders(raw: RawHeaders): Map<string, string> {
  const entries: Array<[string, string]> = Array.isArray(raw)
    ? (raw as ReadonlyArray<{ name: string; value?: string }>).map((h) => [h.name, h.value ?? ''])
    : Object.entries(raw as Record<string, string>);
  const map = new Map<string, string>();
  for (const [name, value] of entries) {
    const key = name.toLowerCase().trim();
    map.set(key, map.has(key) ? `${map.get(key)}, ${value}` : value);
  }
  return map;
}

export function gradeSecurityHeaders(raw: RawHeaders): Omit<HeadersCheck, 'status'> {
  const headers = collectHeaders(raw);
  const present: SecurityHeader[] = [];
  const missing: SecurityHeader[] = [];
  const invalid: SecurityHeader[] = [];
  const details: HeadersCheck['details'] = {};
  let score = 0;

  for (const header of SECURITY_HEADERS) {
    const value = headers.get(header);
    if (value === undefined || value.trim() === '') {
      missing.push(header);
      continue;
    }
    details[header] = value.slice(0, 512);
    if (VALIDATORS[header](value)) {
      present.push(header);
      score += HEADER_WEIGHTS[header];
    } else {
      invalid.push(header);
    }
  }

  return { grade: scoreToGrade(score), score, present, missing, invalid, details };
}
