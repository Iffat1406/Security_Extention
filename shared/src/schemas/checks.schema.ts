import { z } from 'zod';

/**
 * Per-check result payloads the extension posts to the backend.
 *
 * §18.4 boundary rule: "The extension is not a trusted client ... Every
 * field is therefore re-validated with Zod". Every string and array here is
 * therefore length-capped and every object is `.strict()` (unknown keys
 * rejected), so a modified extension can't smuggle extra data into JSONB
 * columns or blow up a row's size.
 *
 * Privacy rule (§17.2): no schema here carries a full URL. Sub-resources are
 * reduced to their host before they leave the browser.
 */

/** §24.3 per-check status. */
export const checkStatusSchema = z.enum(['OK', 'UNAVAILABLE', 'SKIPPED', 'NOT_SUPPORTED']);
export type CheckStatus = z.infer<typeof checkStatusSchema>;

const host = z.string().min(1).max(255);

// ---------------------------------------------------------------------------
// Feature 3 — SSL / TLS, layered per §33.1
// ---------------------------------------------------------------------------

export const sslCheckSchema = z
  .object({
    status: checkStatusSchema,
    /** Layer 1 — always available. */
    protocol: z.enum(['https:', 'http:']),
    isHTTP: z.boolean(),
    /** Layer 2 — did the page load without a certificate error? null = unknown. */
    isValid: z.boolean().nullable(),
    /** Chrome network error name when layer 2 failed, e.g. "net::ERR_CERT_DATE_INVALID". */
    certError: z.string().max(64).nullable(),
    /**
     * Layer 3 — issuer/expiry. Chrome's extension APIs don't expose the page's
     * certificate (verified for §33.1), so the shipped checker always reports
     * NOT_SUPPORTED and leaves the fields below null. The risk engine never
     * requires them.
     */
    certificateDetail: z.enum(['AVAILABLE', 'NOT_SUPPORTED']),
    issuer: z.string().max(200).nullable(),
    expiresAt: z.iso.datetime().nullable(),
    daysLeft: z.number().int().min(-36500).max(36500).nullable(),
  })
  .strict();
export type SslCheck = z.infer<typeof sslCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 4 — HTTP security headers
// ---------------------------------------------------------------------------

export const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;
export type SecurityHeader = (typeof SECURITY_HEADERS)[number];
export const securityHeaderSchema = z.enum(SECURITY_HEADERS);

export const HEADER_GRADES = ['A', 'B', 'C', 'D', 'F'] as const;

export const headersCheckSchema = z
  .object({
    status: checkStatusSchema,
    grade: z.enum(HEADER_GRADES).nullable(),
    score: z.number().int().min(0).max(100).nullable(),
    present: z.array(securityHeaderSchema).max(SECURITY_HEADERS.length),
    missing: z.array(securityHeaderSchema).max(SECURITY_HEADERS.length),
    /** Present but malformed (e.g. X-Content-Type-Options: yes) — scores 0. */
    invalid: z.array(securityHeaderSchema).max(SECURITY_HEADERS.length),
    /** Header values, truncated. Properties of the site, not the user (§17.1). */
    details: z.partialRecord(securityHeaderSchema, z.string().max(512)),
  })
  .strict();
export type HeadersCheck = z.infer<typeof headersCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 5 — trackers (Disconnect.me)
// ---------------------------------------------------------------------------

export const TRACKER_CATEGORIES = ['Advertising', 'Analytics', 'Social', 'Fingerprinting', 'Cryptomining'] as const;
export type TrackerCategory = (typeof TRACKER_CATEGORIES)[number];
export const trackerCategorySchema = z.enum(TRACKER_CATEGORIES);

/** Feature 5 "Intensity scoring: None (0), Light (1–3), Moderate (4–10), Heavy (11+)". */
export const TRACKER_INTENSITIES = ['none', 'light', 'moderate', 'heavy'] as const;

export const trackerCheckSchema = z
  .object({
    status: checkStatusSchema,
    trackerCount: z.number().int().min(0).max(5000),
    trackers: z
      .array(z.object({ name: z.string().min(1).max(100), domain: host, category: trackerCategorySchema }).strict())
      .max(200),
    intensity: z.enum(TRACKER_INTENSITIES),
    categories: z.partialRecord(trackerCategorySchema, z.number().int().min(0).max(5000)),
    /** Sub-resource requests to a different site than the page — feeds the §19.3 ratio signal. */
    thirdPartyRequests: z.number().int().min(0).max(100000),
    totalRequests: z.number().int().min(0).max(100000),
  })
  .strict();
export type TrackerCheck = z.infer<typeof trackerCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 6 — breached password (HIBP k-anonymity)
// ---------------------------------------------------------------------------

/** Boolean + count only. Never the password, hash or prefix (§17.3). */
export const passwordBreachCheckSchema = z
  .object({
    status: checkStatusSchema,
    isBreached: z.boolean(),
    breachCount: z.number().int().min(0).max(1_000_000_000),
  })
  .strict();
export type PasswordBreachCheck = z.infer<typeof passwordBreachCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 9 — mixed content
// ---------------------------------------------------------------------------

export const MIXED_CONTENT_TYPES = ['script', 'iframe', 'stylesheet', 'object', 'image', 'media', 'font', 'other'] as const;

export const mixedContentCheckSchema = z
  .object({
    status: checkStatusSchema,
    mixedCount: z.number().int().min(0).max(10000),
    /** HTTP script / iframe / stylesheet / object on an HTTPS page — §19.2 "Mixed content (active)". */
    activeCount: z.number().int().min(0).max(10000),
    /** HTTP image / media — §19.2 "Mixed content (passive)". */
    passiveCount: z.number().int().min(0).max(10000),
    /** Host only — never the resource URL (§17.2). */
    resources: z.array(z.object({ type: z.enum(MIXED_CONTENT_TYPES), host, active: z.boolean() }).strict()).max(50),
  })
  .strict();
export type MixedContentCheck = z.infer<typeof mixedContentCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 8 — outdated JavaScript libraries (Retire.js)
// ---------------------------------------------------------------------------

export const VULN_SEVERITIES = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type VulnSeverity = (typeof VULN_SEVERITIES)[number];
export const vulnSeveritySchema = z.enum(VULN_SEVERITIES);

export const jsVulnCheckSchema = z
  .object({
    status: checkStatusSchema,
    libraries: z
      .array(
        z
          .object({
            name: z.string().min(1).max(64),
            version: z.string().min(1).max(32),
            severity: vulnSeveritySchema,
            vulnerabilities: z
              .array(
                z
                  .object({
                    severity: vulnSeveritySchema,
                    cves: z.array(z.string().max(32)).max(20),
                    summary: z.string().max(300).nullable(),
                  })
                  .strict()
              )
              .max(50),
          })
          .strict()
      )
      .max(50),
    vulnerableCount: z.number().int().min(0).max(50),
    highestSeverity: vulnSeveritySchema,
  })
  .strict();
export type JsVulnCheck = z.infer<typeof jsVulnCheckSchema>;

// ---------------------------------------------------------------------------
// Feature 11 — browser fingerprinting
// ---------------------------------------------------------------------------

export const FINGERPRINT_TECHNIQUES = ['canvas', 'webgl', 'audio'] as const;

export const fingerprintCheckSchema = z
  .object({
    status: checkStatusSchema,
    detected: z.boolean(),
    techniques: z.array(z.enum(FINGERPRINT_TECHNIQUES)).max(FINGERPRINT_TECHNIQUES.length),
  })
  .strict();
export type FingerprintCheck = z.infer<typeof fingerprintCheckSchema>;

// ---------------------------------------------------------------------------
// §31.1 — redirect chain (main frame)
// ---------------------------------------------------------------------------

/** Query strings stripped from every hop under the §17.2 rule — host only. */
export const redirectCheckSchema = z
  .object({
    status: checkStatusSchema,
    hops: z
      .array(
        z
          .object({
            host,
            statusCode: z.number().int().min(300).max(399),
            scheme: z.enum(['https:', 'http:']),
          })
          .strict()
      )
      .max(20),
  })
  .strict();
export type RedirectCheck = z.infer<typeof redirectCheckSchema>;

// ---------------------------------------------------------------------------

/** Everything the extension can report. Every check is optional — a check
 * the user disabled, or one that hasn't finished yet, is simply absent. */
export const localChecksSchema = z
  .object({
    ssl: sslCheckSchema.optional(),
    headers: headersCheckSchema.optional(),
    trackers: trackerCheckSchema.optional(),
    passwordBreach: passwordBreachCheckSchema.optional(),
    mixedContent: mixedContentCheckSchema.optional(),
    jsVulns: jsVulnCheckSchema.optional(),
    fingerprinting: fingerprintCheckSchema.optional(),
    redirects: redirectCheckSchema.optional(),
  })
  .strict();
export type LocalChecks = z.infer<typeof localChecksSchema>;
export type LocalCheckName = keyof LocalChecks;
