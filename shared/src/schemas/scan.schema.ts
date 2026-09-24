import { z } from 'zod';
import { checkStatusSchema, localChecksSchema } from './checks.schema';

/** §24.1 scan lifecycle states. */
export const SCAN_STATUSES = ['PENDING', 'SCANNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'NOT_SUPPORTED'] as const;
export const scanStatusSchema = z.enum(SCAN_STATUSES);
export type ScanStatus = z.infer<typeof scanStatusSchema>;

/** §19.4 bands. */
export const RISK_BANDS = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export const riskBandSchema = z.enum(RISK_BANDS);
export type RiskBand = z.infer<typeof riskBandSchema>;

export const EVIDENCE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

/** §19.5 evidence object entry. */
export const evidenceItemSchema = z.object({
  signal: z.string(),
  points: z.number().int(),
  severity: z.enum(EVIDENCE_SEVERITIES),
  category: z.enum(['security', 'privacy']),
  detail: z.string(),
});
export type EvidenceItem = z.infer<typeof evidenceItemSchema>;

export const skippedItemSchema = z.object({ signal: z.string(), reason: z.string() });
export type SkippedItem = z.infer<typeof skippedItemSchema>;

/** Every check the popup renders a row for (§23.3), local and backend. */
export const CHECK_NAMES = [
  'ssl',
  'headers',
  'trackers',
  'passwordBreach',
  'mixedContent',
  'jsVulns',
  'fingerprinting',
  'redirects',
  'safeBrowsing',
  'virusTotal',
  'whois',
  'lookalike',
  'community',
] as const;
export const checkNameSchema = z.enum(CHECK_NAMES);
export type CheckName = z.infer<typeof checkNameSchema>;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/**
 * POST /api/v1/scans body.
 *
 * `url` is the full page URL. It exists in memory for the duration of the
 * request only — Safe Browsing and VirusTotal score full URLs — and is never
 * persisted, logged or sent to Claude (§17.2). The max here is deliberately
 * above the 2048 limit so the normaliser can return the specific
 * URL_TOO_LONG code (§20.5) rather than a generic VALIDATION_ERROR.
 */
export const scanSubmissionSchema = z
  .object({
    url: z.string().min(1).max(8192),
    schemaVersion: z.number().int().min(1),
    scannerVersion: z.string().min(1).max(16),
    /** §23.3 "Rescan bypasses both the Chrome Storage cache and the backend dedup window". */
    rescan: z.boolean().optional(),
    checks: localChecksSchema,
  })
  .strict();
export type ScanSubmission = z.infer<typeof scanSubmissionSchema>;

/**
 * PATCH /api/v1/scans/:id — later local results for an existing scan.
 * §30.3 / §15: "Local results are posted as each checker completes" — e.g.
 * the breach check only runs once the user types a password, long after the
 * initial POST.
 */
export const scanUpdateSchema = z.object({ checks: localChecksSchema }).strict();
export type ScanUpdate = z.infer<typeof scanUpdateSchema>;

export const scanHistoryQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

export const aiResultSchema = z.object({
  explanation: z.string(),
  advice: z.string().nullable(),
});
export type AiResult = z.infer<typeof aiResultSchema>;

/** Backend-only check summaries the popup renders (§23.3 rows). */
export const scanDetailsSchema = z.object({
  safeBrowsing: z.object({ isMalicious: z.boolean(), threatTypes: z.array(z.string()) }).optional(),
  virusTotal: z
    .object({ malicious: z.number().int(), suspicious: z.number().int(), harmless: z.number().int(), undetected: z.number().int() })
    .optional(),
  domainAge: z.object({ days: z.number().int().nullable(), registrar: z.string().nullable() }).optional(),
  lookalike: z
    .object({
      brand: z.string(),
      brandDomain: z.string(),
      similarity: z.number(),
      technique: z.string(),
      explanation: z.string(),
    })
    .optional(),
  reputation: z
    .object({
      reputation: z.enum(['UNKNOWN', 'CLEAN', 'SUSPICIOUS', 'MALICIOUS']),
      confidence: z.number(),
      indicatorTypes: z.array(z.string()),
    })
    .optional(),
  redirects: z
    .object({
      hops: z.array(z.object({ host: z.string(), statusCode: z.number().int(), hopType: z.string() })),
      signals: z.array(z.string()),
    })
    .optional(),
});
export type ScanDetails = z.infer<typeof scanDetailsSchema>;

/** §24.2 response shape for POST /scans (202) and GET /scans/:id (200). */
export const scanResultSchema = z.object({
  /** null for anonymous / not-persisted scans — nothing to poll (§17.4). */
  scanId: z.string().nullable(),
  status: scanStatusSchema,
  persisted: z.boolean(),
  host: z.string().nullable(),
  registrableDomain: z.string().nullable(),
  scannedAt: z.string(),
  securityScore: z.number().int().nullable(),
  privacyScore: z.number().int().nullable(),
  overall: z.number().int().nullable(),
  band: riskBandSchema.nullable(),
  evidence: z.array(evidenceItemSchema),
  skipped: z.array(skippedItemSchema),
  checks: z.partialRecord(checkNameSchema, checkStatusSchema),
  details: scanDetailsSchema,
  ai: aiResultSchema.nullable(),
  riskEngineVersion: z.string().nullable(),
  scannerVersion: z.string().nullable(),
  /** Set when status is NOT_SUPPORTED — e.g. BROWSER_INTERNAL, USER_EXCLUDED (§30.2). */
  notSupportedReason: z.string().nullable(),
});
export type ScanResult = z.infer<typeof scanResultSchema>;
