import { z } from 'zod';

/**
 * Validated process environment.
 *
 * Secrets the server cannot run safely without (JWT/cookie/salt) are
 * required. Every third-party credential is OPTIONAL: §33.3 "the
 * architecture should degrade when [a limit] is hit ... rather than depend
 * on a number" — a missing key degrades the same way an outage does (the
 * check reports UNAVAILABLE / SKIPPED and the scan still scores).
 */

/** `KEY=` in a .env file yields "" — treat that as "not set". */
const optionalString = z.preprocess((v) => (typeof v === 'string' && v.trim() === '' ? undefined : v), z.string().optional());
const boolFromString = (defaultValue: boolean) =>
  z.preprocess((v) => (v === undefined || v === '' ? defaultValue : String(v).toLowerCase() === 'true'), z.boolean());

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  /** Public base URL of this backend — used for export links, the privacy policy URL and OAuth redirects. */
  PUBLIC_BASE_URL: z.string().url().default('http://localhost:3000'),
  /** Extra comma-separated CORS origins (dev tools, a separately hosted dashboard). */
  CORS_ORIGIN: optionalString,
  /** Chrome extension id — the CORS allow-list and the OAuth redirect allow-list (§18.3). */
  EXTENSION_ID: optionalString,

  // ---- Phase 2 — auth -----------------------------------------------------
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters (§13)'),
  JWT_ACCESS_TTL: z.string().default('1h'),
  JWT_REFRESH_TTL_DAYS: z.coerce.number().int().positive().default(30),
  COOKIE_SECRET: z.string().min(32, 'COOKIE_SECRET must be at least 32 characters'),
  AUDIT_IP_HASH_SALT: z.string().min(16, 'AUDIT_IP_HASH_SALT must be at least 16 characters'),
  GOOGLE_CLIENT_ID: optionalString,
  GOOGLE_CLIENT_SECRET: optionalString,
  GOOGLE_CALLBACK_URL: z.string().url().default('http://localhost:3000/api/v1/auth/google/callback'),

  // ---- Redis (optional) -----------------------------------------------------
  /** When set: rate-limit counters live in Redis and scheduled jobs run on BullMQ (§28.5). */
  REDIS_URL: optionalString,

  // ---- Phase 5 — reputation -------------------------------------------------
  SAFE_BROWSING_API_KEY: optionalString,
  VIRUSTOTAL_API_KEY: optionalString,
  /** §7 free tier: 4 requests/minute, 500/day. Confirm current limits (§33.3). */
  VIRUSTOTAL_PER_MINUTE: z.coerce.number().int().positive().default(4),
  VIRUSTOTAL_PER_DAY: z.coerce.number().int().positive().default(500),
  /** Domain age comes from RDAP (IANA bootstrap, no key) — see whois.service.ts. */
  RDAP_BASE_URL: z.string().url().default('https://rdap.org'),

  // ---- Phase 7 — AI ---------------------------------------------------------
  ANTHROPIC_API_KEY: optionalString,
  /** Default per the current Claude API guidance; set e.g. claude-haiku-4-5 to trade quality for cost. */
  ANTHROPIC_MODEL: z.string().default('claude-opus-5'),
  ANTHROPIC_MONTHLY_SPEND_CAP_USD: z.coerce.number().nonnegative().default(25),

  // ---- §17 / §29 privacy & retention ----------------------------------------
  /** §17.2 "can be disabled globally (STORE_PATH=false)". */
  STORE_PATH: boolFromString(true),
  SCAN_RETENTION_DAYS: z.coerce.number().int().positive().default(90),
  CHAT_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
  TOKEN_GRACE_DAYS: z.coerce.number().int().nonnegative().default(7),
  AUDIT_RETENTION_DAYS: z.coerce.number().int().positive().default(90),
  DELETION_GRACE_DAYS: z.coerce.number().int().nonnegative().default(7),

  // ---- operations -----------------------------------------------------------
  /** Scheduled jobs (§28.5). Disabled automatically under NODE_ENV=test. */
  JOBS_ENABLED: boolFromString(true),
  /** Bearer token for GET /metrics. If unset, /metrics requires an ADMIN JWT. */
  METRICS_TOKEN: optionalString,
});

export type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // Fail fast and loud — a misconfigured env must never start the server
    // silently with a wrong default.
    console.error('Invalid environment configuration:', z.flattenError(parsed.error).fieldErrors);
    throw new Error('Invalid environment configuration');
  }
  return parsed.data;
}

export const env = loadEnv();

export const isGoogleAuthConfigured = Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
/** A function, not a constant, so tests can enable AI with an injected client. */
export const isAiConfigured = (): boolean => Boolean(env.ANTHROPIC_API_KEY);
