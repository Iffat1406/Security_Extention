import { createHash } from 'node:crypto';
import type { Prisma, PrismaClient, ScanResult as ScanRow } from '@prisma/client';
import type { FastifyBaseLogger } from 'fastify';
import psl from 'psl';
import {
  NOT_SUPPORTED_MESSAGES,
  analyzeRedirectChain,
  classifyPage,
  detectLookalike,
  isIpLiteral,
  withSettingsDefaults,
  type AnalyzedRedirectChain,
  type LocalChecks,
  type LookalikeMatch,
  type NotSupportedReason,
  type ScanDetails,
  type ScanResult,
  type ScanSubmission,
  type UserSettings,
} from '@guardtab/shared';
import { env, isAiConfigured } from '../config/env';
import { DepTimer } from '../lib/dep-timer';
import { metrics } from '../lib/metrics';
import { computeRisk, type RiskEngineInput, type RiskEngineOutput } from '../risk-engine/engine';
import { explainScan, findCachedExplanation } from './ai-explainer.service';
import { urlCacheKey } from './dedup.service';
import { checkSafeBrowsing, type SafeBrowsingResult } from './external/safe-browsing.service';
import type { ExternalOutcome, HttpClient } from './external/types';
import { checkVirusTotal, type VirusTotalResult } from './external/virustotal.service';
import { checkDomainAge, type DomainAgeResult } from './external/whois.service';
import { getCommunitySignal, recordScanObservation, type CommunitySignal } from './reputation.service';
import { normalizeUrl, reputationLookupUrl } from './url-normalizer.service';
import { validateOutboundUrl, type DnsLookup } from './url-safety.service';

/**
 * scan.service.ts — the POST /scans pipeline (§9 page-load flow as
 * revised by §19, §20, §22, §24).
 *
 *   1. URL: browser-internal -> NOT_SUPPORTED; normalise (§20.1); SSRF/DNS
 *      safety (§20.4) -> 400 INVALID_URL / BLOCKED_TARGET / ...
 *   2. Exclusions (§23.2, §30.2) -> NOT_SUPPORTED, nothing stored.
 *   3. External lookups in parallel, deduplicated across users (§24.4).
 *   4. Deterministic risk engine (§19) — the score.
 *   5. One transaction, 2s budget (§24.4) — only for signed-in users with
 *      "Store scan history" on. Anonymous scans are never written (§17.4).
 *   6. Threat intelligence contribution (§22) unless opted out (§23.1).
 *   7. AI explanation runs after the response (§24.2 "never blocks").
 */

// ---------------------------------------------------------------------------
// Stored shapes (JSONB) — enough to re-score a scan without re-running it
// ---------------------------------------------------------------------------

interface StoredRiskEvidence {
  evidence: RiskEngineOutput['evidence'];
  skipped: RiskEngineOutput['skipped'];
  protocol: 'http:' | 'https:';
  community: RiskEngineInput['community'];
}

interface StoredRedirects {
  status: NonNullable<LocalChecks['redirects']>['status'];
  hops: NonNullable<LocalChecks['redirects']>['hops'];
  analyzed: AnalyzedRedirectChain | null;
}

type StoredLookalike = { status: 'OK' | 'NOT_SUPPORTED'; match: LookalikeMatch | null };

export interface ScanDeps {
  prisma: PrismaClient;
  log: FastifyBaseLogger;
  userId: string | null;
  /** Injected in tests to simulate external services (§26.3). */
  httpClient?: HttpClient;
  /** Injected in tests so the real SSRF guard runs against controlled DNS answers. */
  dnsLookup?: DnsLookup;
}

export interface ScanRunResult {
  result: ScanResult;
  /** §28.1 structured log fields for this request. */
  logFields: { domain: string | null; scanStatus: string; deps: Record<string, number> };
  /** Work to run after the response is sent (AI explanation). */
  afterResponse: (() => Promise<void>) | null;
}

const BROWSER_INTERNAL_RE = /^(chrome|chrome-extension|chrome-search|chrome-untrusted|devtools|edge|brave|opera|vivaldi|about|moz-extension|view-source):/i;
/** Exclusion reasons that are a 200 NOT_SUPPORTED rather than a 400 (§20.5). */
const NOT_SUPPORTED_AFTER_PARSE: ReadonlySet<NotSupportedReason> = new Set(['WEB_STORE', 'PDF_VIEWER', 'USER_EXCLUDED']);

export function siteOf(host: string): string {
  return psl.get(host) ?? host;
}

export function evidenceHash(domain: string, output: RiskEngineOutput): string {
  const signature = output.evidence.map((e) => `${e.signal}:${e.points}`).join('|');
  return createHash('sha256').update(`${domain}\n${output.riskEngineVersion}\n${signature}\n${output.band}`).digest('hex');
}

function notSupportedResult(reason: NotSupportedReason, host: string | null = null, registrableDomain: string | null = null): ScanResult {
  return {
    scanId: null,
    status: 'NOT_SUPPORTED',
    persisted: false,
    host,
    registrableDomain,
    scannedAt: new Date().toISOString(),
    securityScore: null,
    privacyScore: null,
    overall: null,
    band: null,
    evidence: [],
    skipped: [],
    checks: {},
    details: {},
    ai: null,
    riskEngineVersion: null,
    scannerVersion: null,
    notSupportedReason: reason,
  };
}

/** Drops local results the user's settings say must not exist (§23.1) — the extension is untrusted (§18.4). */
function applySettingsToChecks(checks: LocalChecks, settings: UserSettings): LocalChecks {
  const filtered: LocalChecks = { ...checks };
  if (!settings.trackerDetection) {
    delete filtered.trackers;
    delete filtered.fingerprinting;
  }
  if (!settings.passwordBreachDetection) delete filtered.passwordBreach;
  return filtered;
}

export function buildDetails(args: {
  safeBrowsing: ExternalOutcome<SafeBrowsingResult> | null;
  virusTotal: ExternalOutcome<VirusTotalResult> | null;
  whois: ExternalOutcome<DomainAgeResult> | null;
  lookalike: StoredLookalike | null;
  community: CommunitySignal | null;
  redirects: AnalyzedRedirectChain | null;
}): ScanDetails {
  const details: ScanDetails = {};
  if (args.safeBrowsing?.status === 'OK') details.safeBrowsing = args.safeBrowsing.data;
  if (args.virusTotal?.status === 'OK') details.virusTotal = args.virusTotal.data;
  if (args.whois?.status === 'OK') details.domainAge = { days: args.whois.data.domainAgeDays, registrar: args.whois.data.registrar };
  if (args.lookalike?.match) {
    const { brand, brandDomain, similarity, technique, explanation } = args.lookalike.match;
    details.lookalike = { brand, brandDomain, similarity, technique, explanation };
  }
  if (args.community) {
    details.reputation = { reputation: args.community.reputation, confidence: args.community.confidence, indicatorTypes: args.community.indicatorTypes };
  }
  if (args.redirects && args.redirects.hops.length > 0) details.redirects = { hops: args.redirects.hops, signals: args.redirects.signals };
  return details;
}

async function loadSettings(prisma: PrismaClient, userId: string | null): Promise<{ settings: UserSettings; excludedDomains: string[] }> {
  if (!userId) return { settings: withSettingsDefaults({}), excludedDomains: [] };
  const row = await prisma.userSettings.findUnique({ where: { userId } });
  return { settings: withSettingsDefaults(row?.settings), excludedDomains: row?.excludedDomains ?? [] };
}

// ---------------------------------------------------------------------------

export async function runScan(deps: ScanDeps, submission: ScanSubmission): Promise<ScanRunResult> {
  const { prisma, userId } = deps;
  const timer = new DepTimer();
  const stopScanTimer = metrics.scanDuration.startTimer();
  const done = (result: ScanResult, afterResponse: ScanRunResult['afterResponse'] = null): ScanRunResult => {
    stopScanTimer();
    metrics.scanTotal.inc({ status: result.status });
    return { result, afterResponse, logFields: { domain: result.registrableDomain, scanStatus: result.status, deps: timer.toJSON() } };
  };

  // ---- 1. URL -------------------------------------------------------------
  if (BROWSER_INTERNAL_RE.test(submission.url)) return done(notSupportedResult('BROWSER_INTERNAL'));

  const normalized = normalizeUrl(submission.url); // throws INVALID_URL / UNSUPPORTED_SCHEME / URL_TOO_LONG
  const { settings, excludedDomains } = await timer.time('db', () => loadSettings(prisma, userId));

  const classification = classifyPage(submission.url, { excludedDomains, scanLocalAddresses: false });
  if (!classification.scannable && NOT_SUPPORTED_AFTER_PARSE.has(classification.reason)) {
    return done(notSupportedResult(classification.reason, normalized.host, normalized.registrableDomain));
  }
  // Local, private and metadata targets become 400 BLOCKED_TARGET here, and a
  // public name that resolves to a private address is caught by the DNS check.
  await timer.time('urlSafety', () => validateOutboundUrl(submission.url, deps.dnsLookup));

  const protocol = new URL(submission.url).protocol as 'http:' | 'https:';
  const { host, registrableDomain } = normalized;
  const checks = applySettingsToChecks(submission.checks, settings);
  const persist = userId !== null && settings.storeScanHistory;

  // ---- 3. external lookups ------------------------------------------------
  const lookupUrl = reputationLookupUrl(submission.url);
  const cacheKey = urlCacheKey(host, normalized.path);
  const bypassCache = submission.rescan === true;

  const reputationChain = async () => {
    const safeBrowsing = await timer.time('safeBrowsing', () =>
      checkSafeBrowsing(prisma, { lookupUrl, cacheKey, bypassCache }, deps.httpClient)
    );
    // §7 "VirusTotal is only called if Safe Browsing returns clean". If Safe
    // Browsing is down, VirusTotal still runs so the scan keeps a reputation source.
    const virusTotal: ExternalOutcome<VirusTotalResult> =
      safeBrowsing.status === 'OK' && safeBrowsing.data.isMalicious
        ? { status: 'SKIPPED', reason: 'SAFE_BROWSING_MALICIOUS' }
        : await timer.time('virusTotal', () => checkVirusTotal(prisma, { lookupUrl, cacheKey, bypassCache }, deps.httpClient));
    return { safeBrowsing, virusTotal };
  };

  const [{ safeBrowsing, virusTotal }, whois, community] = await Promise.all([
    reputationChain(),
    timer.time('whois', () => checkDomainAge(prisma, registrableDomain, deps.httpClient)),
    timer.time('db', () => getCommunitySignal(prisma, registrableDomain)),
  ]);

  const lookalike: StoredLookalike = isIpLiteral(host)
    ? { status: 'NOT_SUPPORTED', match: null }
    : { status: 'OK', match: detectLookalike(host, registrableDomain) };

  const redirects: AnalyzedRedirectChain | null =
    checks.redirects?.status === 'OK'
      ? analyzeRedirectChain(checks.redirects.hops, {
          finalHost: host,
          finalProtocol: protocol,
          siteOf,
          finalDomainAgeDays: whois.status === 'OK' ? whois.data.domainAgeDays : null,
          isLookalikeHost: (h) => (detectLookalike(h, siteOf(h))?.similarity ?? 0) >= 0.9,
        })
      : null;

  // ---- 4. risk engine ------------------------------------------------------
  const communityInput: RiskEngineInput['community'] = {
    status: community.status,
    confidence: community.confidence,
    uniqueReporters: community.uniqueReporters,
  };
  const risk = timer.timeSync('riskEngine', () =>
    computeRisk({ protocol, checks, safeBrowsing, virusTotal, whois, lookalike, redirects, community: communityInput })
  );
  const hash = evidenceHash(registrableDomain, risk);
  const details = buildDetails({ safeBrowsing, virusTotal, whois, lookalike, community, redirects });
  const now = new Date();

  // ---- 5. persist -------------------------------------------------------------
  const willExplain = persist && settings.aiExplanation && isAiConfigured() && risk.scanStatus !== 'FAILED';
  let scanId: string | null = null;
  let newUserForDomain = false;

  if (persist) {
    const storedRedirects: StoredRedirects | null = checks.redirects
      ? { status: checks.redirects.status, hops: checks.redirects.hops, analyzed: redirects }
      : null;
    const storedEvidence: StoredRiskEvidence = { evidence: risk.evidence, skipped: risk.skipped, protocol, community: communityInput };
    const json = (v: unknown) => (v === null || v === undefined ? undefined : (v as Prisma.InputJsonValue));

    const row = await timer.time('db', () =>
      prisma.$transaction(
        async (tx) => {
          newUserForDomain = (await tx.scanResult.count({ where: { userId: userId!, registrableDomain } })) === 0;
          return tx.scanResult.create({
            data: {
              userId: userId!,
              registrableDomain,
              host,
              // §17.2 path is dropped when STORE_PATH=false globally or "Store page paths" is off.
              path: env.STORE_PATH && settings.storePagePaths ? normalized.path : null,
              // §24.2: SCANNING while the AI explanation is pending; final state otherwise.
              scanStatus: willExplain ? 'SCANNING' : risk.scanStatus,
              scannedAt: now,
              startedAt: now,
              completedAt: willExplain ? null : now,
              safeBrowsingData: json(safeBrowsing),
              virusTotalData: json(virusTotal),
              sslData: json(checks.ssl),
              headersData: json(checks.headers),
              trackerData: json(checks.trackers),
              passwordBreachData: json(checks.passwordBreach),
              domainAgeData: json(whois),
              jsVulnData: json(checks.jsVulns),
              mixedContentData: json(checks.mixedContent),
              fingerprintData: json(checks.fingerprinting),
              redirectData: json(storedRedirects),
              lookalikeData: json(lookalike),
              checkStatus: json(risk.checks),
              securityScore: risk.securityScore,
              privacyScore: risk.privacyScore,
              overallScore: risk.overall,
              riskBand: risk.band,
              riskEvidence: json(storedEvidence),
              riskEngineVersion: risk.riskEngineVersion,
              scannerVersion: submission.scannerVersion.slice(0, 16),
              schemaVersion: submission.schemaVersion,
              evidenceHash: hash,
            },
          });
        },
        { timeout: 2000 }
      )
    );
    scanId = row.id;
  }

  // ---- 6. threat intelligence (best effort — never fails the scan) ------------
  if (settings.contributeThreatIntel) {
    try {
      await timer.time('db', () =>
        recordScanObservation(prisma, {
          registrableDomain,
          newUserForDomain,
          securityScore: risk.securityScore,
          domainAgeDays: whois.status === 'OK' ? whois.data.domainAgeDays : null,
          evidence: risk.evidence,
          context: {
            safeBrowsingThreatTypes: safeBrowsing.status === 'OK' ? safeBrowsing.data.threatTypes : [],
            trackerCount: checks.trackers?.status === 'OK' ? checks.trackers.trackerCount : 0,
            lookalikeSimilarity: lookalike.match?.similarity,
            lookalikeBrand: lookalike.match?.brand,
          },
        })
      );
    } catch (error) {
      deps.log.warn({ err: error instanceof Error ? error.message : 'unknown' }, 'threat intelligence update failed');
    }
  }

  // ---- 7. AI -------------------------------------------------------------------
  // Anonymous scans only ever get an already-cached explanation (no Claude spend on anonymous traffic).
  let ai: ScanResult['ai'] = null;
  if (!persist && risk.scanStatus !== 'FAILED' && isAiConfigured()) {
    ai = await timer.time('db', () => findCachedExplanation(prisma, hash));
  }

  const result: ScanResult = {
    scanId,
    status: willExplain ? 'SCANNING' : risk.scanStatus,
    persisted: persist,
    host,
    registrableDomain,
    scannedAt: now.toISOString(),
    securityScore: risk.securityScore,
    privacyScore: risk.privacyScore,
    overall: risk.overall,
    band: risk.band,
    evidence: risk.evidence,
    skipped: risk.skipped,
    checks: risk.checks,
    details,
    ai,
    riskEngineVersion: risk.riskEngineVersion,
    scannerVersion: submission.scannerVersion,
    notSupportedReason: null,
  };

  const afterResponse =
    willExplain && scanId
      ? async () => {
          const id = scanId!;
          const outcome = await explainScan(
            prisma,
            {
              registrableDomain,
              securityScore: risk.securityScore,
              privacyScore: risk.privacyScore,
              overall: risk.overall,
              band: risk.band,
              evidence: risk.evidence,
              checks: risk.checks,
              evidenceHash: hash,
            },
            deps.log
          );
          await prisma.scanResult.update({
            where: { id },
            data: {
              scanStatus: risk.scanStatus,
              completedAt: new Date(),
              ...(outcome.status === 'OK' ? { aiExplanation: outcome.ai.explanation, aiAdvice: outcome.ai.advice } : {}),
            },
          });
        }
      : null;

  return done(result, afterResponse);
}

// ---------------------------------------------------------------------------
// Reading and re-scoring stored scans
// ---------------------------------------------------------------------------

function asObject<T>(value: Prisma.JsonValue | null): T | null {
  return value === null || typeof value !== 'object' ? null : (value as unknown as T);
}

export function localChecksFromRow(row: ScanRow): LocalChecks {
  const redirects = asObject<StoredRedirects>(row.redirectData);
  const checks: LocalChecks = {};
  const assign = <K extends keyof LocalChecks>(key: K, value: Prisma.JsonValue | null) => {
    const obj = asObject<NonNullable<LocalChecks[K]>>(value);
    if (obj) checks[key] = obj;
  };
  assign('ssl', row.sslData);
  assign('headers', row.headersData);
  assign('trackers', row.trackerData);
  assign('passwordBreach', row.passwordBreachData);
  assign('mixedContent', row.mixedContentData);
  assign('jsVulns', row.jsVulnData);
  assign('fingerprinting', row.fingerprintData);
  if (redirects) checks.redirects = { status: redirects.status, hops: redirects.hops };
  return checks;
}

export function engineInputFromRow(row: ScanRow, checksOverride?: LocalChecks): RiskEngineInput {
  const stored = asObject<StoredRiskEvidence>(row.riskEvidence);
  return {
    protocol: stored?.protocol ?? 'https:',
    checks: checksOverride ?? localChecksFromRow(row),
    safeBrowsing: asObject(row.safeBrowsingData),
    virusTotal: asObject(row.virusTotalData),
    whois: asObject(row.domainAgeData),
    lookalike: asObject(row.lookalikeData),
    redirects: asObject<StoredRedirects>(row.redirectData)?.analyzed ?? null,
    community: stored?.community ?? null,
  };
}

export function rowToScanResult(row: ScanRow): ScanResult {
  const stored = asObject<StoredRiskEvidence>(row.riskEvidence);
  const input = engineInputFromRow(row);
  return {
    scanId: row.id,
    status: row.scanStatus,
    persisted: true,
    host: row.host,
    registrableDomain: row.registrableDomain,
    scannedAt: row.scannedAt.toISOString(),
    securityScore: row.securityScore,
    privacyScore: row.privacyScore,
    overall: row.overallScore,
    band: row.riskBand,
    evidence: stored?.evidence ?? [],
    skipped: stored?.skipped ?? [],
    checks: (asObject(row.checkStatus) ?? {}) as ScanResult['checks'],
    details: buildDetails({
      safeBrowsing: input.safeBrowsing,
      virusTotal: input.virusTotal,
      whois: input.whois,
      lookalike: asObject<StoredLookalike>(row.lookalikeData),
      community: null,
      redirects: input.redirects,
    }),
    ai: row.aiExplanation ? { explanation: row.aiExplanation, advice: row.aiAdvice } : null,
    riskEngineVersion: row.riskEngineVersion,
    scannerVersion: row.scannerVersion,
    notSupportedReason: null,
  };
}

/**
 * PATCH /scans/:id — merge later local results (e.g. the breach check) and
 * re-score from the stored evidence. External lookups are not re-run.
 */
export async function updateScanChecks(prisma: PrismaClient, row: ScanRow, patch: LocalChecks, userId: string): Promise<ScanResult> {
  const { settings } = await loadSettings(prisma, userId);
  const merged = applySettingsToChecks({ ...localChecksFromRow(row), ...patch }, settings);
  const input = engineInputFromRow(row, merged);
  const risk = computeRisk(input);
  const stored = asObject<StoredRiskEvidence>(row.riskEvidence);
  const json = (v: unknown) => (v === undefined ? undefined : (v as Prisma.InputJsonValue));

  const updated = await prisma.scanResult.update({
    where: { id: row.id },
    data: {
      sslData: json(merged.ssl),
      headersData: json(merged.headers),
      trackerData: json(merged.trackers),
      passwordBreachData: json(merged.passwordBreach),
      mixedContentData: json(merged.mixedContent),
      jsVulnData: json(merged.jsVulns),
      fingerprintData: json(merged.fingerprinting),
      checkStatus: json(risk.checks),
      securityScore: risk.securityScore,
      privacyScore: risk.privacyScore,
      overallScore: risk.overall,
      riskBand: risk.band,
      riskEvidence: json({ ...stored, evidence: risk.evidence, skipped: risk.skipped }),
      evidenceHash: evidenceHash(row.registrableDomain, risk),
      // Leave SCANNING alone while the AI job is still pending.
      ...(row.scanStatus === 'SCANNING' ? {} : { scanStatus: risk.scanStatus }),
    },
  });
  return rowToScanResult(updated);
}

export function notSupportedMessage(reason: string): string {
  return NOT_SUPPORTED_MESSAGES[reason as NotSupportedReason] ?? 'This page is not scanned.';
}
