import {
  isSessionReplayDomain,
  type AnalyzedRedirectChain,
  type CheckName,
  type CheckStatus,
  type EvidenceItem,
  type LocalChecks,
  type LookalikeMatch,
  type RiskBand,
  type SkippedItem,
} from '@guardtab/shared';
import type { ExternalOutcome } from '../services/external/types';
import type { SafeBrowsingResult } from '../services/external/safe-browsing.service';
import type { VirusTotalResult } from '../services/external/virustotal.service';
import type { DomainAgeResult } from '../services/external/whois.service';
import { BANDS, BLEND, PRIVACY_SIGNALS, RISK_ENGINE_VERSION, SECURITY_SIGNALS, THRESHOLDS } from './weights';

/**
 * risk-engine.ts — §19. A pure function: same input -> same output, no I/O,
 * no clock, no randomness. The AI layer explains this output; it never
 * produces or alters any number here (§19.8).
 */

export interface RiskEngineInput {
  /** From the backend's own parse of the URL — not the extension's ssl claim. */
  protocol: 'http:' | 'https:';
  checks: LocalChecks;
  safeBrowsing: ExternalOutcome<SafeBrowsingResult> | null;
  virusTotal: ExternalOutcome<VirusTotalResult> | null;
  whois: ExternalOutcome<DomainAgeResult> | null;
  lookalike: { status: CheckStatus; match: LookalikeMatch | null } | null;
  redirects: AnalyzedRedirectChain | null;
  community: { status: CheckStatus; confidence: number; uniqueReporters: number } | null;
}

export interface RiskEngineOutput {
  riskEngineVersion: string;
  securityScore: number | null;
  privacyScore: number | null;
  overall: number | null;
  band: RiskBand | null;
  evidence: EvidenceItem[];
  skipped: SkippedItem[];
  checks: Partial<Record<CheckName, CheckStatus>>;
  scanStatus: 'COMPLETED' | 'PARTIAL' | 'FAILED';
}

const LOCAL_CHECKS = ['ssl', 'headers', 'trackers', 'passwordBreach', 'mixedContent', 'jsVulns', 'fingerprinting', 'redirects'] as const;

export function bandOf(score: number): RiskBand {
  for (const { band, min } of BANDS) if (score >= min) return band;
  return 'CRITICAL';
}

/** Highest score that still falls inside `band` (SAFE -> 100, LOW -> 79 ...). */
export function bandUpperBound(band: RiskBand): number {
  const index = BANDS.findIndex((b) => b.band === band);
  return index <= 0 ? 100 : BANDS[index - 1]!.min - 1;
}

function statusOf(outcome: { status: CheckStatus } | null | undefined): CheckStatus | undefined {
  return outcome?.status;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export function computeRisk(input: RiskEngineInput): RiskEngineOutput {
  const { checks } = input;

  // ---- per-check status (§24.3) ---------------------------------------------
  const statuses: Partial<Record<CheckName, CheckStatus>> = {};
  for (const name of LOCAL_CHECKS) {
    const status = checks[name]?.status;
    if (status) statuses[name] = status;
  }
  const external: Array<[CheckName, { status: CheckStatus; reason?: string } | null]> = [
    ['safeBrowsing', input.safeBrowsing],
    ['virusTotal', input.virusTotal],
    ['whois', input.whois],
    ['lookalike', input.lookalike],
    ['community', input.community],
  ];
  const skipped: SkippedItem[] = [];
  for (const [name, outcome] of external) {
    const status = statusOf(outcome);
    if (!status) continue;
    statuses[name] = status;
    if (status === 'UNAVAILABLE' || status === 'SKIPPED') {
      const reason = outcome && 'reason' in outcome && typeof outcome.reason === 'string' ? outcome.reason : status;
      skipped.push({ signal: name.toUpperCase(), reason: status === 'UNAVAILABLE' ? `EXTERNAL_SERVICE_UNAVAILABLE:${reason}` : reason });
    }
  }
  for (const name of LOCAL_CHECKS) {
    const status = statuses[name];
    if (status === 'UNAVAILABLE' || status === 'SKIPPED') skipped.push({ signal: name.toUpperCase(), reason: status });
  }

  const statusValues = Object.values(statuses);
  // §24.1 FAILED: "The scan could not produce a score — every source failed".
  if (!statusValues.includes('OK')) {
    return {
      riskEngineVersion: RISK_ENGINE_VERSION,
      securityScore: null,
      privacyScore: null,
      overall: null,
      band: null,
      evidence: [],
      skipped,
      checks: statuses,
      scanStatus: 'FAILED',
    };
  }

  const evidence: EvidenceItem[] = [];
  const addSecurity = (signal: keyof typeof SECURITY_SIGNALS, detail: string, points: number = SECURITY_SIGNALS[signal].points) =>
    evidence.push({ signal, points, severity: SECURITY_SIGNALS[signal].severity, category: 'security', detail });
  const addPrivacy = (signal: keyof typeof PRIVACY_SIGNALS, detail: string, points: number = PRIVACY_SIGNALS[signal].points) =>
    evidence.push({ signal, points, severity: PRIVACY_SIGNALS[signal].severity, category: 'privacy', detail });

  // ---- §19.2 security --------------------------------------------------------
  if (input.safeBrowsing?.status === 'OK' && input.safeBrowsing.data.isMalicious) {
    addSecurity('SAFE_BROWSING_MALICIOUS', `Flagged as ${input.safeBrowsing.data.threatTypes.join(', ')} by Google Safe Browsing`);
  }

  if (input.virusTotal?.status === 'OK') {
    const { malicious } = input.virusTotal.data;
    if (malicious >= THRESHOLDS.VT_MALICIOUS_MIN_ENGINES) {
      addSecurity('VIRUSTOTAL_MALICIOUS', `${plural(malicious, 'security vendor')} on VirusTotal flag this address`);
    } else if (malicious >= 1) {
      addSecurity('VIRUSTOTAL_SUSPICIOUS', `${plural(malicious, 'security vendor')} on VirusTotal flag this address`);
    }
  }

  if (input.protocol === 'http:') {
    addSecurity('SERVED_OVER_HTTP', 'This page was loaded over unencrypted HTTP');
  }

  const ssl = checks.ssl;
  if (ssl?.status === 'OK') {
    let certSignal = false;
    if (ssl.isValid === false) {
      const expired = ssl.certError?.includes('DATE_INVALID') ?? false;
      addSecurity(
        expired ? 'CERT_EXPIRED' : 'CERT_INVALID',
        expired
          ? "The site's certificate has expired or is not yet valid"
          : `The browser reported a certificate error${ssl.certError ? ` (${ssl.certError})` : ''}`
      );
      certSignal = true;
    }
    // Layer 3 (§33.1) — only when certificate detail was actually available.
    if (ssl.certificateDetail === 'AVAILABLE' && ssl.daysLeft !== null) {
      if (ssl.daysLeft < 0 && !certSignal) {
        addSecurity('CERT_EXPIRED', `Certificate expired ${plural(-ssl.daysLeft, 'day')} ago`);
      } else if (ssl.daysLeft >= 0 && ssl.daysLeft <= THRESHOLDS.CERT_EXPIRY_WARNING_DAYS) {
        addSecurity('CERT_EXPIRING_SOON', `Certificate expires in ${plural(ssl.daysLeft, 'day')}`);
      }
    }
  }

  if (input.whois?.status === 'OK' && input.whois.data.domainAgeDays !== null) {
    const age = input.whois.data.domainAgeDays;
    if (age < THRESHOLDS.DOMAIN_VERY_YOUNG_DAYS) addSecurity('DOMAIN_VERY_YOUNG', `Domain registered ${plural(age, 'day')} ago`);
    else if (age < THRESHOLDS.DOMAIN_YOUNG_DAYS) addSecurity('DOMAIN_YOUNG', `Domain registered ${plural(age, 'day')} ago`);
  }

  const js = checks.jsVulns;
  if (js?.status === 'OK') {
    const libs = (sev: string) =>
      js.libraries.filter((l) => l.severity === sev).map((l) => `${l.name} ${l.version}`).slice(0, 3).join(', ');
    // Once, at the highest severity found — not once per library.
    if (js.highestSeverity === 'critical') addSecurity('JS_VULN_CRITICAL', `Critical vulnerability in ${libs('critical')}`);
    else if (js.highestSeverity === 'high') addSecurity('JS_VULN_HIGH', `High-severity vulnerability in ${libs('high')}`);
    else if (js.highestSeverity === 'medium') addSecurity('JS_VULN_MEDIUM', `Known vulnerability in ${libs('medium')}`);
  }

  const mixed = checks.mixedContent;
  if (mixed?.status === 'OK') {
    if (mixed.activeCount > 0) addSecurity('MIXED_CONTENT_ACTIVE', `${plural(mixed.activeCount, 'script or frame')} loaded over HTTP on an HTTPS page`);
    if (mixed.passiveCount > 0) addSecurity('MIXED_CONTENT_PASSIVE', `${plural(mixed.passiveCount, 'image or media file')} loaded over HTTP`);
  }

  const headers = checks.headers;
  if (headers?.status === 'OK') {
    const valid = new Set(headers.present);
    if (!valid.has('content-security-policy')) addSecurity('MISSING_CSP', 'No valid Content-Security-Policy header');
    if (input.protocol === 'https:' && !valid.has('strict-transport-security')) {
      addSecurity('MISSING_HSTS', 'HTTPS page without Strict-Transport-Security');
    }
    const others = (['x-frame-options', 'x-content-type-options', 'referrer-policy'] as const).filter((h) => !valid.has(h));
    if (others.length > 0) {
      addSecurity(
        'MISSING_OTHER_HEADERS',
        `Missing ${others.join(', ')}`,
        Math.min(others.length * SECURITY_SIGNALS.MISSING_OTHER_HEADERS.points, THRESHOLDS.MISSING_OTHER_HEADERS_MAX)
      );
    }
  }

  const lookalike = input.lookalike;
  if (lookalike?.status === 'OK' && lookalike.match && lookalike.match.similarity >= THRESHOLDS.LOOKALIKE_MIN_SIMILARITY) {
    addSecurity(
      'LOOKALIKE_DOMAIN',
      `Resembles ${lookalike.match.brand} (${lookalike.match.brandDomain}) — similarity ${lookalike.match.similarity.toFixed(2)}`
    );
  }

  if (input.redirects?.suspicious) {
    addSecurity('SUSPICIOUS_REDIRECT_CHAIN', `Redirect chain: ${input.redirects.signals.join(', ').toLowerCase().replace(/_/g, ' ')}`);
  }

  const community = input.community;
  if (
    community?.status === 'OK' &&
    community.confidence >= THRESHOLDS.COMMUNITY_MIN_CONFIDENCE &&
    community.uniqueReporters >= THRESHOLDS.COMMUNITY_MIN_REPORTERS
  ) {
    addSecurity('COMMUNITY_THREAT_REPORTS', `Reported by ${community.uniqueReporters} GuardTab users (confidence ${community.confidence.toFixed(2)})`);
  }

  // ---- §19.3 privacy — scored only when tracker detection ran ---------------
  const trackers = checks.trackers;
  const privacyAvailable = trackers?.status === 'OK';
  if (privacyAvailable) {
    if (trackers.trackerCount > 0) {
      addPrivacy(
        'TRACKERS',
        `${plural(trackers.trackerCount, 'tracking service')} detected`,
        Math.min(trackers.trackerCount * PRIVACY_SIGNALS.TRACKERS.points, THRESHOLDS.TRACKER_POINTS_CAP)
      );
    }
    if ((trackers.categories.Advertising ?? 0) > 0) addPrivacy('ADVERTISING_TRACKERS', 'Advertising trackers present');
    if ((trackers.categories.Cryptomining ?? 0) > 0) addPrivacy('CRYPTOMINING', 'A known cryptomining script was loaded');
    if (
      trackers.totalRequests >= THRESHOLDS.THIRD_PARTY_RATIO_MIN_REQUESTS &&
      trackers.thirdPartyRequests / trackers.totalRequests > THRESHOLDS.THIRD_PARTY_RATIO
    ) {
      const pct = Math.round((trackers.thirdPartyRequests / trackers.totalRequests) * 100);
      addPrivacy('THIRD_PARTY_RATIO_HIGH', `${pct}% of requests go to other companies' servers`);
    }
    const replay = trackers.trackers.find((t) => isSessionReplayDomain(t.domain));
    if (replay) addPrivacy('SESSION_RECORDING', `Session recording by ${replay.name}`);

    if (checks.fingerprinting?.status === 'OK' && checks.fingerprinting.detected) {
      addPrivacy('FINGERPRINTING', `Browser fingerprinting via ${checks.fingerprinting.techniques.join(', ')}`);
    }
    if (headers?.status === 'OK' && !headers.present.includes('referrer-policy')) {
      addPrivacy('NO_REFERRER_POLICY', 'No Referrer-Policy — the page address may be shared with third parties');
    }
  }

  // ---- scores, blend, floor rule (§19.4) -------------------------------------
  const sum = (category: 'security' | 'privacy') =>
    evidence.filter((e) => e.category === category).reduce((total, e) => total + e.points, 0);
  const securityScore = 100 - Math.min(100, sum('security'));
  const privacyScore = privacyAvailable ? 100 - Math.min(100, sum('privacy')) : null;

  const blended = privacyScore === null ? securityScore : Math.round(BLEND.security * securityScore + BLEND.privacy * privacyScore);
  // "floored at the security band: a site with a critical security signal can
  // never present as Safe because of a good privacy score".
  const overall = Math.min(blended, bandUpperBound(bandOf(securityScore)));

  evidence.sort((a, b) => b.points - a.points || a.signal.localeCompare(b.signal));

  return {
    riskEngineVersion: RISK_ENGINE_VERSION,
    securityScore,
    privacyScore,
    overall,
    band: bandOf(overall),
    evidence,
    skipped,
    checks: statuses,
    scanStatus: statusValues.includes('UNAVAILABLE') ? 'PARTIAL' : 'COMPLETED',
  };
}
