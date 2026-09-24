import { describe, expect, it } from 'vitest';
import type { LocalChecks } from '@guardtab/shared';
import { bandOf, bandUpperBound, computeRisk, type RiskEngineInput } from '../src/risk-engine/engine';
import { PRIVACY_SIGNALS, RISK_ENGINE_VERSION, SECURITY_SIGNALS } from '../src/risk-engine/weights';

// ---- fixtures ---------------------------------------------------------------

const cleanHeaders: NonNullable<LocalChecks['headers']> = {
  status: 'OK',
  grade: 'A',
  score: 100,
  present: ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'],
  missing: [],
  invalid: [],
  details: {},
};

const noTrackers: NonNullable<LocalChecks['trackers']> = {
  status: 'OK',
  trackerCount: 0,
  trackers: [],
  intensity: 'none',
  categories: {},
  thirdPartyRequests: 0,
  totalRequests: 10,
};

const validSsl: NonNullable<LocalChecks['ssl']> = {
  status: 'OK',
  protocol: 'https:',
  isHTTP: false,
  isValid: true,
  certError: null,
  certificateDetail: 'NOT_SUPPORTED',
  issuer: null,
  expiresAt: null,
  daysLeft: null,
};

/** A spotless HTTPS site: every check OK, no signals -> 100 / 100 / SAFE. */
function cleanInput(overrides: Partial<RiskEngineInput> = {}): RiskEngineInput {
  return {
    protocol: 'https:',
    checks: { ssl: validSsl, headers: cleanHeaders, trackers: noTrackers },
    safeBrowsing: { status: 'OK', data: { isMalicious: false, threatTypes: [] }, cached: false },
    virusTotal: { status: 'OK', data: { malicious: 0, suspicious: 0, harmless: 70, undetected: 10 }, cached: false },
    whois: { status: 'OK', data: { domainAgeDays: 4000, registeredAt: null, registrar: 'Example Registrar' }, cached: false },
    lookalike: { status: 'OK', match: null },
    redirects: null,
    community: { status: 'OK', confidence: 0, uniqueReporters: 0 },
    ...overrides,
  };
}

const withChecks = (checks: Partial<LocalChecks>, rest: Partial<RiskEngineInput> = {}) =>
  cleanInput({ ...rest, checks: { ...cleanInput().checks, ...checks } });

const pointsFor = (input: RiskEngineInput, signal: string) =>
  computeRisk(input).evidence.find((e) => e.signal === signal)?.points;

// ---- tests ------------------------------------------------------------------

describe('baseline', () => {
  it('a clean site scores 100/100/100 SAFE with no evidence', () => {
    const result = computeRisk(cleanInput());
    expect(result).toMatchObject({ securityScore: 100, privacyScore: 100, overall: 100, band: 'SAFE', evidence: [], scanStatus: 'COMPLETED' });
    expect(result.riskEngineVersion).toBe(RISK_ENGINE_VERSION);
  });

  it('is deterministic: same input, same output', () => {
    const input = withChecks({}, { protocol: 'http:' });
    expect(computeRisk(input)).toEqual(computeRisk(structuredClone(input)));
  });
});

describe('§19.2 security weights — one test per signal', () => {
  it('Safe Browsing malicious +60', () => {
    expect(pointsFor(cleanInput({ safeBrowsing: { status: 'OK', data: { isMalicious: true, threatTypes: ['SOCIAL_ENGINEERING'] }, cached: false } }), 'SAFE_BROWSING_MALICIOUS')).toBe(60);
  });

  it('VirusTotal ≥3 engines +20, 1–2 engines +10, 0 engines nothing', () => {
    const vt = (malicious: number): RiskEngineInput => cleanInput({ virusTotal: { status: 'OK', data: { malicious, suspicious: 0, harmless: 60, undetected: 0 }, cached: false } });
    expect(pointsFor(vt(3), 'VIRUSTOTAL_MALICIOUS')).toBe(20);
    expect(pointsFor(vt(2), 'VIRUSTOTAL_SUSPICIOUS')).toBe(10);
    expect(pointsFor(vt(1), 'VIRUSTOTAL_SUSPICIOUS')).toBe(10);
    expect(computeRisk(vt(0)).evidence).toEqual([]);
  });

  it('served over HTTP +15 (HSTS is not also charged on an HTTP page)', () => {
    const result = computeRisk(withChecks({ ssl: { ...validSsl, protocol: 'http:', isHTTP: true } }, { protocol: 'http:' }));
    expect(result.evidence.find((e) => e.signal === 'SERVED_OVER_HTTP')?.points).toBe(15);
    expect(result.evidence.find((e) => e.signal === 'MISSING_HSTS')).toBeUndefined();
  });

  it('certificate error +20; a date error is reported as CERT_EXPIRED', () => {
    expect(pointsFor(withChecks({ ssl: { ...validSsl, isValid: false, certError: 'net::ERR_CERT_AUTHORITY_INVALID' } }), 'CERT_INVALID')).toBe(20);
    expect(pointsFor(withChecks({ ssl: { ...validSsl, isValid: false, certError: 'net::ERR_CERT_DATE_INVALID' } }), 'CERT_EXPIRED')).toBe(20);
  });

  it('certificate expiring within 14 days +5 — only when certificate detail was available (§33.1)', () => {
    const detail = { ...validSsl, certificateDetail: 'AVAILABLE' as const, daysLeft: 14 };
    expect(pointsFor(withChecks({ ssl: detail }), 'CERT_EXPIRING_SOON')).toBe(5);
    expect(pointsFor(withChecks({ ssl: { ...detail, daysLeft: 15 } }), 'CERT_EXPIRING_SOON')).toBeUndefined();
    // Layer-3 detail NOT_SUPPORTED: the signal simply doesn't fire.
    expect(pointsFor(withChecks({ ssl: { ...validSsl, daysLeft: 3 } }), 'CERT_EXPIRING_SOON')).toBeUndefined();
  });

  it('domain younger than 30 days +10, 30–89 days +5, 90+ nothing', () => {
    const age = (days: number) => cleanInput({ whois: { status: 'OK', data: { domainAgeDays: days, registeredAt: null, registrar: null }, cached: false } });
    expect(pointsFor(age(29), 'DOMAIN_VERY_YOUNG')).toBe(10);
    expect(pointsFor(age(30), 'DOMAIN_YOUNG')).toBe(5);
    expect(pointsFor(age(89), 'DOMAIN_YOUNG')).toBe(5);
    expect(computeRisk(age(90)).evidence).toEqual([]);
  });

  it('JS vulnerability: critical +20, high +10, medium +5 — once, at the highest severity', () => {
    const js = (highestSeverity: 'critical' | 'high' | 'medium' | 'low') =>
      withChecks({
        jsVulns: {
          status: 'OK',
          vulnerableCount: 2,
          highestSeverity,
          libraries: [
            { name: 'jquery', version: '1.8.0', severity: highestSeverity, vulnerabilities: [] },
            { name: 'lodash', version: '4.17.0', severity: 'medium', vulnerabilities: [] },
          ],
        },
      });
    expect(pointsFor(js('critical'), 'JS_VULN_CRITICAL')).toBe(20);
    expect(pointsFor(js('high'), 'JS_VULN_HIGH')).toBe(10);
    expect(pointsFor(js('medium'), 'JS_VULN_MEDIUM')).toBe(5);
    expect(computeRisk(js('critical')).evidence.filter((e) => e.signal.startsWith('JS_VULN'))).toHaveLength(1);
    expect(computeRisk(js('low')).evidence.filter((e) => e.signal.startsWith('JS_VULN'))).toHaveLength(0);
  });

  it('mixed content: active +10, passive +3', () => {
    const mixed = withChecks({ mixedContent: { status: 'OK', mixedCount: 3, activeCount: 1, passiveCount: 2, resources: [] } });
    expect(pointsFor(mixed, 'MIXED_CONTENT_ACTIVE')).toBe(10);
    expect(pointsFor(mixed, 'MIXED_CONTENT_PASSIVE')).toBe(3);
  });

  it('missing CSP +5, HSTS +3, other headers +1 each capped at +3', () => {
    const none = withChecks({ headers: { ...cleanHeaders, present: [], missing: [...cleanHeaders.present] } });
    expect(pointsFor(none, 'MISSING_CSP')).toBe(5);
    expect(pointsFor(none, 'MISSING_HSTS')).toBe(3);
    expect(pointsFor(none, 'MISSING_OTHER_HEADERS')).toBe(3);
    const oneMissing = withChecks({ headers: { ...cleanHeaders, present: cleanHeaders.present.filter((h) => h !== 'x-frame-options') } });
    expect(pointsFor(oneMissing, 'MISSING_OTHER_HEADERS')).toBe(1);
  });

  it('an invalid header counts as missing', () => {
    const invalidCsp = withChecks({
      headers: { ...cleanHeaders, present: cleanHeaders.present.filter((h) => h !== 'content-security-policy'), invalid: ['content-security-policy'] },
    });
    expect(pointsFor(invalidCsp, 'MISSING_CSP')).toBe(5);
  });

  it('lookalike +25 only at similarity ≥ 0.90', () => {
    const match = (similarity: number) =>
      cleanInput({ lookalike: { status: 'OK', match: { brand: 'PayPal', brandDomain: 'paypal.com', similarity, technique: 'HOMOGLYPH', explanation: '' } } });
    expect(pointsFor(match(0.9), 'LOOKALIKE_DOMAIN')).toBe(25);
    expect(pointsFor(match(0.89), 'LOOKALIKE_DOMAIN')).toBeUndefined();
  });

  it('suspicious redirect chain +10', () => {
    const input = cleanInput({ redirects: { hops: [], signals: ['SHORTENER_HOP', 'YOUNG_FINAL_DOMAIN'], suspicious: true, crossDomainHops: 1 } });
    expect(pointsFor(input, 'SUSPICIOUS_REDIRECT_CHAIN')).toBe(10);
  });

  it('community reports +10 only at confidence ≥ 0.8 from ≥ 5 unique users', () => {
    const community = (confidence: number, uniqueReporters: number) => cleanInput({ community: { status: 'OK', confidence, uniqueReporters } });
    expect(pointsFor(community(0.8, 5), 'COMMUNITY_THREAT_REPORTS')).toBe(10);
    expect(pointsFor(community(0.79, 50), 'COMMUNITY_THREAT_REPORTS')).toBeUndefined();
    expect(pointsFor(community(0.95, 4), 'COMMUNITY_THREAT_REPORTS')).toBeUndefined();
  });
});

describe('§19.3 privacy weights', () => {
  const trackers = (overrides: Partial<NonNullable<LocalChecks['trackers']>>) => withChecks({ trackers: { ...noTrackers, ...overrides } });

  it('+2 per tracker, capped at +30', () => {
    expect(pointsFor(trackers({ trackerCount: 8 }), 'TRACKERS')).toBe(16);
    expect(pointsFor(trackers({ trackerCount: 40 }), 'TRACKERS')).toBe(30);
  });

  it('advertising +10, cryptomining +30', () => {
    expect(pointsFor(trackers({ trackerCount: 1, categories: { Advertising: 1 } }), 'ADVERTISING_TRACKERS')).toBe(10);
    expect(pointsFor(trackers({ trackerCount: 1, categories: { Cryptomining: 1 } }), 'CRYPTOMINING')).toBe(30);
  });

  it('third-party ratio > 50% +10 (needs ≥ 5 requests to count)', () => {
    expect(pointsFor(trackers({ thirdPartyRequests: 6, totalRequests: 10 }), 'THIRD_PARTY_RATIO_HIGH')).toBe(10);
    expect(pointsFor(trackers({ thirdPartyRequests: 5, totalRequests: 10 }), 'THIRD_PARTY_RATIO_HIGH')).toBeUndefined();
    expect(pointsFor(trackers({ thirdPartyRequests: 3, totalRequests: 4 }), 'THIRD_PARTY_RATIO_HIGH')).toBeUndefined();
  });

  it('session recording vendor +10', () => {
    const input = trackers({ trackerCount: 1, trackers: [{ name: 'Hotjar', domain: 'static.hotjar.com', category: 'Analytics' }] });
    expect(pointsFor(input, 'SESSION_RECORDING')).toBe(PRIVACY_SIGNALS.SESSION_RECORDING.points);
  });

  it('fingerprinting +20, no Referrer-Policy +5', () => {
    const input = withChecks({
      fingerprinting: { status: 'OK', detected: true, techniques: ['canvas'] },
      headers: { ...cleanHeaders, present: cleanHeaders.present.filter((h) => h !== 'referrer-policy') },
    });
    expect(pointsFor(input, 'FINGERPRINTING')).toBe(20);
    expect(pointsFor(input, 'NO_REFERRER_POLICY')).toBe(5);
  });

  it('privacy is null when tracker detection did not run, and overall = security', () => {
    const result = computeRisk(withChecks({ trackers: undefined }, { protocol: 'http:' }));
    expect(result.privacyScore).toBeNull();
    expect(result.overall).toBe(result.securityScore);
    expect(result.evidence.every((e) => e.category === 'security')).toBe(true);
  });
});

describe('§19.4 bands, blend and floor rule', () => {
  it('band boundaries at 19/20, 39/40, 59/60, 79/80', () => {
    expect(bandOf(100)).toBe('SAFE');
    expect(bandOf(80)).toBe('SAFE');
    expect(bandOf(79)).toBe('LOW');
    expect(bandOf(60)).toBe('LOW');
    expect(bandOf(59)).toBe('MEDIUM');
    expect(bandOf(40)).toBe('MEDIUM');
    expect(bandOf(39)).toBe('HIGH');
    expect(bandOf(20)).toBe('HIGH');
    expect(bandOf(19)).toBe('CRITICAL');
    expect(bandOf(0)).toBe('CRITICAL');
  });

  it('band upper bounds', () => {
    expect(bandUpperBound('SAFE')).toBe(100);
    expect(bandUpperBound('LOW')).toBe(79);
    expect(bandUpperBound('CRITICAL')).toBe(19);
  });

  it('overall = round(0.7 × security + 0.3 × privacy)', () => {
    // security 100, privacy 100 − 16 = 84 -> round(70 + 25.2) = 95
    const result = computeRisk(withChecks({ trackers: { ...noTrackers, trackerCount: 8 } }));
    expect(result.privacyScore).toBe(84);
    expect(result.overall).toBe(95);
  });

  it('floor rule: a critical security score can never present better than CRITICAL', () => {
    // Safe Browsing (60) + cert (20) + HTTP (15) = 95 -> security 5 (CRITICAL);
    // privacy is a perfect 100, so the plain blend would be round(3.5 + 30) = 34 (HIGH).
    const result = computeRisk(
      withChecks(
        { ssl: { ...validSsl, protocol: 'http:', isHTTP: true, isValid: false, certError: 'net::ERR_CERT_AUTHORITY_INVALID' } },
        { protocol: 'http:', safeBrowsing: { status: 'OK', data: { isMalicious: true, threatTypes: ['MALWARE'] }, cached: false } }
      )
    );
    expect(result.securityScore).toBe(5);
    expect(result.privacyScore).toBe(100);
    expect(result.overall).toBe(19);
    expect(result.band).toBe('CRITICAL');
  });

  it('clamps the security score at 0, never negative', () => {
    const result = computeRisk(
      withChecks(
        {
          ssl: { ...validSsl, isValid: false, certError: 'net::ERR_CERT_DATE_INVALID' },
          jsVulns: { status: 'OK', vulnerableCount: 1, highestSeverity: 'critical', libraries: [{ name: 'x', version: '1', severity: 'critical', vulnerabilities: [] }] },
        },
        {
          protocol: 'http:',
          safeBrowsing: { status: 'OK', data: { isMalicious: true, threatTypes: ['MALWARE'] }, cached: false },
          lookalike: { status: 'OK', match: { brand: 'PayPal', brandDomain: 'paypal.com', similarity: 0.96, technique: 'MIXED_SCRIPT', explanation: '' } },
        }
      )
    );
    expect(result.securityScore).toBe(0);
    // Blend = round(0 + 0.3 × 100) = 30, floored to the top of CRITICAL.
    expect(result.overall).toBe(19);
    expect(result.band).toBe('CRITICAL');
  });

  it('clamps the privacy score at 0', () => {
    const result = computeRisk(
      withChecks({
        trackers: { ...noTrackers, trackerCount: 30, categories: { Advertising: 5, Cryptomining: 1 }, thirdPartyRequests: 90, totalRequests: 100 },
        fingerprinting: { status: 'OK', detected: true, techniques: ['canvas', 'webgl'] },
      })
    );
    expect(result.privacyScore).toBe(0);
  });
});

describe('§19.5 evidence and §24 status', () => {
  it('orders evidence by points, highest first', () => {
    const result = computeRisk(
      withChecks(
        { headers: { ...cleanHeaders, present: [] } },
        { protocol: 'http:', safeBrowsing: { status: 'OK', data: { isMalicious: true, threatTypes: ['MALWARE'] }, cached: false } }
      )
    );
    const points = result.evidence.map((e) => e.points);
    expect(points).toEqual([...points].sort((a, b) => b - a));
    expect(result.evidence[0]!.signal).toBe('SAFE_BROWSING_MALICIOUS');
  });

  it('an UNAVAILABLE dependency makes the scan PARTIAL — not FAILED — and is listed in skipped', () => {
    const result = computeRisk(cleanInput({ virusTotal: { status: 'UNAVAILABLE', reason: 'TIMEOUT' } }));
    expect(result.scanStatus).toBe('PARTIAL');
    expect(result.securityScore).toBe(100);
    expect(result.skipped).toContainEqual({ signal: 'VIRUSTOTAL', reason: 'EXTERNAL_SERVICE_UNAVAILABLE:TIMEOUT' });
    expect(result.checks.virusTotal).toBe('UNAVAILABLE');
  });

  it('a deliberately SKIPPED check does not make the scan PARTIAL', () => {
    const result = computeRisk(cleanInput({ virusTotal: { status: 'SKIPPED', reason: 'QUOTA_BUDGET' } }));
    expect(result.scanStatus).toBe('COMPLETED');
    expect(result.skipped).toContainEqual({ signal: 'VIRUSTOTAL', reason: 'QUOTA_BUDGET' });
  });

  it('every source failing -> FAILED with no score', () => {
    const result = computeRisk({
      protocol: 'https:',
      checks: {},
      safeBrowsing: { status: 'UNAVAILABLE', reason: 'X' },
      virusTotal: { status: 'UNAVAILABLE', reason: 'X' },
      whois: { status: 'UNAVAILABLE', reason: 'X' },
      lookalike: null,
      redirects: null,
      community: null,
    });
    expect(result).toMatchObject({ scanStatus: 'FAILED', securityScore: null, overall: null, band: null });
  });

  it('every documented security weight is covered by a test above', () => {
    // Guard against a signal being added to weights.ts without a test.
    expect(Object.keys(SECURITY_SIGNALS).sort()).toEqual(
      [
        'CERT_EXPIRED', 'CERT_EXPIRING_SOON', 'CERT_INVALID', 'COMMUNITY_THREAT_REPORTS', 'DOMAIN_VERY_YOUNG', 'DOMAIN_YOUNG',
        'JS_VULN_CRITICAL', 'JS_VULN_HIGH', 'JS_VULN_MEDIUM', 'LOOKALIKE_DOMAIN', 'MISSING_CSP', 'MISSING_HSTS',
        'MISSING_OTHER_HEADERS', 'MIXED_CONTENT_ACTIVE', 'MIXED_CONTENT_PASSIVE', 'SAFE_BROWSING_MALICIOUS', 'SERVED_OVER_HTTP',
        'SUSPICIOUS_REDIRECT_CHAIN', 'VIRUSTOTAL_MALICIOUS', 'VIRUSTOTAL_SUSPICIOUS',
      ].sort()
    );
    expect(Object.keys(PRIVACY_SIGNALS).sort()).toEqual(
      ['ADVERTISING_TRACKERS', 'CRYPTOMINING', 'FINGERPRINTING', 'NO_REFERRER_POLICY', 'SESSION_RECORDING', 'THIRD_PARTY_RATIO_HIGH', 'TRACKERS'].sort()
    );
  });
});
