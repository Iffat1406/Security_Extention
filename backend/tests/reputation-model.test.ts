import { describe, expect, it } from 'vitest';
import { computeReputation, decay, type IndicatorForScoring, type ReputationInput } from '../src/services/reputation-model';

const now = new Date('2026-09-24T00:00:00Z');
const daysAgo = (n: number) => new Date(now.getTime() - n * 86_400_000);

const indicator = (overrides: Partial<IndicatorForScoring>): IndicatorForScoring => ({
  type: 'PHISHING',
  source: 'SAFE_BROWSING',
  lastDetectedAt: now,
  suppressed: false,
  ...overrides,
});

const input = (overrides: Partial<ReputationInput>): ReputationInput => ({
  indicators: [],
  weightedReporters: 0,
  confirmedFalsePositives: 0,
  confirmedTruePositives: 0,
  isAllowlisted: false,
  scanCount: 10,
  now,
  ...overrides,
});

describe('decay — "full weight for 7 days, linear decay to zero over 90 days"', () => {
  it('is 1 up to 7 days, 0 from 90 days, linear between', () => {
    expect(decay(daysAgo(0), now)).toBe(1);
    expect(decay(daysAgo(7), now)).toBe(1);
    expect(decay(daysAgo(48.5), now)).toBeCloseTo(0.5, 5);
    expect(decay(daysAgo(90), now)).toBe(0);
    expect(decay(daysAgo(365), now)).toBe(0);
  });
});

describe('computeReputation — §22.4', () => {
  it('a never-scanned domain with no indicators is UNKNOWN; a scanned one is CLEAN', () => {
    expect(computeReputation(input({ scanCount: 0 })).reputation).toBe('UNKNOWN');
    expect(computeReputation(input({})).reputation).toBe('CLEAN');
  });

  it('Safe Browsing and VirusTotal agreeing -> MALICIOUS with high confidence', () => {
    const result = computeReputation(
      input({ indicators: [indicator({}), indicator({ type: 'MALWARE', source: 'VIRUSTOTAL' })] })
    );
    expect(result.reputation).toBe('MALICIOUS');
    expect(result.components.external).toBe(1);
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('a fresh Safe Browsing flag on its own is enough for MALICIOUS', () => {
    expect(computeReputation(input({ indicators: [indicator({})] })).reputation).toBe('MALICIOUS');
  });

  it('...but the same flag decayed over two months is not', () => {
    expect(computeReputation(input({ indicators: [indicator({ lastDetectedAt: daysAgo(60) })] })).reputation).not.toBe('MALICIOUS');
  });

  it('POISONING: a flood of community reports alone can never reach MALICIOUS', () => {
    const result = computeReputation(
      input({ indicators: [indicator({ type: 'SCAM', source: 'COMMUNITY' })], weightedReporters: 10_000 })
    );
    expect(result.reputation).toBe('SUSPICIOUS');
  });

  it('reporter weight is log-scaled: the 50th reporter adds almost nothing', () => {
    const community = [indicator({ type: 'SCAM', source: 'COMMUNITY' })];
    const at20 = computeReputation(input({ indicators: community, weightedReporters: 20 })).components.reporters;
    const at50 = computeReputation(input({ indicators: community, weightedReporters: 50 })).components.reporters;
    const at5 = computeReputation(input({ indicators: community, weightedReporters: 5 })).components.reporters;
    expect(at20).toBe(1);
    expect(at50).toBe(1);
    expect(at5).toBeLessThan(at20);
  });

  it('allowlisted domains ignore community signals entirely', () => {
    const result = computeReputation(
      input({ isAllowlisted: true, indicators: [indicator({ type: 'SCAM', source: 'COMMUNITY' })], weightedReporters: 500 })
    );
    expect(result.reputation).toBe('CLEAN');
    expect(result.components.reporters).toBe(0);
  });

  it('suppressed indicators never score', () => {
    const result = computeReputation(input({ indicators: [indicator({ suppressed: true })] }));
    expect(result.reputation).toBe('CLEAN');
    expect(result.confidence).toBe(0);
  });

  it('confirmed false positives reduce confidence', () => {
    const base = input({ indicators: [indicator({})] });
    const clean = computeReputation(base).confidence;
    const withFp = computeReputation({ ...base, confirmedFalsePositives: 3, confirmedTruePositives: 1 }).confidence;
    expect(withFp).toBeLessThan(clean);
  });

  it('indicators fully decayed (90+ days) no longer count', () => {
    const result = computeReputation(input({ indicators: [indicator({ lastDetectedAt: daysAgo(120) })] }));
    expect(result.reputation).toBe('CLEAN');
  });

  it('an ADMIN indicator forces MALICIOUS', () => {
    const result = computeReputation(input({ indicators: [indicator({ source: 'ADMIN', type: 'PHISHING' })] }));
    expect(result.reputation).toBe('MALICIOUS');
    expect(result.confidence).toBeGreaterThanOrEqual(0.95);
  });

  it('several scanner-only observations make a domain SUSPICIOUS but never MALICIOUS', () => {
    const result = computeReputation(
      input({
        indicators: [
          indicator({ type: 'EXPIRED_CERT', source: 'SCANNER' }),
          indicator({ type: 'MIXED_CONTENT', source: 'SCANNER' }),
          indicator({ type: 'LOOKALIKE', source: 'SCANNER' }),
        ],
      })
    );
    expect(result.reputation).toBe('SUSPICIOUS');
  });

  it('confidence stays within 0.00–1.00 and has two decimals', () => {
    const result = computeReputation(
      input({
        indicators: [indicator({}), indicator({ type: 'MALWARE', source: 'VIRUSTOTAL' }), indicator({ type: 'EXPIRED_CERT', source: 'SCANNER' })],
        weightedReporters: 100,
      })
    );
    expect(result.confidence).toBeLessThanOrEqual(1);
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(Number.isInteger(result.confidence * 100)).toBe(true);
  });
});
