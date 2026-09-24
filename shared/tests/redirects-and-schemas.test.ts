import { describe, expect, it } from 'vitest';
import { analyzeRedirectChain } from '../src/detection/redirects';
import { approximateSiteOf } from '../src/detection/domain';
import { localChecksSchema, scanSubmissionSchema } from '../src';
import { DEFAULT_USER_SETTINGS, settingsPatchSchema, withSettingsDefaults } from '../src/schemas/settings.schema';

const ctxBase = { siteOf: approximateSiteOf, finalProtocol: 'https:' as const };

describe('analyzeRedirectChain — §31.1', () => {
  it('flags the spec example: shortener -> tracker -> young landing domain', () => {
    const result = analyzeRedirectChain(
      [
        { host: 'example-newsletter.com', statusCode: 302, scheme: 'https:' },
        { host: 'bit.ly', statusCode: 301, scheme: 'https:' },
        { host: 'tracking-redirect.net', statusCode: 302, scheme: 'https:' },
      ],
      { ...ctxBase, finalHost: 'login-secure-update.co', finalDomainAgeDays: 6 }
    );
    expect(result.signals).toEqual(expect.arrayContaining(['CROSS_DOMAIN_CHAIN', 'SHORTENER_HOP', 'YOUNG_FINAL_DOMAIN']));
    expect(result.suspicious).toBe(true);
    expect(result.hops.map((h) => h.hopType)).toEqual(['cross-domain', 'shortener', 'cross-domain']);
  });

  it('a single same-site redirect (http -> https upgrade) is not suspicious', () => {
    const result = analyzeRedirectChain([{ host: 'example.com', statusCode: 301, scheme: 'http:' }], {
      ...ctxBase,
      finalHost: 'www.example.com',
    });
    expect(result.signals).toEqual([]);
    expect(result.suspicious).toBe(false);
  });

  it('detects an HTTPS -> HTTP downgrade', () => {
    const result = analyzeRedirectChain([{ host: 'a.com', statusCode: 302, scheme: 'https:' }], {
      ...ctxBase,
      finalHost: 'b.com',
      finalProtocol: 'http:',
    });
    expect(result.signals).toContain('SCHEME_DOWNGRADE');
  });

  it('one signal alone is not enough (two must coincide)', () => {
    const result = analyzeRedirectChain([{ host: 'bit.ly', statusCode: 301, scheme: 'https:' }], {
      ...ctxBase,
      finalHost: 'example.com',
    });
    expect(result.signals).toEqual(['SHORTENER_HOP']);
    expect(result.suspicious).toBe(false);
  });
});

describe('payload schemas — §18.4 the extension is not a trusted client', () => {
  it('rejects unknown keys in a check result', () => {
    const r = localChecksSchema.safeParse({
      passwordBreach: { status: 'OK', isBreached: true, breachCount: 3, passwordHash: 'abc' },
    });
    expect(r.success).toBe(false);
  });

  it('rejects oversized arrays', () => {
    const trackers = Array.from({ length: 201 }, (_, i) => ({ name: `t${i}`, domain: `t${i}.com`, category: 'Analytics' }));
    const r = localChecksSchema.safeParse({
      trackers: { status: 'OK', trackerCount: 201, trackers, intensity: 'heavy', categories: {}, thirdPartyRequests: 0, totalRequests: 0 },
    });
    expect(r.success).toBe(false);
  });

  it('accepts a minimal valid submission', () => {
    const r = scanSubmissionSchema.safeParse({ url: 'https://example.com', schemaVersion: 1, scannerVersion: '1.0.0', checks: {} });
    expect(r.success).toBe(true);
  });
});

describe('settings — §23.1/§23.4', () => {
  it('rejects unknown keys on PATCH', () => {
    expect(settingsPatchSchema.safeParse({ autoScan: false, telemetry: true }).success).toBe(false);
  });

  it('only allows the documented retention choices', () => {
    expect(settingsPatchSchema.safeParse({ scanRetentionDays: 60 }).success).toBe(false);
    expect(settingsPatchSchema.safeParse({ scanRetentionDays: null }).success).toBe(true);
  });

  it('fills defaults for keys added after a row was written', () => {
    expect(withSettingsDefaults({ autoScan: false })).toEqual({ ...DEFAULT_USER_SETTINGS, autoScan: false });
    expect(withSettingsDefaults('garbage')).toEqual(DEFAULT_USER_SETTINGS);
  });
});
