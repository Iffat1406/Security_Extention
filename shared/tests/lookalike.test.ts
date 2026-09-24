import { describe, expect, it } from 'vitest';
import {
  LOOKALIKE_SCORING_THRESHOLD,
  damerauLevenshtein,
  detectLookalike,
  skeleton,
} from '../src/detection/lookalike';
import { decodePunycodeLabel, hostToUnicode } from '../src/detection/punycode';

// Registrable domains are passed explicitly (the backend supplies psl.get()).
const check = (host: string, reg = host) => detectLookalike(host, reg);

describe('punycode decoding', () => {
  it('decodes the §31.2 example xn--pypal-4ve (Cyrillic а)', () => {
    expect(decodePunycodeLabel('pypal-4ve')).toBe('pаypal');
    expect(hostToUnicode('xn--pypal-4ve.com')).toBe('pаypal.com');
  });

  it('decodes a German IDN', () => {
    expect(hostToUnicode('xn--mnchen-3ya.de')).toBe('münchen.de');
  });

  it('returns null for malformed input instead of throwing', () => {
    expect(decodePunycodeLabel('!!!')).toBeNull();
  });
});

describe('skeleton / edit distance', () => {
  it('collapses §31.2 homoglyphs: rn→m, 0→o, I/l', () => {
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
    expect(skeleton('g00gle')).toBe(skeleton('google'));
    expect(skeleton('paypai')).toBe(skeleton('paypal'));
  });

  it('computes Damerau-Levenshtein with transpositions', () => {
    expect(damerauLevenshtein('paypal', 'paypall')).toBe(1);
    expect(damerauLevenshtein('google', 'gogole')).toBe(1); // transposition
    expect(damerauLevenshtein('amazon', 'amazon')).toBe(0);
  });
});

describe('detectLookalike — §31.2 techniques that must fire', () => {
  it('mixed script: xn--pypal-4ve.com', () => {
    const m = check('xn--pypal-4ve.com');
    expect(m?.brand).toBe('PayPal');
    expect(m?.technique).toBe('MIXED_SCRIPT');
    expect(m!.similarity).toBeGreaterThanOrEqual(LOOKALIKE_SCORING_THRESHOLD);
  });

  it('homoglyph: rnicrosoft.com, g00gle.com, paypa1.com', () => {
    expect(check('rnicrosoft.com')?.brand).toBe('Microsoft');
    expect(check('g00gle.com')?.brand).toBe('Google');
    expect(check('paypa1.com')?.technique).toBe('HOMOGLYPH');
  });

  it('edit distance ≤ 2: paypall.com, gooogle.com score', () => {
    expect(check('paypall.com')!.similarity).toBeGreaterThanOrEqual(LOOKALIKE_SCORING_THRESHOLD);
    expect(check('gooogle.com')?.brand).toBe('Google');
  });

  it('brand token + keyword: paypal-login.com, apple-security-verify.com', () => {
    expect(check('paypal-login.com')?.technique).toBe('BRAND_KEYWORD');
    expect(check('apple-security-verify.com')?.brand).toBe('Apple');
  });

  it('the spec example paypaI-security.com (capital I, lowercased by the URL parser)', () => {
    const m = check('paypai-security.com');
    expect(m?.brand).toBe('PayPal');
    expect(m!.similarity).toBeGreaterThanOrEqual(0.9);
  });

  it('brand domain inside another domain: paypal.com.secure-verify.io', () => {
    const m = check('paypal.com.secure-verify.io', 'secure-verify.io');
    expect(m?.technique).toBe('BRAND_DOMAIN_IN_SUBDOMAIN');
    expect(m!.similarity).toBeGreaterThanOrEqual(LOOKALIKE_SCORING_THRESHOLD);
  });

  it('short brand tokens only match as whole hyphen parts: dhl-parcel-redelivery.com', () => {
    expect(check('dhl-parcel-redelivery.com')?.brand).toBe('DHL');
  });

  it('a suspicious TLD bumps an existing match', () => {
    const plain = check('paypal-login.com')!;
    const onXyz = check('paypal-login.xyz')!;
    expect(onXyz.similarity).toBeGreaterThan(plain.similarity);
  });

  it('wording says "resembles" and never calls the site fake', () => {
    const m = check('paypal-login.com')!;
    expect(m.explanation).toMatch(/resembles/);
    expect(m.explanation).not.toMatch(/fake/i);
  });
});

describe('detectLookalike — must NOT fire (false-positive guards)', () => {
  it.each([
    ['paypal.com'],
    ['www.paypal.com'],
    ['accounts.google.com'],
    ['login.microsoftonline.com'],
    ['amazon.co.uk'],
    ['github.io'],
    ['icloud.com'],
  ])('a brand on its own domain or alias: %s', (host) => {
    const reg = host.split('.').slice(-2).join('.');
    expect(detectLookalike(host, host === 'amazon.co.uk' ? 'amazon.co.uk' : reg)).toBeNull();
  });

  it('generic-word brands are not fuzzy-matched: ample.com, targets.com', () => {
    expect(check('ample.com')).toBeNull();
    expect(check('targets.com')).toBeNull();
  });

  it('short tokens do not match inside ordinary words: groups.com, startups.io', () => {
    expect(check('groups.com')).toBeNull();
    expect(check('startups.io')).toBeNull();
  });

  it('a 3-letter token does not homoglyph-match: lrs.com is not IRS', () => {
    expect(check('lrs.com')).toBeNull();
  });

  it('IP literals report nothing (§30.3: lookalike NOT_SUPPORTED on IPs)', () => {
    expect(check('93.184.216.34')).toBeNull();
  });

  it('an unrelated ordinary domain', () => {
    expect(check('example.com')).toBeNull();
    expect(check('bbc.co.uk', 'bbc.co.uk')).toBeNull();
  });

  it('a 5-letter one-edit neighbour is informational only, never scoring', () => {
    const m = check('venmoo.com');
    // venmo is 5 chars: distance-1 matches exist but stay below the scoring threshold.
    if (m) expect(m.similarity).toBeLessThan(LOOKALIKE_SCORING_THRESHOLD);
  });
});
