import { describe, expect, it } from 'vitest';
import { AppError } from '../src/lib/errors';
import { normalizeUrl } from '../src/services/url-normalizer.service';

// Test cases lifted directly from §20.2 "Normalisation rules".
describe('normalizeUrl — §20.2 examples', () => {
  it('lowercases scheme and host but not the path', () => {
    const result = normalizeUrl('HTTP://Example.COM/Path');
    expect(result.normalizedUrl).toBe('http://example.com/Path');
  });

  it('keeps www on the host and extracts the registrable domain', () => {
    const result = normalizeUrl('https://www.example.com');
    expect(result.host).toBe('www.example.com');
    expect(result.registrableDomain).toBe('example.com');
  });

  it('strips the default HTTPS port', () => {
    const result = normalizeUrl('https://example.com:443/a');
    expect(result.normalizedUrl).toBe('https://example.com/a');
  });

  it('keeps a non-default port', () => {
    const result = normalizeUrl('https://example.com:8443/a');
    expect(result.normalizedUrl).toBe('https://example.com:8443/a');
  });

  it('drops the fragment', () => {
    const result = normalizeUrl('https://example.com/a#login');
    expect(result.normalizedUrl).toBe('https://example.com/a');
  });

  it('drops the query string', () => {
    const result = normalizeUrl('https://example.com?token=abc');
    expect(result.normalizedUrl).toBe('https://example.com/');
    expect(result.path).toBeNull();
  });

  it('punycode-encodes an IDN host', () => {
    const result = normalizeUrl('https://münchen.de');
    expect(result.host).toBe('xn--mnchen-3ya.de');
  });

  it('flags a mixed-script (homoglyph) host without rejecting it', () => {
    // "exаmple.com" — the "а" is Cyrillic U+0430, not Latin "a".
    const result = normalizeUrl('https://exаmple.com');
    expect(result.mixedScriptHost).toBe(true);
  });

  it('does not flag a genuinely single-script IDN host', () => {
    const result = normalizeUrl('https://münchen.de');
    expect(result.mixedScriptHost).toBe(false);
  });

  it('redacts a high-entropy path segment', () => {
    const result = normalizeUrl('https://example.com/u/9f8c2a1b3d4e5f6071829304a5b6c72b/edit');
    expect(result.path).toBe('/u/:redacted/edit');
  });
});

describe('normalizeUrl — additional rules', () => {
  it('rejects an unparseable URL', () => {
    expect(() => normalizeUrl('not a url')).toThrow(AppError);
  });

  it('rejects a disallowed scheme', () => {
    try {
      normalizeUrl('ftp://example.com/file');
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).code).toBe('UNSUPPORTED_SCHEME');
    }
  });

  it('rejects a URL over 2048 characters', () => {
    const longUrl = `https://example.com/${'a'.repeat(2048)}`;
    try {
      normalizeUrl(longUrl);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).code).toBe('URL_TOO_LONG');
    }
  });

  it('rejects credentials embedded in the URL', () => {
    try {
      normalizeUrl('https://user:pass@example.com');
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).code).toBe('INVALID_URL');
    }
  });

  it('collapses repeated slashes in the path', () => {
    const result = normalizeUrl('https://example.com//a///b');
    expect(result.path).toBe('/a/b');
  });

  it('truncates a path longer than 200 characters', () => {
    // "z" repeated is neither hex, numeric, nor a mixed alnum token, so it
    // exercises truncation without also tripping high-entropy redaction.
    const result = normalizeUrl(`https://example.com/${'z'.repeat(300)}`);
    expect(result.path).not.toBeNull();
    expect(result.path!.length).toBe(200);
  });
});
