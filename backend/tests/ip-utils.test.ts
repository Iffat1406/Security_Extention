import { describe, expect, it } from 'vitest';
import {
  canonicalizeIpLiteral,
  extractIPv4MappedAddress,
  isBlockedIp,
  isIPv4InCidr,
  isIPv6InCidr,
  ipv6ToBigInt,
  parseObfuscatedIPv4,
} from '../src/lib/ip-utils';

describe('isIPv4InCidr', () => {
  it('matches an address inside the range', () => {
    expect(isIPv4InCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(isIPv4InCidr('192.168.1.1', '192.168.0.0/16')).toBe(true);
  });

  it('rejects an address outside the range', () => {
    expect(isIPv4InCidr('8.8.8.8', '10.0.0.0/8')).toBe(false);
  });
});

describe('ipv6ToBigInt', () => {
  it('parses "::1"', () => {
    expect(ipv6ToBigInt('::1')).toBe(1n);
  });

  it('parses an IPv4-mapped address', () => {
    const value = ipv6ToBigInt('::ffff:127.0.0.1');
    expect(value).not.toBeNull();
  });
});

describe('isIPv6InCidr', () => {
  it('matches loopback against ::1/128', () => {
    expect(isIPv6InCidr('::1', '::1/128')).toBe(true);
  });

  it('matches a link-local address against fe80::/10', () => {
    expect(isIPv6InCidr('fe80::1', 'fe80::/10')).toBe(true);
  });
});

describe('extractIPv4MappedAddress', () => {
  it('extracts the embedded IPv4 address', () => {
    expect(extractIPv4MappedAddress('::ffff:127.0.0.1')).toBe('127.0.0.1');
  });

  it('returns null for a non-mapped address', () => {
    expect(extractIPv4MappedAddress('2001:db8::1')).toBeNull();
  });
});

describe('parseObfuscatedIPv4 (§20.4 "Encoded bypasses")', () => {
  it('parses a pure decimal 32-bit value', () => {
    expect(parseObfuscatedIPv4('2130706433')).toBe('127.0.0.1');
  });

  it('parses a per-octet octal form', () => {
    expect(parseObfuscatedIPv4('0177.0.0.1')).toBe('127.0.0.1');
  });

  it('parses a hex form', () => {
    expect(parseObfuscatedIPv4('0x7f000001')).toBe('127.0.0.1');
  });

  it('parses a short "a.b" form', () => {
    expect(parseObfuscatedIPv4('127.1')).toBe('127.0.0.1');
  });

  it('returns null for a real hostname', () => {
    expect(parseObfuscatedIPv4('example.com')).toBeNull();
  });

  it('returns null for an out-of-range octet', () => {
    expect(parseObfuscatedIPv4('999.0.0.1')).toBeNull();
  });
});

describe('canonicalizeIpLiteral', () => {
  it('recognises a plain dotted-quad', () => {
    expect(canonicalizeIpLiteral('127.0.0.1')).toEqual({ ip: '127.0.0.1', family: 4 });
  });

  it('recognises a bracketed IPv6 literal', () => {
    expect(canonicalizeIpLiteral('[::1]')).toEqual({ ip: '::1', family: 6 });
  });

  it('recognises an obfuscated decimal IPv4', () => {
    expect(canonicalizeIpLiteral('2130706433')).toEqual({ ip: '127.0.0.1', family: 4 });
  });

  it('returns null for a real hostname', () => {
    expect(canonicalizeIpLiteral('example.com')).toBeNull();
  });
});

describe('isBlockedIp (§20.4 deny-lists)', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.0.0.1', 'RFC1918'],
    ['172.16.0.1', 'RFC1918'],
    ['192.168.1.1', 'RFC1918'],
    ['169.254.1.1', 'link-local'],
    ['169.254.169.254', 'cloud metadata'],
    ['100.100.100.200', 'cloud metadata (alibaba)'],
    ['100.64.0.1', 'CGNAT'],
    ['192.0.2.1', 'TEST-NET'],
    ['0.0.0.0', 'unspecified'],
  ])('blocks %s (%s)', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each([['8.8.8.8'], ['1.1.1.1'], ['93.184.216.34']])('allows public address %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });

  it('blocks IPv6 loopback and link-local', () => {
    expect(isBlockedIp('::1')).toBe(true);
    expect(isBlockedIp('fe80::1')).toBe(true);
    expect(isBlockedIp('fc00::1')).toBe(true);
  });

  it('blocks an IPv4-mapped IPv6 loopback address', () => {
    expect(isBlockedIp('::ffff:127.0.0.1')).toBe(true);
  });

  it('allows a public IPv6 address', () => {
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false);
  });
});
