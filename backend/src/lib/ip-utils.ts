import net from 'node:net';

/**
 * IP literal parsing, canonicalisation and CIDR containment helpers used by
 * url-safety.service.ts (§20.4). Kept dependency-free and independently
 * testable — this is the part of the SSRF guard that is easiest to get
 * subtly wrong.
 */

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

export function ipv4ToInt(ip: string): number {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    throw new Error(`Not a dotted-quad IPv4 address: ${ip}`);
  }
  return (((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0);
}

export function intToIpv4(value: number): string {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.');
}

export function isIPv4InCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range!);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Detects the classic "inet_aton"-style IPv4 obfuscations that bypass naive
 * string-based deny-lists: pure decimal ("2130706433"), octal per-octet
 * ("0177.0.0.1"), hex ("0x7f000001" / "0x7f.0x0.0x0.0x1"), and short forms
 * ("127.1" -> 127.0.0.1). Returns the canonical dotted-quad form, or null if
 * the input is not one of these forms (i.e. it should be treated as a
 * regular hostname and resolved via DNS instead).
 */
export function parseObfuscatedIPv4(host: string): string | null {
  const componentPattern = /^(?:0x[0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*|0)$/;
  const parts = host.split('.');
  if (parts.length === 0 || parts.length > 4) return null;
  if (!parts.every((p) => componentPattern.test(p))) return null;

  const parseComponent = (s: string): number => {
    if (/^0x/i.test(s)) return parseInt(s, 16);
    if (/^0[0-7]+$/.test(s)) return parseInt(s, 8);
    return parseInt(s, 10);
  };

  const values = parts.map(parseComponent);
  const last = values.length - 1;

  for (let i = 0; i < last; i++) {
    if (values[i]! < 0 || values[i]! > 255) return null;
  }
  const lastBits = 32 - last * 8;
  const lastMax = lastBits >= 32 ? 0xffffffff : 2 ** lastBits - 1;
  if (values[last]! < 0 || values[last]! > lastMax) return null;

  let value = 0;
  for (let i = 0; i < last; i++) {
    value = value * 256 + values[i]!;
  }
  value = value * 2 ** lastBits + values[last]!;
  value = value >>> 0;

  // A single plain decimal/hex/octal component with no dots is only treated
  // as an IP if it actually looks numeric-only end to end (already enforced
  // by componentPattern) — real hostnames always contain a non-numeric TLD.
  return intToIpv4(value);
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/** Parses a syntactically valid IPv6 address (RFC 4291, including "::"
 * compression and a trailing embedded IPv4 dotted-quad) into a 128-bit BigInt. */
export function ipv6ToBigInt(address: string): bigint | null {
  let addr = address;

  const ipv4Tail = addr.match(/(?:^|:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (ipv4Tail) {
    const ipv4 = ipv4Tail[1]!;
    const octets = ipv4.split('.').map(Number);
    if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
    const hi = ((octets[0]! << 8) | octets[1]!).toString(16);
    const lo = ((octets[2]! << 8) | octets[3]!).toString(16);
    addr = addr.slice(0, addr.length - ipv4.length) + hi + ':' + lo;
  }

  const doubleColonParts = addr.split('::');
  if (doubleColonParts.length > 2) return null;

  const head = doubleColonParts[0] ? doubleColonParts[0].split(':').filter((g) => g !== '') : [];
  const tail =
    doubleColonParts.length === 2 && doubleColonParts[1]
      ? doubleColonParts[1].split(':').filter((g) => g !== '')
      : [];

  let groups: string[];
  if (doubleColonParts.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

export function isIPv6InCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/');
  const bits = BigInt(Number(bitsStr));
  const ipVal = ipv6ToBigInt(ip);
  const rangeVal = ipv6ToBigInt(range!);
  if (ipVal === null || rangeVal === null) return false;
  const shift = 128n - bits;
  const fullMask = (1n << 128n) - 1n;
  const mask = shift === 0n ? fullMask : (fullMask >> shift) << shift;
  return (ipVal & mask) === (rangeVal & mask);
}

/** If `ip` is an IPv4-mapped IPv6 address (::ffff:0:0/96), returns the
 * embedded IPv4 address so it can be re-checked against the IPv4 deny-list. */
export function extractIPv4MappedAddress(ip: string): string | null {
  const value = ipv6ToBigInt(ip);
  if (value === null) return null;
  const top96 = value >> 32n;
  if (top96 !== 0xffffn) return null;
  const low32 = value & 0xffffffffn;
  return intToIpv4(Number(low32));
}

// ---------------------------------------------------------------------------
// Deny-lists (§20.4)
// ---------------------------------------------------------------------------

export const IPV4_DENY_CIDRS = [
  '127.0.0.0/8',
  '0.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '192.0.2.0/24',
] as const;

export const IPV6_DENY_CIDRS = [
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  '::ffff:0:0/96',
] as const;

/** Rejected explicitly, before any generic range check (§20.4 "Cloud metadata"). */
export const EXPLICIT_METADATA_IPS = new Set(['169.254.169.254', '100.100.100.200']);

export function isBlockedIp(ip: string): boolean {
  if (EXPLICIT_METADATA_IPS.has(ip)) return true;

  const family = net.isIP(ip);
  if (family === 4) {
    return IPV4_DENY_CIDRS.some((cidr) => isIPv4InCidr(ip, cidr));
  }
  if (family === 6) {
    if (IPV6_DENY_CIDRS.some((cidr) => isIPv6InCidr(ip, cidr))) return true;
    const embedded = extractIPv4MappedAddress(ip);
    if (embedded && isBlockedIp(embedded)) return true;
    return false;
  }
  // Not a recognisable IP literal — fail closed rather than let it through.
  return true;
}

/**
 * Canonicalises a hostname string that may be an obfuscated IP literal
 * (decimal/octal/hex IPv4, or a bracket-stripped IPv6 literal). Returns
 * { ip, family } if the host IS an IP literal in some form, or null if it
 * should instead be treated as a hostname and resolved via DNS.
 */
export function canonicalizeIpLiteral(host: string): { ip: string; family: 4 | 6 } | null {
  const stripped = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;

  const directFamily = net.isIP(stripped);
  if (directFamily === 4) return { ip: stripped, family: 4 };
  if (directFamily === 6) return { ip: stripped, family: 6 };

  const obfuscated = parseObfuscatedIPv4(stripped);
  if (obfuscated) return { ip: obfuscated, family: 4 };

  return null;
}
