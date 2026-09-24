/**
 * Small, dependency-free host helpers that run in both the extension (no
 * `node:net`) and the backend. The backend's SSRF guard (ip-utils.ts,
 * url-safety.service.ts) is the rigorous check; these exist so the extension
 * can decide *locally* not to scan or send a private address at all (§30.2).
 */

/** True when `host` is `domain` or any subdomain of it (§23.2 exclusion semantics). */
export function hostMatchesDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith(`.${d}`);
}

export function stripIpv6Brackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

export function isIpv4Literal(host: string): boolean {
  const parts = host.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

export function isIpv6Literal(host: string): boolean {
  const h = stripIpv6Brackets(host);
  return h.includes(':') && /^[0-9a-f:.]+$/i.test(h);
}

export function isIpLiteral(host: string): boolean {
  return isIpv4Literal(host) || isIpv6Literal(host);
}

/** Loopback / localhost / mDNS — scannable locally only when the user opts in (§30.2 "Local addresses"). */
export function isLocalAddress(host: string): boolean {
  const h = stripIpv6Brackets(host.toLowerCase());
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  if (isIpv4Literal(h)) return h.startsWith('127.') || h === '0.0.0.0';
  return false;
}

/** RFC1918 / link-local / CGNAT / ULA — never scanned (§30.2 "Private networks"). */
export function isPrivateNetworkAddress(host: string): boolean {
  const h = stripIpv6Brackets(host.toLowerCase());
  if (isIpv4Literal(h)) {
    const [a, b] = h.split('.').map(Number) as [number, number];
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (isIpv6Literal(h)) {
    return /^f[cd][0-9a-f]{0,2}:/.test(h) || /^fe[89ab][0-9a-f]?:/.test(h);
  }
  return h.endsWith('.internal') || h.endsWith('.lan') || h.endsWith('.home.arpa');
}

/**
 * Approximate "same site" test without bundling the Public Suffix List into
 * the extension. Used only for the third-party request ratio (§19.3) — an
 * estimate by nature. The backend always uses the real PSL for anything that
 * is persisted or deduplicated.
 */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'firm.in', 'gen.in', 'ind.in',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za', 'gov.za',
  'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.my', 'com.pk', 'com.ng', 'com.eg', 'com.sa',
  'co.kr', 'or.kr', 'co.id', 'co.il', 'co.th',
  'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'pages.dev', 'web.app', 'firebaseapp.com',
  'blogspot.com', 'azurewebsites.net', 'cloudfront.net', 'appspot.com',
]);

export function approximateSiteOf(host: string): string {
  const h = stripIpv6Brackets(host.toLowerCase()).replace(/\.$/, '');
  if (isIpLiteral(h)) return h;
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

export function isSameSite(hostA: string, hostB: string): boolean {
  return approximateSiteOf(hostA) === approximateSiteOf(hostB);
}
