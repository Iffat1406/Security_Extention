import type { RedirectCheck } from '../schemas/checks.schema';

/**
 * §31.1 redirect chain analysis. Pure: the caller supplies the site
 * (registrable domain) function and the final domain's age, so the backend
 * can use the real Public Suffix List and cached WHOIS data.
 */

/** Public URL shorteners. Brand-owned shorteners (youtu.be, amzn.to) are deliberately absent — a hop through them isn't suspicious. */
export const URL_SHORTENERS: ReadonlySet<string> = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'v.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
  'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink', 's.id', 'short.io', 'shorte.st', 'adf.ly', 'soo.gd',
  'tr.im', 'x.co', 'clck.ru', 'qr.net', 'urlz.fr', 'surl.li', 'shorturl.asia', 'tiny.one', 'gg.gg', 'lnk.bio',
]);

export const REDIRECT_SIGNALS = [
  /** 3+ cross-domain hops. */
  'CROSS_DOMAIN_CHAIN',
  /** A hop through a known public shortener. */
  'SHORTENER_HOP',
  /** The landing domain is younger than 30 days. */
  'YOUNG_FINAL_DOMAIN',
  /** A hop that changes scheme from HTTPS to HTTP. */
  'SCHEME_DOWNGRADE',
  /** A hop (or the landing host) that is a lookalike match. */
  'LOOKALIKE_HOP',
] as const;
export type RedirectSignal = (typeof REDIRECT_SIGNALS)[number];

export type HopType = 'shortener' | 'cross-domain' | 'same-domain' | 'scheme-downgrade';

export interface AnalyzedRedirectChain {
  hops: Array<{ host: string; statusCode: number; hopType: HopType }>;
  signals: RedirectSignal[];
  /** §31.1 "Contributes +10 ... when two or more of those signals coincide". */
  suspicious: boolean;
  crossDomainHops: number;
}

export interface RedirectContext {
  finalHost: string;
  finalProtocol: 'http:' | 'https:';
  siteOf: (host: string) => string;
  finalDomainAgeDays?: number | null;
  isLookalikeHost?: (host: string) => boolean;
}

export function analyzeRedirectChain(hops: RedirectCheck['hops'], ctx: RedirectContext): AnalyzedRedirectChain {
  // Each hop is a host that answered with a 3xx; the next element (or the
  // landing page) is where it sent the browser.
  const chain = [...hops.map((h) => ({ host: h.host, scheme: h.scheme })), { host: ctx.finalHost, scheme: ctx.finalProtocol }];
  const analyzed: AnalyzedRedirectChain['hops'] = [];
  const signals = new Set<RedirectSignal>();
  let crossDomainHops = 0;

  hops.forEach((hop, i) => {
    const next = chain[i + 1]!;
    let hopType: HopType;
    if (hop.scheme === 'https:' && next.scheme === 'http:') {
      hopType = 'scheme-downgrade';
      signals.add('SCHEME_DOWNGRADE');
    } else if (URL_SHORTENERS.has(hop.host)) {
      hopType = 'shortener';
      signals.add('SHORTENER_HOP');
    } else if (ctx.siteOf(hop.host) !== ctx.siteOf(next.host)) {
      hopType = 'cross-domain';
    } else {
      hopType = 'same-domain';
    }
    if (ctx.siteOf(hop.host) !== ctx.siteOf(next.host)) crossDomainHops++;
    if (ctx.isLookalikeHost?.(hop.host)) signals.add('LOOKALIKE_HOP');
    analyzed.push({ host: hop.host, statusCode: hop.statusCode, hopType });
  });

  if (crossDomainHops >= 3) signals.add('CROSS_DOMAIN_CHAIN');
  if (hops.length > 0) {
    if (ctx.finalDomainAgeDays != null && ctx.finalDomainAgeDays < 30) signals.add('YOUNG_FINAL_DOMAIN');
    if (ctx.isLookalikeHost?.(ctx.finalHost)) signals.add('LOOKALIKE_HOP');
  }

  const signalList = REDIRECT_SIGNALS.filter((s) => signals.has(s));
  return { hops: analyzed, signals: signalList, suspicious: signalList.length >= 2, crossDomainHops };
}
