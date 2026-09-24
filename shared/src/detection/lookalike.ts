import { BRANDS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, type Brand } from './brands';
import { hostMatchesDomain, isIpLiteral } from './domain';
import { hostToUnicode } from './punycode';

/**
 * §31.2 lookalike domain detection.
 *
 * Each technique carries an explicit similarity constant rather than a
 * learned or blended score, so the behaviour is reviewable and unit-testable
 * and the "only ≥ 0.90 adds points" rule has a precise meaning. Copy
 * produced here always says "resembles" — this is a similarity measure, not
 * a verdict (§31.2 "Wording is careful").
 */

/** Only matches at or above this add +25 to the security penalty (§31.2). */
export const LOOKALIKE_SCORING_THRESHOLD = 0.9;
/** Below this, a match isn't even shown as information. */
export const LOOKALIKE_INFO_THRESHOLD = 0.75;

export const LOOKALIKE_SIMILARITY = {
  /** Unicode/mixed-script host whose skeleton is exactly the brand (xn--pypal-4ve.com). */
  MIXED_SCRIPT: 0.96,
  /** ASCII homoglyph skeleton is exactly the brand (paypa1.com, rnicrosoft.com, g00gle.com). */
  HOMOGLYPH: 0.95,
  /** The brand's real domain sits inside another domain's subdomain (paypal.com.secure-verify.io). */
  BRAND_DOMAIN_IN_SUBDOMAIN: 0.95,
  /** Damerau-Levenshtein 1 from a brand token of 6+ characters (paypall.com, gooogle.com). */
  EDIT_DISTANCE_1_LONG: 0.92,
  /** Brand token plus a phishing keyword (paypal-login.com), via a homoglyph (paypaI-security.com). */
  BRAND_KEYWORD_HOMOGLYPH: 0.91,
  /** Brand token plus a phishing keyword (paypal-login.com, apple-security-verify.com). */
  BRAND_KEYWORD: 0.9,
  /** Damerau-Levenshtein 2 from a brand token of 8+ characters. */
  EDIT_DISTANCE_2_LONG: 0.86,
  /** Distance 1 from a 5-character token — too many honest words to score. */
  EDIT_DISTANCE_1_SHORT: 0.85,
  /** Exact brand label on a high-abuse TLD (paypal.xyz). */
  BRAND_ON_SUSPICIOUS_TLD: 0.85,
  /** Brand token as a subdomain label of an unrelated domain (paypal.verify-now.io). */
  BRAND_LABEL_IN_SUBDOMAIN: 0.85,
  /** 4+ subdomain levels with the brand token somewhere in them. */
  EXCESSIVE_SUBDOMAIN_DEPTH: 0.8,
  /** Added to a match that also sits on a high-abuse TLD (§31.2 "Suspicious TLD — Low"). */
  SUSPICIOUS_TLD_BUMP: 0.03,
} as const;

export type LookalikeTechnique =
  | 'MIXED_SCRIPT'
  | 'HOMOGLYPH'
  | 'BRAND_DOMAIN_IN_SUBDOMAIN'
  | 'EDIT_DISTANCE'
  | 'BRAND_KEYWORD'
  | 'BRAND_ON_SUSPICIOUS_TLD'
  | 'BRAND_LABEL_IN_SUBDOMAIN'
  | 'EXCESSIVE_SUBDOMAIN_DEPTH';

export interface LookalikeMatch {
  brand: string;
  brandDomain: string;
  similarity: number;
  technique: LookalikeTechnique;
  /** User-facing, careful wording: "resembles", never "fake". */
  explanation: string;
}

// ---------------------------------------------------------------------------
// Skeleton: collapse visually-confusable characters to one canonical form
// ---------------------------------------------------------------------------

const UNICODE_CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x',
  ѕ: 's', і: 'i', ї: 'i', ј: 'j', ԁ: 'd', ԛ: 'q', ԝ: 'w', ӏ: 'l', ɡ: 'g', ү: 'y', һ: 'h', ո: 'n', ս: 'u',
  // Greek
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w', μ: 'u',
  // Latin look-alikes that survive NFD
  ı: 'i', ł: 'l', ɑ: 'a', ɩ: 'i', ʟ: 'l', ƅ: 'b', ɒ: 'a', đ: 'd', ħ: 'h', ŧ: 't', ø: 'o', ß: 'ss', æ: 'ae', œ: 'oe',
};

const ASCII_CONFUSABLES: ReadonlyArray<[RegExp, string]> = [
  // Multi-character first: "rn" renders as "m", "vv" as "w", "cl" as "d".
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/3/g, 'e'],
  [/5/g, 's'],
  [/\|/g, 'l'],
  // "I" and "l" are indistinguishable in many sans-serif fonts; hosts are
  // lowercased, so fold "i" into "l" on both sides of every comparison.
  [/i/g, 'l'],
];

export function skeleton(input: string): string {
  let s = input.normalize('NFKC').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  s = Array.from(s, (ch) => UNICODE_CONFUSABLES[ch] ?? ch).join('');
  for (const [pattern, replacement] of ASCII_CONFUSABLES) s = s.replace(pattern, replacement);
  return s;
}

// ---------------------------------------------------------------------------
// Damerau-Levenshtein (optimal string alignment)
// ---------------------------------------------------------------------------

export function damerauLevenshtein(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const d: number[][] = Array.from({ length: rows }, (_, i) => {
    const row = new Array<number>(cols).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j < cols; j++) d[0]![j] = j;

  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = value;
    }
  }
  return d[a.length]![b.length]!;
}

// ---------------------------------------------------------------------------

function hasSuspiciousKeyword(label: string): boolean {
  const parts = label.split('-').filter(Boolean);
  if (parts.some((p) => SUSPICIOUS_KEYWORDS.has(p))) return true;
  // Concatenated forms ("paypalsecure", "appleidverify") — only for longer keywords
  // so short ones like "id" and "pay" can't match inside ordinary words.
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (keyword.length >= 5 && label.includes(keyword)) return true;
  }
  return false;
}

function matchBrand(
  brand: Brand,
  label: string,
  labelSkeleton: string,
  subdomainLabels: string[],
  tld: string,
  hadUnicode: boolean
): { similarity: number; technique: LookalikeTechnique; detail: string } | null {
  const token = brand.token;
  const tokenSkeleton = skeleton(token);
  const short = token.length < 5;
  const candidates: Array<{ similarity: number; technique: LookalikeTechnique; detail: string }> = [];

  // 1. Homoglyph / mixed script — the label *is* the brand once confusables
  // collapse. Not for very short tokens: with "i"→"l" folding, "lrs.com"
  // would collapse onto "irs", and a 3–4 letter skeleton collides with too
  // many honest names to be worth +25.
  if (!short && label !== token && labelSkeleton === tokenSkeleton) {
    candidates.push(
      hadUnicode
        ? { similarity: LOOKALIKE_SIMILARITY.MIXED_SCRIPT, technique: 'MIXED_SCRIPT', detail: 'uses look-alike characters from another alphabet' }
        : { similarity: LOOKALIKE_SIMILARITY.HOMOGLYPH, technique: 'HOMOGLYPH', detail: 'swaps in look-alike characters' }
    );
  }

  // 2. Edit distance on the registrable label.
  if (brand.fuzzy !== false && token.length >= 5 && label !== token) {
    const distance = Math.min(damerauLevenshtein(label, token), damerauLevenshtein(labelSkeleton, tokenSkeleton));
    if (distance === 1) {
      candidates.push({
        similarity: token.length >= 6 ? LOOKALIKE_SIMILARITY.EDIT_DISTANCE_1_LONG : LOOKALIKE_SIMILARITY.EDIT_DISTANCE_1_SHORT,
        technique: 'EDIT_DISTANCE',
        detail: 'is one character away from the real name',
      });
    } else if (distance === 2 && token.length >= 8) {
      candidates.push({ similarity: LOOKALIKE_SIMILARITY.EDIT_DISTANCE_2_LONG, technique: 'EDIT_DISTANCE', detail: 'is two characters away from the real name' });
    }
  }

  // 3. Brand token + phishing keyword.
  const parts = label.split('-');
  const containsToken = short ? parts.includes(token) : label.includes(token) && label !== token;
  const containsTokenViaHomoglyph = !containsToken && !short && labelSkeleton.includes(tokenSkeleton) && labelSkeleton !== tokenSkeleton;
  if ((containsToken || containsTokenViaHomoglyph) && hasSuspiciousKeyword(label)) {
    candidates.push(
      containsTokenViaHomoglyph
        ? { similarity: LOOKALIKE_SIMILARITY.BRAND_KEYWORD_HOMOGLYPH, technique: 'BRAND_KEYWORD', detail: 'combines a disguised brand name with a sign-in or account word' }
        : { similarity: LOOKALIKE_SIMILARITY.BRAND_KEYWORD, technique: 'BRAND_KEYWORD', detail: 'combines the brand name with a sign-in or account word' }
    );
  }

  // 4. The brand's real domain, or its token, inside someone else's subdomain.
  if (subdomainLabels.length > 0) {
    const sub = `.${subdomainLabels.join('.')}.`;
    if (brand.domains.some((d) => sub.includes(`.${d}.`))) {
      candidates.push({ similarity: LOOKALIKE_SIMILARITY.BRAND_DOMAIN_IN_SUBDOMAIN, technique: 'BRAND_DOMAIN_IN_SUBDOMAIN', detail: "puts the brand's real address in front of a different domain" });
    } else if (token.length >= 4 && subdomainLabels.includes(token)) {
      candidates.push({ similarity: LOOKALIKE_SIMILARITY.BRAND_LABEL_IN_SUBDOMAIN, technique: 'BRAND_LABEL_IN_SUBDOMAIN', detail: 'uses the brand name as a subdomain of an unrelated site' });
    }
    if (subdomainLabels.length >= 4 && subdomainLabels.some((l) => l.includes(token)) && token.length >= 4) {
      candidates.push({ similarity: LOOKALIKE_SIMILARITY.EXCESSIVE_SUBDOMAIN_DEPTH, technique: 'EXCESSIVE_SUBDOMAIN_DEPTH', detail: 'hides the brand name deep inside a long address' });
    }
  }

  // 5. Suspicious TLD.
  const onSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  if (onSuspiciousTld && label === token) {
    candidates.push({ similarity: LOOKALIKE_SIMILARITY.BRAND_ON_SUSPICIOUS_TLD, technique: 'BRAND_ON_SUSPICIOUS_TLD', detail: `uses the brand name on the uncommon ".${tld}" ending` });
  }

  if (candidates.length === 0) return null;
  const best = candidates.reduce((a, b) => (b.similarity > a.similarity ? b : a));
  const bumped = onSuspiciousTld && best.technique !== 'BRAND_ON_SUSPICIOUS_TLD' ? Math.min(0.99, best.similarity + LOOKALIKE_SIMILARITY.SUSPICIOUS_TLD_BUMP) : best.similarity;
  return { ...best, similarity: Math.round(bumped * 100) / 100 };
}

/**
 * @param host             Lowercase hostname (punycode form is fine).
 * @param registrableDomain Public-Suffix-List registrable domain for `host` (the backend passes psl.get()).
 */
export function detectLookalike(host: string, registrableDomain: string, brands: readonly Brand[] = BRANDS): LookalikeMatch | null {
  const h = host.toLowerCase().replace(/\.$/, '');
  const reg = registrableDomain.toLowerCase();
  if (!h || !reg || isIpLiteral(h)) return null;

  const unicodeHost = hostToUnicode(h);
  const unicodeReg = hostToUnicode(reg);
  const hadUnicode = unicodeHost !== h;

  const regLabels = unicodeReg.split('.');
  const label = regLabels[0] ?? '';
  const tld = regLabels[regLabels.length - 1] ?? '';
  const hostLabels = unicodeHost.split('.');
  const subdomainLabels = hostLabels.slice(0, Math.max(0, hostLabels.length - regLabels.length)).filter((l) => l !== 'www');
  const labelSkeleton = skeleton(label);

  let best: LookalikeMatch | null = null;
  for (const brand of brands) {
    // A brand never matches its own domains or declared aliases — "the most
    // common false positive by far" (§31.2).
    if (brand.domains.some((d) => hostMatchesDomain(h, d))) continue;

    const match = matchBrand(brand, label, labelSkeleton, subdomainLabels, tld, hadUnicode);
    if (match && (!best || match.similarity > best.similarity)) {
      best = {
        brand: brand.name,
        brandDomain: brand.domains[0]!,
        similarity: match.similarity,
        technique: match.technique,
        explanation: `This address resembles ${brand.name} (${brand.domains[0]}) — it ${match.detail}. GuardTab has not verified that this site is fraudulent. Check the address carefully before signing in.`,
      };
    }
  }

  return best && best.similarity >= LOOKALIKE_INFO_THRESHOLD ? best : null;
}
