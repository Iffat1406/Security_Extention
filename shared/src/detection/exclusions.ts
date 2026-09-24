import { hostMatchesDomain, isLocalAddress, isPrivateNetworkAddress } from './domain';

/**
 * §30.2 "Page types that are never scanned" + §23.2 user exclusions.
 *
 * Runs in the service worker before any check (§23.2: "an excluded page
 * produces no local checks, no backend request, and no cache entry"), and
 * again on the backend as defence in depth — the extension is not a trusted
 * client (§18.4).
 */

export const NOT_SUPPORTED_REASONS = [
  'BROWSER_INTERNAL',
  'WEB_STORE',
  'LOCAL_FILE',
  'LOCAL_ADDRESS',
  'PRIVATE_NETWORK',
  'BLANK_PAGE',
  'PDF_VIEWER',
  'VIEW_SOURCE',
  'DATA_URL',
  'USER_EXCLUDED',
  'UNSUPPORTED_SCHEME',
  'INVALID_URL',
] as const;
export type NotSupportedReason = (typeof NOT_SUPPORTED_REASONS)[number];

export type PageClassification =
  | { scannable: true; host: string; origin: string; protocol: 'http:' | 'https:'; localOnly: boolean }
  | { scannable: false; reason: NotSupportedReason };

export interface ClassifyOptions {
  excludedDomains?: readonly string[];
  /** §30.2 "A setting allows local scanning with local checks only". */
  scanLocalAddresses?: boolean;
}

const BROWSER_INTERNAL_SCHEMES = new Set([
  'chrome:',
  'chrome-extension:',
  'chrome-search:',
  'chrome-untrusted:',
  'devtools:',
  'edge:',
  'brave:',
  'opera:',
  'vivaldi:',
  'about:',
  'moz-extension:',
]);

const WEB_STORE_HOSTS = ['chromewebstore.google.com', 'microsoftedge.microsoft.com'];

/** Human-readable popup copy for each reason (§30.2 "Behaviour" column). */
export const NOT_SUPPORTED_MESSAGES: Record<NotSupportedReason, string> = {
  BROWSER_INTERNAL: "GuardTab doesn't scan browser pages.",
  WEB_STORE: "Chrome doesn't allow extensions to inspect the Web Store.",
  LOCAL_FILE: 'Local files are not scanned. Nothing was sent anywhere.',
  LOCAL_ADDRESS: 'Local addresses are not scanned. You can allow local-only scanning in settings.',
  PRIVATE_NETWORK: "Private network addresses are never scanned — an internal hostname doesn't leave your machine.",
  BLANK_PAGE: 'Nothing to scan on a blank page.',
  PDF_VIEWER: "PDFs open in Chrome's viewer have no page to inspect.",
  VIEW_SOURCE: 'View-source pages are not scanned.',
  DATA_URL: 'Data and blob URLs are not scanned.',
  USER_EXCLUDED: 'You excluded this site. GuardTab is deliberately inactive here.',
  UNSUPPORTED_SCHEME: 'Only http and https pages are scanned.',
  INVALID_URL: "This address couldn't be read.",
};

export function classifyPage(rawUrl: string, options: ClassifyOptions = {}): PageClassification {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { scannable: false, reason: 'INVALID_URL' };
  }

  const scheme = url.protocol;
  if (scheme === 'about:' && (url.pathname === 'blank' || url.pathname === 'newtab')) {
    return { scannable: false, reason: 'BLANK_PAGE' };
  }
  if (BROWSER_INTERNAL_SCHEMES.has(scheme)) return { scannable: false, reason: 'BROWSER_INTERNAL' };
  if (scheme === 'view-source:') return { scannable: false, reason: 'VIEW_SOURCE' };
  if (scheme === 'file:') return { scannable: false, reason: 'LOCAL_FILE' };
  if (scheme === 'data:' || scheme === 'blob:') return { scannable: false, reason: 'DATA_URL' };
  if (scheme !== 'http:' && scheme !== 'https:') return { scannable: false, reason: 'UNSUPPORTED_SCHEME' };

  const host = url.hostname.toLowerCase();
  if (!host) return { scannable: false, reason: 'INVALID_URL' };

  if (
    WEB_STORE_HOSTS.some((h) => hostMatchesDomain(host, h)) ||
    (host === 'chrome.google.com' && url.pathname.startsWith('/webstore'))
  ) {
    return { scannable: false, reason: 'WEB_STORE' };
  }

  // Chrome's built-in PDF viewer is itself an extension page; a top-level
  // http(s) URL ending in .pdf is also rendered by it — no DOM to inspect.
  if (/\.pdf$/i.test(url.pathname)) return { scannable: false, reason: 'PDF_VIEWER' };

  if (isPrivateNetworkAddress(host)) return { scannable: false, reason: 'PRIVATE_NETWORK' };

  let localOnly = false;
  if (isLocalAddress(host)) {
    if (!options.scanLocalAddresses) return { scannable: false, reason: 'LOCAL_ADDRESS' };
    localOnly = true;
  }

  if ((options.excludedDomains ?? []).some((d) => hostMatchesDomain(host, d))) {
    return { scannable: false, reason: 'USER_EXCLUDED' };
  }

  return { scannable: true, host, origin: url.origin, protocol: scheme, localOnly };
}
