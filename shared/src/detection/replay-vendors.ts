import { hostMatchesDomain } from './domain';

/**
 * §19.3 "Session recording / analytics replay +10 — Known replay vendors in
 * the tracker list". Disconnect.me files these under Analytics without a
 * separate category, so the vendors are listed here explicitly.
 */
export const SESSION_REPLAY_DOMAINS: readonly string[] = [
  'hotjar.com',
  'hotjar.io',
  'fullstory.com',
  'mouseflow.com',
  'smartlook.com',
  'smartlook.cloud',
  'logrocket.com',
  'lr-ingest.io',
  'lr-in.com',
  'clarity.ms',
  'inspectlet.com',
  'luckyorange.com',
  'luckyorange.net',
  'sessioncam.com',
  'quantummetric.com',
  'contentsquare.net',
  'contentsquare.com',
  'clicktale.net',
  'crazyegg.com',
  'glassboxdigital.io',
  'decibelinsight.net',
  'uxcam.com',
  'heapanalytics.com',
  'posthog.com',
];

export function isSessionReplayDomain(host: string): boolean {
  return SESSION_REPLAY_DOMAINS.some((d) => hostMatchesDomain(host, d));
}
