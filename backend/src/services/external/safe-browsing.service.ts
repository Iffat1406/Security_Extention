import type { PrismaClient } from '@prisma/client';
import { SCANNER_VERSION } from '@guardtab/shared';
import { env } from '../../config/env';
import { breakers } from '../../lib/circuit-breaker';
import { metrics } from '../../lib/metrics';
import { getCached, setCached } from '../dedup.service';
import { ExternalHttpError, defaultHttpClient, reasonFor, sleep, type ExternalOutcome, type HttpClient } from './types';

/**
 * safe-browsing.service.ts — Google Safe Browsing Lookup API v4
 * (threatMatches:find). §24.4: 2s timeout, 1 retry with 200ms backoff,
 * once per page per 10 minutes across all users.
 *
 * §33.3: confirm current quota/terms before launch, and whether the Update
 * API is a better fit at scale. The Lookup API sends the (sensitive-param-
 * stripped, §20.3) URL to Google; the Update API would keep URLs local.
 */
export interface SafeBrowsingResult {
  isMalicious: boolean;
  threatTypes: string[];
}

const ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const TIMEOUT_MS = 2000;
const RETRY_BACKOFF_MS = 200;
const THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];

async function lookup(http: HttpClient, url: string): Promise<SafeBrowsingResult> {
  const response = await http(`${ENDPOINT}?key=${encodeURIComponent(env.SAFE_BROWSING_API_KEY!)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    timeoutMs: TIMEOUT_MS,
    body: JSON.stringify({
      client: { clientId: 'guardtab', clientVersion: SCANNER_VERSION },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    }),
  });
  if (response.status !== 200) throw new ExternalHttpError('safeBrowsing', response.status);

  const parsed = JSON.parse(response.body || '{}') as { matches?: Array<{ threatType?: string }> };
  const threatTypes = [...new Set((parsed.matches ?? []).map((m) => m.threatType).filter((t): t is string => Boolean(t)))];
  return { isMalicious: threatTypes.length > 0, threatTypes };
}

export async function checkSafeBrowsing(
  prisma: PrismaClient,
  args: { lookupUrl: string; cacheKey: string; bypassCache?: boolean },
  http: HttpClient = defaultHttpClient
): Promise<ExternalOutcome<SafeBrowsingResult>> {
  if (!env.SAFE_BROWSING_API_KEY) {
    metrics.externalCallTotal.inc({ service: 'safeBrowsing', outcome: 'skipped' });
    return { status: 'SKIPPED', reason: 'NOT_CONFIGURED' };
  }

  if (!args.bypassCache) {
    const cached = await getCached<SafeBrowsingResult>(prisma, 'SAFE_BROWSING', args.cacheKey);
    if (cached) {
      metrics.externalCallTotal.inc({ service: 'safeBrowsing', outcome: 'cached' });
      return { status: 'OK', data: cached.result, cached: true };
    }
  }

  const end = metrics.externalCallDuration.startTimer({ service: 'safeBrowsing' });
  try {
    const data = await breakers.safeBrowsing.exec(async () => {
      try {
        return await lookup(http, args.lookupUrl);
      } catch (error) {
        // One retry, 200ms backoff (§24.4) — but never on a 4xx, which won't change.
        if (error instanceof ExternalHttpError && error.statusCode < 500 && error.statusCode !== 429) throw error;
        await sleep(RETRY_BACKOFF_MS);
        return lookup(http, args.lookupUrl);
      }
    });
    await setCached(prisma, 'SAFE_BROWSING', args.cacheKey, data);
    metrics.externalCallTotal.inc({ service: 'safeBrowsing', outcome: 'ok' });
    return { status: 'OK', data, cached: false };
  } catch (error) {
    const reason = reasonFor(error);
    metrics.externalCallTotal.inc({ service: 'safeBrowsing', outcome: reason === 'CIRCUIT_OPEN' ? 'circuit_open' : 'error' });
    return { status: 'UNAVAILABLE', reason };
  } finally {
    end();
  }
}
