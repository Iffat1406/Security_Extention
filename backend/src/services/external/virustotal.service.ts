import type { PrismaClient } from '@prisma/client';
import { env } from '../../config/env';
import { breakers } from '../../lib/circuit-breaker';
import { metrics } from '../../lib/metrics';
import { getCached, setCached } from '../dedup.service';
import { ExternalHttpError, defaultHttpClient, reasonFor, type ExternalOutcome, type HttpClient } from './types';

/**
 * virustotal.service.ts — VirusTotal API v3 URL report (GET /urls/{id}).
 *
 * §7 / §24.4: "Only called if Safe Browsing returns clean", "max 1 per
 * domain per hour", 3s timeout, no retry. The free tier is 4 req/min and
 * 500/day (§33.3: confirm before launch) — enforced here by an in-process
 * budget so the key is never pushed into a 429 in the first place.
 *
 * A URL VirusTotal has never analysed returns 404; that's reported as
 * SKIPPED (no data), not as "clean" — "not yet known" is not "safe" (§30.1).
 */
export interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

const TIMEOUT_MS = 3000;

/** Sliding-window budget. Single-instance by design; see README "Scaling". */
export class CallBudget {
  private minuteCalls: number[] = [];
  private dayCalls: number[] = [];

  constructor(
    private readonly perMinute: number,
    private readonly perDay: number,
    private readonly now: () => number = Date.now
  ) {}

  tryConsume(): boolean {
    const t = this.now();
    this.minuteCalls = this.minuteCalls.filter((c) => t - c < 60_000);
    this.dayCalls = this.dayCalls.filter((c) => t - c < 86_400_000);
    if (this.minuteCalls.length >= this.perMinute || this.dayCalls.length >= this.perDay) return false;
    this.minuteCalls.push(t);
    this.dayCalls.push(t);
    metrics.externalQuotaRemaining.set({ service: 'virusTotal', window: 'minute' }, this.perMinute - this.minuteCalls.length);
    metrics.externalQuotaRemaining.set({ service: 'virusTotal', window: 'day' }, this.perDay - this.dayCalls.length);
    return true;
  }

  remaining() {
    const t = this.now();
    return {
      minute: this.perMinute - this.minuteCalls.filter((c) => t - c < 60_000).length,
      day: this.perDay - this.dayCalls.filter((c) => t - c < 86_400_000).length,
    };
  }
}

export const virusTotalBudget = new CallBudget(env.VIRUSTOTAL_PER_MINUTE, env.VIRUSTOTAL_PER_DAY);

/** VT v3 URL identifier: unpadded base64url of the URL. */
export function virusTotalUrlId(url: string): string {
  return Buffer.from(url).toString('base64url');
}

export async function checkVirusTotal(
  prisma: PrismaClient,
  args: { lookupUrl: string; cacheKey: string; bypassCache?: boolean },
  http: HttpClient = defaultHttpClient,
  budget: CallBudget = virusTotalBudget
): Promise<ExternalOutcome<VirusTotalResult>> {
  if (!env.VIRUSTOTAL_API_KEY) {
    metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: 'skipped' });
    return { status: 'SKIPPED', reason: 'NOT_CONFIGURED' };
  }

  // Rescan bypasses the Chrome cache and the 10-minute dedup window (§23.3)
  // but not VirusTotal's hourly cap — that one protects a hard daily quota.
  const cached = await getCached<VirusTotalResult | { notFound: true }>(prisma, 'VIRUSTOTAL', args.cacheKey);
  if (cached) {
    metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: 'cached' });
    if ('notFound' in cached.result) return { status: 'SKIPPED', reason: 'NO_VIRUSTOTAL_RECORD' };
    return { status: 'OK', data: cached.result, cached: true };
  }

  if (!budget.tryConsume()) {
    metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: 'skipped' });
    return { status: 'SKIPPED', reason: 'QUOTA_BUDGET' };
  }

  const end = metrics.externalCallDuration.startTimer({ service: 'virusTotal' });
  try {
    const data = await breakers.virusTotal.exec(async () => {
      const response = await http(`https://www.virustotal.com/api/v3/urls/${virusTotalUrlId(args.lookupUrl)}`, {
        method: 'GET',
        headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY!, accept: 'application/json' },
        timeoutMs: TIMEOUT_MS,
      });
      if (response.status === 404) return null;
      if (response.status !== 200) throw new ExternalHttpError('virusTotal', response.status);
      const parsed = JSON.parse(response.body) as {
        data?: { attributes?: { last_analysis_stats?: Partial<VirusTotalResult> } };
      };
      const stats = parsed.data?.attributes?.last_analysis_stats ?? {};
      return {
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
      } satisfies VirusTotalResult;
    });

    if (data === null) {
      await setCached(prisma, 'VIRUSTOTAL', args.cacheKey, { notFound: true });
      metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: 'ok' });
      return { status: 'SKIPPED', reason: 'NO_VIRUSTOTAL_RECORD' };
    }
    await setCached(prisma, 'VIRUSTOTAL', args.cacheKey, data);
    metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: 'ok' });
    return { status: 'OK', data, cached: false };
  } catch (error) {
    const reason = reasonFor(error);
    metrics.externalCallTotal.inc({ service: 'virusTotal', outcome: reason === 'CIRCUIT_OPEN' ? 'circuit_open' : 'error' });
    return { status: 'UNAVAILABLE', reason };
  } finally {
    end();
  }
}
