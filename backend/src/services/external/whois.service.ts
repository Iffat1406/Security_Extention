import type { PrismaClient } from '@prisma/client';
import { isIpLiteral } from '@guardtab/shared';
import { env } from '../../config/env';
import { breakers } from '../../lib/circuit-breaker';
import { metrics } from '../../lib/metrics';
import { getCached, setCached } from '../dedup.service';
import { ExternalHttpError, defaultHttpClient, reasonFor, type ExternalOutcome, type HttpClient } from './types';

/**
 * whois.service.ts — domain age and registrar (Feature 7).
 *
 * Provider decision (§33.3 "Choose a provider, confirm the tier"): RDAP,
 * the IETF-standard JSON successor to WHOIS, via the IANA bootstrap
 * redirector at rdap.org. It needs no API key and has no paid tier to
 * outgrow; the 7-day cache (§24.4) keeps request volume low regardless.
 * rdap.org answers with a redirect to the authoritative registry server —
 * safeFetch re-validates every hop against the SSRF rules (§20.4).
 *
 * TLDs with no RDAP service (some ccTLDs) return 404 and are reported as
 * NOT_SUPPORTED, which the risk engine treats as "no signal".
 */
export interface DomainAgeResult {
  domainAgeDays: number | null;
  registeredAt: string | null;
  registrar: string | null;
}

const TIMEOUT_MS = 3000;

interface RdapResponse {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: Array<{ roles?: string[]; vcardArray?: [string, Array<[string, unknown, string, unknown]>] }>;
}

export function parseRdap(body: string, now = Date.now()): DomainAgeResult {
  const rdap = JSON.parse(body) as RdapResponse;
  const registration = rdap.events?.find((e) => e.eventAction === 'registration')?.eventDate ?? null;
  const registeredMs = registration ? Date.parse(registration) : NaN;
  const registrarEntity = rdap.entities?.find((e) => e.roles?.includes('registrar'));
  const fn = registrarEntity?.vcardArray?.[1]?.find((field) => field[0] === 'fn');
  return {
    registeredAt: Number.isNaN(registeredMs) ? null : new Date(registeredMs).toISOString(),
    domainAgeDays: Number.isNaN(registeredMs) ? null : Math.max(0, Math.floor((now - registeredMs) / 86_400_000)),
    registrar: typeof fn?.[3] === 'string' ? fn[3].slice(0, 200) : null,
  };
}

export async function checkDomainAge(
  prisma: PrismaClient,
  registrableDomain: string,
  http: HttpClient = defaultHttpClient
): Promise<ExternalOutcome<DomainAgeResult>> {
  // §30.3 "Page uses an IP address ... WHOIS and lookalike checks report NOT_SUPPORTED".
  if (isIpLiteral(registrableDomain)) return { status: 'NOT_SUPPORTED', reason: 'IP_ADDRESS' };

  const cached = await getCached<DomainAgeResult | { unsupported: true }>(prisma, 'WHOIS', registrableDomain);
  if (cached) {
    metrics.externalCallTotal.inc({ service: 'whois', outcome: 'cached' });
    if ('unsupported' in cached.result) return { status: 'NOT_SUPPORTED', reason: 'NO_RDAP_SERVICE' };
    // Age keeps increasing while cached — recompute it from the stored registration date.
    const registered = cached.result.registeredAt ? Date.parse(cached.result.registeredAt) : NaN;
    const data = Number.isNaN(registered)
      ? cached.result
      : { ...cached.result, domainAgeDays: Math.floor((Date.now() - registered) / 86_400_000) };
    return { status: 'OK', data, cached: true };
  }

  const end = metrics.externalCallDuration.startTimer({ service: 'whois' });
  try {
    const data = await breakers.whois.exec(async () => {
      const response = await http(`${env.RDAP_BASE_URL}/domain/${encodeURIComponent(registrableDomain)}`, {
        method: 'GET',
        headers: { accept: 'application/rdap+json, application/json' },
        timeoutMs: TIMEOUT_MS,
      });
      if (response.status === 404) return null;
      if (response.status !== 200) throw new ExternalHttpError('whois', response.status);
      return parseRdap(response.body);
    });

    if (data === null) {
      await setCached(prisma, 'WHOIS', registrableDomain, { unsupported: true });
      return { status: 'NOT_SUPPORTED', reason: 'NO_RDAP_SERVICE' };
    }
    await setCached(prisma, 'WHOIS', registrableDomain, data);
    metrics.externalCallTotal.inc({ service: 'whois', outcome: 'ok' });
    return { status: 'OK', data, cached: false };
  } catch (error) {
    const reason = reasonFor(error);
    metrics.externalCallTotal.inc({ service: 'whois', outcome: reason === 'CIRCUIT_OPEN' ? 'circuit_open' : 'error' });
    return { status: 'UNAVAILABLE', reason };
  } finally {
    end();
  }
}
