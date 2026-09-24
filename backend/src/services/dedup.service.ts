import type { ExternalService, Prisma, PrismaClient } from '@prisma/client';
import { recordCacheLookup } from '../lib/metrics';

/**
 * dedup.service.ts — cross-user deduplication of external lookups (§5.1
 * Feature 2 "Deduplication", §24.4 budget controls).
 *
 * "If the same domain has been scanned by any user in the last 10 minutes,
 * the backend returns the cached DB result — no redundant external API
 * call." Backed by the reputation_cache table (see schema.prisma for why
 * Safe Browsing / VirusTotal are keyed by normalised URL, WHOIS by domain).
 *
 * The §16 interview note mentions moving this to Redis at scale; it's an
 * indexed unique-key lookup in PostgreSQL today, which is well inside the
 * §13 < 50ms query budget.
 */
export const DEDUP_TTL_MS: Record<ExternalService, number> = {
  SAFE_BROWSING: 10 * 60 * 1000,
  VIRUSTOTAL: 60 * 60 * 1000,
  WHOIS: 7 * 24 * 60 * 60 * 1000,
};

export async function getCached<T>(
  prisma: PrismaClient,
  service: ExternalService,
  cacheKey: string,
  maxAgeMs: number = DEDUP_TTL_MS[service]
): Promise<{ result: T; checkedAt: Date } | null> {
  const row = await prisma.reputationCache.findUnique({ where: { cacheKey_service: { cacheKey, service } } });
  const fresh = row !== null && Date.now() - row.checkedAt.getTime() <= maxAgeMs;
  recordCacheLookup(`dedup_${service.toLowerCase()}`, fresh);
  return fresh ? { result: row.result as T, checkedAt: row.checkedAt } : null;
}

export async function setCached(prisma: PrismaClient, service: ExternalService, cacheKey: string, result: unknown): Promise<void> {
  const json = result as Prisma.InputJsonValue;
  await prisma.reputationCache.upsert({
    where: { cacheKey_service: { cacheKey, service } },
    create: { cacheKey, service, result: json },
    update: { result: json, checkedAt: new Date() },
  });
}

/** Cache key for URL-level verdicts: host + normalised (redacted) path, never the query. */
export function urlCacheKey(host: string, path: string | null): string {
  return `${host}${path ?? '/'}`.slice(0, 512);
}
