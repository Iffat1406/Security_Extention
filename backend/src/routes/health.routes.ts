import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { env, isAiConfigured, isGoogleAuthConfigured } from '../config/env';
import { breakers } from '../lib/circuit-breaker';
import { registry } from '../lib/metrics';
import { redisHealthy } from '../lib/redis';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { isUnderSpendCap } from '../services/ai-explainer.service';
import { virusTotalBudget } from '../services/external/virustotal.service';

/**
 * §28.3 "Health endpoints" + §28.2 metrics.
 *
 * "Public health endpoints must never return dependency hostnames, library
 * versions, migration names, stack traces or quota values." /health and
 * /health/ready return booleans only; everything detailed is ADMIN-only.
 */
export default async function healthRoutes(app: FastifyInstance) {
  app.get('/health', { config: { rateLimit: false } }, async () => ({ status: 'ok' as const }));

  app.get('/health/ready', { config: { rateLimit: false } }, async (_request, reply) => {
    const dependencies: Record<string, boolean> = { postgres: false, migrations: false };

    try {
      await app.prisma.$queryRaw`SELECT 1`;
      dependencies.postgres = true;
    } catch {
      dependencies.postgres = false;
    }
    if (dependencies.postgres) {
      try {
        const rows = await app.prisma.$queryRaw<Array<{ pending: bigint }>>`
          SELECT count(*) AS pending FROM _prisma_migrations WHERE finished_at IS NULL OR rolled_back_at IS NOT NULL`;
        const applied = await app.prisma.$queryRaw<Array<{ applied: bigint }>>`SELECT count(*) AS applied FROM _prisma_migrations`;
        dependencies.migrations = Number(rows[0]!.pending) === 0 && Number(applied[0]!.applied) > 0;
      } catch {
        dependencies.migrations = false;
      }
    }
    const redis = await redisHealthy();
    if (redis !== null) dependencies.redis = redis;

    const allOk = Object.values(dependencies).every(Boolean);
    reply.status(allOk ? 200 : 503);
    return { status: allOk ? ('ok' as const) : ('degraded' as const), dependencies };
  });

  app.get('/health/dependencies', { preHandler: [authenticate, authorize('ADMIN')] }, async () => ({
    safeBrowsing: { configured: Boolean(env.SAFE_BROWSING_API_KEY), breaker: breakers.safeBrowsing.snapshot() },
    virusTotal: { configured: Boolean(env.VIRUSTOTAL_API_KEY), breaker: breakers.virusTotal.snapshot(), quotaRemaining: virusTotalBudget.remaining() },
    whois: { configured: true, provider: 'RDAP', breaker: breakers.whois.snapshot() },
    claude: {
      configured: isAiConfigured(),
      model: env.ANTHROPIC_MODEL,
      underMonthlySpendCap: await isUnderSpendCap(app.prisma),
      breaker: breakers.claude.snapshot(),
    },
    googleAuth: { configured: isGoogleAuthConfigured },
    redis: { configured: Boolean(env.REDIS_URL), healthy: await redisHealthy() },
  }));

  // §28.2 — bearer METRICS_TOKEN for a scraper, otherwise an ADMIN JWT.
  app.get('/metrics', { config: { rateLimit: false } }, async (request, reply) => {
    if (!hasMetricsToken(request.headers.authorization)) {
      await authenticate(request, reply);
      await authorize('ADMIN')(request, reply);
    }
    reply.header('content-type', registry.contentType);
    return registry.metrics();
  });
}

function hasMetricsToken(header: string | undefined): boolean {
  if (!env.METRICS_TOKEN || !header?.startsWith('Bearer ')) return false;
  const expected = Buffer.from(env.METRICS_TOKEN);
  const actual = Buffer.from(header.slice(7));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
