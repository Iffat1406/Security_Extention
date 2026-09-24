import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { AppError } from '../lib/errors';
import { optionalAuthenticate } from '../middleware/auth.middleware';

/**
 * §22.5 public threat intelligence — "Aggregated across all users. No
 * individual browsing history is exposed." Domain-level fields only: no
 * user ids, no scan counts per user, no indicator evidence detail (that is
 * the ANALYST view under /admin).
 */
const windowQuery = z.object({
  days: z.coerce.number().int().min(1).max(90).default(7),
  limit: z.coerce.number().int().min(1).max(50).default(20),
});

const threatsRoutes: FastifyPluginAsyncZod = async (app) => {
  app.get(
    '/threats/top',
    { preHandler: optionalAuthenticate, schema: { tags: ['threat intelligence'], querystring: windowQuery } },
    async (request) => {
      const since = new Date(Date.now() - request.query.days * 86_400_000);
      const domains = await app.prisma.domain.findMany({
        where: { reputation: { in: ['MALICIOUS', 'SUSPICIOUS'] }, lastSeenAt: { gte: since }, isAllowlisted: false },
        orderBy: [{ reputationConfidence: 'desc' }, { lastSeenAt: 'desc' }],
        take: request.query.limit,
        select: {
          domain: true,
          reputation: true,
          reputationConfidence: true,
          indicators: { where: { suppressedAt: null }, select: { type: true } },
        },
      });
      return {
        windowDays: request.query.days,
        domains: domains.map((d) => ({
          domain: d.domain,
          reputation: d.reputation,
          confidence: Number(d.reputationConfidence),
          indicatorTypes: [...new Set(d.indicators.map((i) => i.type))],
        })),
      };
    }
  );

  app.get(
    '/threats/domain/:domain',
    { preHandler: optionalAuthenticate, schema: { tags: ['threat intelligence'], params: z.object({ domain: z.string().min(1).max(253) }) } },
    async (request) => {
      const domain = await app.prisma.domain.findUnique({
        where: { domain: request.params.domain.toLowerCase() },
        select: {
          domain: true,
          reputation: true,
          reputationConfidence: true,
          firstSeenAt: true,
          lastSeenAt: true,
          domainAgeDays: true,
          latestSecurityScore: true,
          indicators: { where: { suppressedAt: null }, select: { type: true, severity: true, lastDetectedAt: true } },
        },
      });
      if (!domain) throw new AppError('NOT_FOUND', 'No intelligence for that domain yet');
      return { ...domain, reputationConfidence: Number(domain.reputationConfidence) };
    }
  );

  app.get(
    '/threats/stats',
    { preHandler: optionalAuthenticate, schema: { tags: ['threat intelligence'], querystring: windowQuery.pick({ days: true }) } },
    async (request) => {
      const since = new Date(Date.now() - request.query.days * 86_400_000);
      const byType = await app.prisma.threatIndicator.groupBy({
        by: ['type'],
        where: { lastDetectedAt: { gte: since }, suppressedAt: null },
        _count: { _all: true },
      });
      const byReputation = await app.prisma.domain.groupBy({
        by: ['reputation'],
        where: { lastSeenAt: { gte: since } },
        _count: { _all: true },
      });
      return {
        windowDays: request.query.days,
        indicatorsByType: Object.fromEntries(byType.map((r) => [r.type, r._count._all])),
        domainsByReputation: Object.fromEntries(byReputation.map((r) => [r.reputation, r._count._all])),
      };
    }
  );
};

export default threatsRoutes;
