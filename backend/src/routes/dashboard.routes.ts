import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import type { EvidenceItem, TrackerCheck } from '@guardtab/shared';
import { authenticate } from '../middleware/auth.middleware';

/**
 * §11 "Dashboard endpoints" + Phase 8. A read layer over the caller's own
 * scans — every query is filtered on the verified user id.
 *
 * Trends exclude PARTIAL scans (§24.3 "an outage in one dependency does not
 * distort a user's security history") and are grouped by engine version so
 * the chart can mark where scoring rules changed (§19.7).
 */
const daysQuery = z.object({ days: z.coerce.number().int().min(1).max(365).default(30) });

const dashboardRoutes: FastifyPluginAsyncZod = async (app) => {
  app.addHook('preHandler', authenticate);

  app.get('/dashboard/summary', { schema: { tags: ['dashboard'], querystring: daysQuery } }, async (request) => {
    const userId = request.authUser!.id;
    const since = new Date(Date.now() - request.query.days * 86_400_000);
    const where = { userId, scannedAt: { gte: since } };

    const [totalScans, averages, bands, recent] = await Promise.all([
      app.prisma.scanResult.count({ where }),
      app.prisma.scanResult.aggregate({
        where: { ...where, scanStatus: 'COMPLETED' },
        _avg: { securityScore: true, privacyScore: true, overallScore: true },
      }),
      app.prisma.scanResult.groupBy({ by: ['riskBand'], where, _count: { _all: true } }),
      app.prisma.scanResult.findMany({ where, select: { riskEvidence: true, passwordBreachData: true }, take: 2000, orderBy: { scannedAt: 'desc' } }),
    ]);

    const threatCounts = new Map<string, number>();
    const headerCounts = new Map<string, number>();
    let breachedPasswords = 0;
    for (const scan of recent) {
      const evidence = ((scan.riskEvidence as { evidence?: EvidenceItem[] } | null)?.evidence ?? []);
      for (const e of evidence) {
        if (e.category !== 'security') continue;
        if (e.signal.startsWith('MISSING_')) headerCounts.set(e.signal, (headerCounts.get(e.signal) ?? 0) + 1);
        else threatCounts.set(e.signal, (threatCounts.get(e.signal) ?? 0) + 1);
      }
      if ((scan.passwordBreachData as { isBreached?: boolean } | null)?.isBreached) breachedPasswords++;
    }
    const top = (m: Map<string, number>) =>
      [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([signal, count]) => ({ signal, count }));
    const round = (n: number | null) => (n === null ? null : Math.round(n));

    return {
      windowDays: request.query.days,
      totalScans,
      avgSecurityScore: round(averages._avg.securityScore),
      avgPrivacyScore: round(averages._avg.privacyScore),
      avgOverallScore: round(averages._avg.overallScore),
      bands: Object.fromEntries(bands.map((b) => [b.riskBand ?? 'NONE', b._count._all])),
      topThreats: top(threatCounts),
      topMissingHeaders: top(headerCounts),
      breachedPasswordWarnings: breachedPasswords,
    };
  });

  app.get('/dashboard/trends', { schema: { tags: ['dashboard'], querystring: daysQuery } }, async (request) => {
    const since = new Date(Date.now() - request.query.days * 86_400_000);
    const rows = await app.prisma.$queryRaw<
      Array<{ day: Date; engine: string | null; security: number | null; privacy: number | null; trackers: number | null; scans: bigint }>
    >(Prisma.sql`
      SELECT date_trunc('day', scanned_at) AS day,
             risk_engine_version AS engine,
             AVG(security_score)::float AS security,
             AVG(privacy_score)::float AS privacy,
             AVG(NULLIF(tracker_data->>'trackerCount', '')::int)::float AS trackers,
             COUNT(*) AS scans
      FROM scan_results
      WHERE user_id = ${request.authUser!.id}::uuid
        AND scanned_at >= ${since}
        AND scan_status = 'COMPLETED'
      GROUP BY 1, 2
      ORDER BY 1 ASC`);
    return {
      windowDays: request.query.days,
      points: rows.map((r) => ({
        day: r.day.toISOString().slice(0, 10),
        riskEngineVersion: r.engine,
        security: r.security === null ? null : Math.round(r.security),
        privacy: r.privacy === null ? null : Math.round(r.privacy),
        avgTrackers: r.trackers === null ? null : Math.round(r.trackers * 10) / 10,
        scans: Number(r.scans),
      })),
    };
  });

  app.get('/dashboard/trackers', { schema: { tags: ['dashboard'], querystring: daysQuery } }, async (request) => {
    const since = new Date(Date.now() - request.query.days * 86_400_000);
    const scans = await app.prisma.scanResult.findMany({
      where: { userId: request.authUser!.id, scannedAt: { gte: since }, trackerData: { not: Prisma.DbNull } },
      select: { trackerData: true, registrableDomain: true },
      take: 5000,
    });
    const counts = new Map<string, { name: string; category: string; count: number; sites: Set<string> }>();
    for (const scan of scans) {
      const data = scan.trackerData as TrackerCheck | null;
      for (const t of data?.trackers ?? []) {
        const entry = counts.get(t.name) ?? { name: t.name, category: t.category, count: 0, sites: new Set<string>() };
        entry.count++;
        entry.sites.add(scan.registrableDomain);
        counts.set(t.name, entry);
      }
    }
    return {
      trackers: [...counts.values()]
        .sort((a, b) => b.sites.size - a.sites.size || b.count - a.count)
        .slice(0, 50)
        .map((t) => ({ name: t.name, category: t.category, count: t.count, sites: t.sites.size })),
    };
  });

  // §11 "the user's 10 most recently scanned sites sorted by risk score" — now the deterministic overall score.
  app.get('/dashboard/riskiest-sites', { schema: { tags: ['dashboard'] } }, async (request) => {
    const recent = await app.prisma.scanResult.findMany({
      where: { userId: request.authUser!.id, overallScore: { not: null } },
      orderBy: { scannedAt: 'desc' },
      distinct: ['registrableDomain'],
      take: 10,
      select: { id: true, registrableDomain: true, overallScore: true, securityScore: true, privacyScore: true, riskBand: true, scannedAt: true },
    });
    return { sites: recent.sort((a, b) => (a.overallScore ?? 100) - (b.overallScore ?? 100)) };
  });
};

export default dashboardRoutes;
