import type { FastifyInstance } from 'fastify';

/**
 * §28.3 "Health endpoints".
 *
 * GET /health/dependencies (Safe Browsing, VirusTotal, WHOIS, Claude
 * reachability + quota, ADMIN-only) is deferred — none of those services
 * exist until Phase 5 and Phase 7. Only /health and /health/ready are
 * meaningful in Phase 1.
 */
export default async function healthRoutes(app: FastifyInstance) {
  // Process-up check only — never inspects a dependency (§28.3).
  app.get('/health', async () => ({ status: 'ok' as const }));

  app.get('/health/ready', async (_request, reply) => {
    const dependencies = { postgres: false, migrations: false };

    try {
      await app.prisma.$queryRaw`SELECT 1`;
      dependencies.postgres = true;
    } catch {
      dependencies.postgres = false;
    }

    if (dependencies.postgres) {
      try {
        const rows = await app.prisma.$queryRaw<
          Array<{ finished_at: Date | null; rolled_back_at: Date | null }>
        >`SELECT finished_at, rolled_back_at FROM _prisma_migrations ORDER BY started_at DESC LIMIT 1`;
        dependencies.migrations = rows.length > 0 && rows[0]!.finished_at !== null && rows[0]!.rolled_back_at === null;
      } catch {
        dependencies.migrations = false;
      }
    }

    const allOk = Object.values(dependencies).every(Boolean);
    reply.status(allOk ? 200 : 503);
    return { status: allOk ? ('ok' as const) : ('degraded' as const), dependencies };
  });
}
