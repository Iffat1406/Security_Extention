import type { PrismaClient } from '@prisma/client';
import { hostMatchesDomain } from '@guardtab/shared';
import { env } from '../config/env';
import { writeAuditLog } from '../services/audit.service';
import { checkDomainAge } from '../services/external/whois.service';
import { recomputeDomainReputation } from '../services/reputation.service';
import { computeRisk } from '../risk-engine/engine';
import { engineInputFromRow } from '../services/scan.service';

/**
 * §28.5 scheduled jobs. Each one is idempotent, batched, returns the rows it
 * affected, and throws JobAbortedError instead of carrying on when it would
 * delete more than its safety threshold ("A job that deletes more than an
 * expected threshold aborts and alerts rather than continuing").
 *
 * Retention is enforced here, not by query filters (§29.1): data the policy
 * says is gone is actually deleted.
 */
export class JobAbortedError extends Error {
  constructor(job: string, affected: number, threshold: number) {
    super(`${job} aborted after ${affected} rows — exceeds the ${threshold}-row safety threshold`);
    this.name = 'JobAbortedError';
  }
}

export interface JobContext {
  prisma: PrismaClient;
  now: Date;
  log: { info: (obj: object, msg: string) => void; warn: (obj: object, msg: string) => void };
}

export interface JobDefinition {
  name: string;
  /** Cron expression, UTC. */
  schedule: string;
  run: (ctx: JobContext) => Promise<number>;
}

const BATCH = 5000;
const DAY_MS = 86_400_000;

/** Repeats a batched statement until it affects nothing, enforcing the safety threshold. */
async function inBatches(job: string, threshold: number, step: () => Promise<number>): Promise<number> {
  let total = 0;
  for (;;) {
    const affected = await step();
    total += affected;
    if (total > threshold) throw new JobAbortedError(job, total, threshold);
    if (affected < BATCH) return total;
  }
}

export const JOBS: JobDefinition[] = [
  {
    // "Delete scan_results past the user's retention window, in batches of 5,000".
    name: 'purge_expired_scans',
    schedule: '0 3 * * *',
    run: ({ prisma, now }) =>
      inBatches('purge_expired_scans', 2_000_000, () =>
        prisma.$executeRaw`
          WITH doomed AS (
            SELECT s.id
            FROM scan_results s
            LEFT JOIN user_settings us ON us.user_id = s.user_id
            WHERE NOT (COALESCE(us.settings, '{}'::jsonb) ? 'scanRetentionDays'
                       AND jsonb_typeof(us.settings->'scanRetentionDays') = 'null')   -- "forever"
              AND s.scanned_at < ${now}::timestamptz
                  - make_interval(days => COALESCE((us.settings->>'scanRetentionDays')::int, ${env.SCAN_RETENTION_DAYS}::int))
            LIMIT ${BATCH}
          )
          DELETE FROM scan_results WHERE id IN (SELECT id FROM doomed)`
      ),
  },
  {
    name: 'purge_expired_chats',
    schedule: '15 3 * * *',
    run: ({ prisma, now }) => {
      const cutoff = new Date(now.getTime() - env.CHAT_RETENTION_DAYS * DAY_MS);
      return inBatches('purge_expired_chats', 2_000_000, () =>
        prisma.$executeRaw`DELETE FROM scan_chats WHERE id IN (SELECT id FROM scan_chats WHERE created_at < ${cutoff} LIMIT ${BATCH})`
      );
    },
  },
  {
    // "Delete refresh_tokens past expiry plus a 7-day grace period". Revoked-but-unexpired
    // rows stay: reuse detection needs them to recognise a replayed token.
    name: 'purge_revoked_tokens',
    schedule: '0 * * * *',
    run: ({ prisma, now }) => {
      const cutoff = new Date(now.getTime() - env.TOKEN_GRACE_DAYS * DAY_MS);
      return inBatches('purge_revoked_tokens', 5_000_000, () =>
        prisma.$executeRaw`DELETE FROM refresh_tokens WHERE id IN (SELECT id FROM refresh_tokens WHERE expires_at < ${cutoff} LIMIT ${BATCH})`
      );
    },
  },
  {
    // "Remove any row that should never have persisted — a safety net, expected to delete nothing."
    name: 'purge_anonymous_data',
    schedule: '30 * * * *',
    run: async ({ prisma, log }) => {
      let affected = 0;
      // Paths stored while STORE_PATH=false (§17.2).
      if (!env.STORE_PATH) {
        affected += await prisma.$executeRaw`UPDATE scan_results SET path = NULL WHERE path IS NOT NULL`;
      }
      // Scans of a domain the user has since excluded (§23.2 — excluded pages are never stored).
      const withExclusions = await prisma.userSettings.findMany({
        where: { excludedDomains: { isEmpty: false } },
        select: { userId: true, excludedDomains: true },
      });
      for (const { userId, excludedDomains } of withExclusions) {
        const scans = await prisma.scanResult.findMany({ where: { userId }, select: { id: true, host: true } });
        const ids = scans.filter((s) => excludedDomains.some((d) => hostMatchesDomain(s.host, d))).map((s) => s.id);
        if (ids.length) affected += (await prisma.scanResult.deleteMany({ where: { id: { in: ids } } })).count;
      }
      if (affected > 0) log.warn({ affected }, 'purge_anonymous_data removed rows — the write-time guard missed something');
      return affected;
    },
  },
  {
    // "Apply decay and recompute domain confidence (§22.4)".
    name: 'recompute_reputation',
    schedule: '0 4 * * *',
    run: async ({ prisma, now }) => {
      const domains = await prisma.domain.findMany({
        where: { OR: [{ reputation: { not: 'UNKNOWN' } }, { indicators: { some: {} } }] },
        select: { id: true },
      });
      for (const { id } of domains) await recomputeDomainReputation(prisma, id, now);
      return domains.length;
    },
  },
  {
    // "Re-query WHOIS for domains whose cached age is older than 7 days, within quota."
    name: 'refresh_domain_age',
    schedule: '30 4 * * *',
    run: async ({ prisma, now }) => {
      const stale = await prisma.$queryRaw<Array<{ domain: string }>>`
        SELECT d.domain FROM domains d
        LEFT JOIN reputation_cache rc ON rc.cache_key = d.domain AND rc.service = 'WHOIS'
        WHERE d.last_seen_at > ${new Date(now.getTime() - 30 * DAY_MS)}
          AND (rc.checked_at IS NULL OR rc.checked_at < ${new Date(now.getTime() - 7 * DAY_MS)})
        ORDER BY d.last_seen_at DESC
        LIMIT 200`;
      let refreshed = 0;
      for (const { domain } of stale) {
        const outcome = await checkDomainAge(prisma, domain);
        if (outcome.status === 'OK') {
          await prisma.domain.update({ where: { domain }, data: { domainAgeDays: outcome.data.domainAgeDays } });
          refreshed++;
        }
      }
      return refreshed;
    },
  },
  {
    // §29.2 — "Execute deletions past the grace period", one transaction per user.
    name: 'finalise_account_deletions',
    schedule: '0 5 * * *',
    run: async ({ prisma, now }) => {
      const due = await prisma.user.findMany({
        where: { deletionRequestedAt: { lte: new Date(now.getTime() - env.DELETION_GRACE_DAYS * DAY_MS) } },
        select: { id: true },
        take: 500,
      });
      for (const { id } of due) await finaliseAccountDeletion(prisma, id);
      return due.length;
    },
  },
  {
    name: 'purge_audit_logs',
    schedule: '0 6 * * 0',
    run: ({ prisma, now }) => {
      const cutoff = new Date(now.getTime() - env.AUDIT_RETENTION_DAYS * DAY_MS);
      return inBatches('purge_audit_logs', 5_000_000, () =>
        prisma.$executeRaw`DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < ${cutoff} LIMIT ${BATCH})`
      );
    },
  },
  {
    // "Roll scan counts into a summary table so the dashboard does not scan raw history".
    // Recomputes yesterday and today, so a late run or a re-run converges on the same numbers.
    name: 'aggregate_daily_stats',
    schedule: '30 5 * * *',
    run: async ({ prisma, now }) => {
      const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      const days = [new Date(today.getTime() - DAY_MS), today];
      for (const day of days) {
        const next = new Date(day.getTime() + DAY_MS);
        const [row] = await prisma.$queryRaw<
          Array<{ total: bigint; completed: bigint; partial: bigint; failed: bigint; domains: bigint; security: number | null; privacy: number | null }>
        >`
          SELECT count(*) AS total,
                 count(*) FILTER (WHERE scan_status = 'COMPLETED') AS completed,
                 count(*) FILTER (WHERE scan_status = 'PARTIAL') AS partial,
                 count(*) FILTER (WHERE scan_status = 'FAILED') AS failed,
                 count(DISTINCT registrable_domain) AS domains,
                 avg(security_score) FILTER (WHERE scan_status = 'COMPLETED')::float AS security,
                 avg(privacy_score) FILTER (WHERE scan_status = 'COMPLETED')::float AS privacy
          FROM scan_results WHERE scanned_at >= ${day} AND scanned_at < ${next}`;
        const data = {
          scansTotal: Number(row!.total),
          scansCompleted: Number(row!.completed),
          scansPartial: Number(row!.partial),
          scansFailed: Number(row!.failed),
          uniqueDomains: Number(row!.domains),
          avgSecurityScore: row!.security,
          avgPrivacyScore: row!.privacy,
        };
        await prisma.dailyStat.upsert({ where: { date: day }, create: { date: day, ...data }, update: data });
      }
      return days.length;
    },
  },
  {
    // Not in §28.5: a scan left in SCANNING (the process died before its AI step
    // finished) is moved to the terminal state its checks already determined.
    name: 'finalise_stale_scans',
    schedule: '*/10 * * * *',
    run: async ({ prisma, now }) => {
      const stale = await prisma.scanResult.findMany({
        where: { scanStatus: 'SCANNING', startedAt: { lt: new Date(now.getTime() - 5 * 60_000) } },
        take: 1000,
      });
      for (const row of stale) {
        const { scanStatus } = computeRisk(engineInputFromRow(row));
        await prisma.scanResult.update({ where: { id: row.id }, data: { scanStatus, completedAt: now } });
      }
      return stale.length;
    },
  },
];

/**
 * §29.2 deletion order, one transaction: counters, feedback, then the user
 * row (chats, scans, settings and tokens go with it via ON DELETE CASCADE;
 * audit rows are anonymised by ON DELETE SET NULL, not erased).
 */
export async function finaliseAccountDeletion(prisma: PrismaClient, userId: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    // "Domain-level counters are decremented where the user contributed".
    const contributions = await tx.scanResult.groupBy({ by: ['registrableDomain'], where: { userId }, _count: { _all: true } });
    for (const c of contributions) {
      await tx.$executeRaw`
        UPDATE domains SET scan_count = GREATEST(scan_count - ${c._count._all}, 0),
                           unique_user_count = GREATEST(unique_user_count - 1, 0)
        WHERE domain = ${c.registrableDomain}`;
    }
    await tx.scanFeedback.deleteMany({ where: { userId } });
    await tx.user.update({ where: { id: userId }, data: { deletedAt: new Date() } });
    await tx.user.delete({ where: { id: userId } });
    await writeAuditLog(tx, { userId: null, action: 'ACCOUNT_DELETE', resourceType: 'user', resourceId: userId });
  });
}
