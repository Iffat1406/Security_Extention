import { createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { Queue, Worker } from 'bullmq';
import type { FastifyBaseLogger } from 'fastify';
import cron from 'node-cron';
import { env } from '../config/env';
import { metrics } from '../lib/metrics';
import { getRedis } from '../lib/redis';
import { JOBS, JobAbortedError, type JobDefinition } from './definitions';

/**
 * §28.5 "Jobs run as node-cron inside the API process until Phase 10, then
 * move to BullMQ with Redis so they survive restarts and can be observed."
 * Both are supported: BullMQ when REDIS_URL is set, node-cron otherwise.
 *
 * Either way every run takes a PostgreSQL advisory lock keyed on the job
 * name, so two API instances can never run the same job at once.
 */
function lockKey(name: string): bigint {
  return createHash('sha256').update(`guardtab-job:${name}`).digest().readBigInt64BE(0);
}

export async function runJob(prisma: PrismaClient, log: FastifyBaseLogger, job: JobDefinition, now = new Date()): Promise<number | null> {
  const key = lockKey(job.name);
  const started = Date.now();
  // Prisma pools connections, so a session-level lock and its unlock could
  // land on different connections and leave the job locked forever. Instead
  // the lock is transaction-scoped and held by one open transaction for the
  // job's duration; it is released automatically when that transaction ends.
  // The job's own queries use the normal client and are not part of it.
  return prisma.$transaction(
    async (tx) => {
      const locked = await tx.$queryRaw<Array<{ ok: boolean }>>`SELECT pg_try_advisory_xact_lock(${key}) AS ok`;
      if (!locked[0]?.ok) {
        log.info({ job: job.name }, 'job skipped — another instance holds its lock');
        metrics.jobRuns.inc({ job: job.name, outcome: 'skipped' });
        return null;
      }
      try {
        const affected = await job.run({ prisma, now, log });
        log.info({ job: job.name, affected, durationMs: Date.now() - started }, 'job completed');
        metrics.jobRuns.inc({ job: job.name, outcome: 'ok' });
        return affected;
      } catch (error) {
        const aborted = error instanceof JobAbortedError;
        log.error(
          { job: job.name, durationMs: Date.now() - started, err: error instanceof Error ? error.message : 'unknown' },
          aborted ? 'job ABORTED at safety threshold' : 'job failed'
        );
        metrics.jobRuns.inc({ job: job.name, outcome: aborted ? 'aborted' : 'error' });
        return null;
      }
    },
    { maxWait: 10_000, timeout: 60 * 60 * 1000 }
  );
}

export interface Scheduler {
  stop(): Promise<void>;
}

export async function startScheduler(prisma: PrismaClient, log: FastifyBaseLogger): Promise<Scheduler | null> {
  if (!env.JOBS_ENABLED || env.NODE_ENV === 'test') return null;
  const redis = getRedis();

  if (redis) {
    const connection = redis.duplicate();
    const queue = new Queue('guardtab-jobs', { connection });
    for (const job of JOBS) {
      await queue.upsertJobScheduler(job.name, { pattern: job.schedule, tz: 'UTC' }, { name: job.name, opts: { removeOnComplete: 100, removeOnFail: 500 } });
    }
    const worker = new Worker(
      'guardtab-jobs',
      async (bullJob) => {
        const job = JOBS.find((j) => j.name === bullJob.name);
        if (job) await runJob(prisma, log, job);
      },
      { connection: redis.duplicate(), concurrency: 1 }
    );
    log.info({ jobs: JOBS.length }, 'scheduled jobs registered on BullMQ');
    return {
      stop: async () => {
        await worker.close();
        await queue.close();
        await connection.quit().catch(() => undefined);
      },
    };
  }

  const tasks = JOBS.map((job) =>
    cron.schedule(job.schedule, () => void runJob(prisma, log, job), { timezone: 'UTC', name: job.name, noOverlap: true })
  );
  log.info({ jobs: JOBS.length }, 'scheduled jobs registered on node-cron');
  return {
    stop: async () => {
      for (const task of tasks) await task.stop();
    },
  };
}
