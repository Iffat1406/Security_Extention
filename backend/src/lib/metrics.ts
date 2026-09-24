import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from '@prometheus-io/client';

/**
 * §28.2 metrics. One registry for the process, exposed at GET /metrics
 * (bearer METRICS_TOKEN, or an ADMIN JWT).
 *
 * Label values are always from fixed sets (service names, statuses, route
 * patterns) — never a domain, user id or URL, which would both leak data
 * and explode cardinality.
 */
export const registry = new Registry();
collectDefaultMetrics({ register: registry, prefix: 'guardtab_process_' });

export const metrics = {
  scanDuration: new Histogram({
    name: 'scan_duration_seconds',
    help: 'End-to-end POST /scans server time (§13 target: < 3s)',
    buckets: [0.1, 0.25, 0.5, 0.8, 1, 1.5, 2, 3, 5, 8],
    registers: [registry],
  }),
  scanTotal: new Counter({
    name: 'scan_total',
    help: 'Scans by terminal status — COMPLETED vs PARTIAL vs FAILED is the primary health signal',
    labelNames: ['status'] as const,
    registers: [registry],
  }),
  externalCallDuration: new Histogram({
    name: 'external_call_duration_seconds',
    help: 'Latency per external dependency',
    labelNames: ['service'] as const,
    buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 3, 6, 15],
    registers: [registry],
  }),
  externalCallTotal: new Counter({
    name: 'external_call_total',
    help: 'External calls by outcome (ok, error, timeout, circuit_open, skipped, cached)',
    labelNames: ['service', 'outcome'] as const,
    registers: [registry],
  }),
  externalQuotaRemaining: new Gauge({
    name: 'external_quota_remaining',
    help: 'Remaining budget in the current window, where the service has one',
    labelNames: ['service', 'window'] as const,
    registers: [registry],
  }),
  dbQueryDuration: new Histogram({
    name: 'db_query_duration_seconds',
    help: 'Prisma query duration (§13 target: < 50ms)',
    buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
    registers: [registry],
  }),
  cacheHitRatio: new Gauge({
    name: 'cache_hit_ratio',
    help: 'Backend dedup-cache effectiveness per service (extension cache is reported client-side)',
    labelNames: ['layer'] as const,
    registers: [registry],
  }),
  authFailures: new Counter({
    name: 'auth_failures_total',
    help: 'Authentication/authorisation failures — a spike means credential stuffing or a broken client',
    labelNames: ['reason'] as const,
    registers: [registry],
  }),
  rateLimitHits: new Counter({
    name: 'rate_limit_hits_total',
    help: 'Requests rejected by a rate limit',
    labelNames: ['route'] as const,
    registers: [registry],
  }),
  jobRuns: new Counter({
    name: 'job_runs_total',
    help: 'Scheduled job runs by outcome',
    labelNames: ['job', 'outcome'] as const,
    registers: [registry],
  }),
};

/** Running hit/miss tally used to publish cache_hit_ratio. */
const cacheTallies = new Map<string, { hits: number; total: number }>();
export function recordCacheLookup(layer: string, hit: boolean): void {
  const tally = cacheTallies.get(layer) ?? { hits: 0, total: 0 };
  tally.total++;
  if (hit) tally.hits++;
  cacheTallies.set(layer, tally);
  metrics.cacheHitRatio.set({ layer }, tally.hits / tally.total);
}
