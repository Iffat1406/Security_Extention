import fastifyRateLimit from '@fastify/rate-limit';
import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { hashIp } from '../services/audit.service';
import { verifyAccessToken } from '../services/auth.service';
import { AppError } from './errors';
import { metrics } from './metrics';
import { getRedis } from './redis';

/**
 * rate-limit.ts — §18.3 "Rate-limit bypass: Limits keyed on user_id and on
 * hashed IP; global per-endpoint ceiling; 429 with Retry-After".
 *
 * The key is derived from the bearer token itself (a cheap HMAC check) so
 * it doesn't depend on hook ordering with `authenticate`. Anonymous callers
 * are keyed by a salted hash of their IP — raw IPs never reach a counter
 * key, a log line or Redis.
 */
export function rateLimitKey(request: FastifyRequest): string {
  const header = request.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      return `u:${verifyAccessToken(header.slice(7)).sub}`;
    } catch {
      /* invalid token -> fall through to IP; authenticate will reject it anyway */
    }
  }
  return `ip:${hashIp(request.ip)}`;
}

/** Per-route limits. Numbers from §26.5 / §23.3 / §24.4 / §22.4 where the spec gives one. */
export const LIMITS = {
  /** Default ceiling for any route without its own entry. */
  global: { max: 300, timeWindow: '1 minute' },
  /** §26.5 "501 scan requests in one hour from one account -> 429". */
  scanCreate: { max: 500, timeWindow: '1 hour' },
  scanUpdate: { max: 1000, timeWindow: '1 hour' },
  auth: { max: 30, timeWindow: '1 minute' },
  /** §21.3 "Admin endpoints are rate-limited more tightly than user endpoints". */
  admin: { max: 60, timeWindow: '1 minute' },
  /** §29.2 "The deletion endpoint is rate-limited". */
  accountDeletion: { max: 5, timeWindow: '1 hour' },
  settingsWrite: { max: 60, timeWindow: '1 minute' },
} as const;

/** Buckets checked inside a handler, where the limit depends on the body (a rescan flag) or is per-day. */
export const BUCKETS = {
  /** §23.3 "Rescan ... is rate-limited to 10 per hour per user". */
  rescan: { max: 10, timeWindow: 60 * 60 * 1000 },
  /** §24.4 "Per-user rate limit: 30 messages/hour". */
  chat: { max: 30, timeWindow: 60 * 60 * 1000 },
  /** §22.4 "20 feedback submissions per user per day". */
  feedback: { max: 20, timeWindow: 24 * 60 * 60 * 1000 },
} as const;
export type BucketName = keyof typeof BUCKETS;

declare module 'fastify' {
  interface FastifyInstance {
    checkBucket(request: FastifyRequest, bucket: BucketName): Promise<void>;
  }
}

export default fp(
  async function rateLimitPlugin(app: FastifyInstance) {
    const redis = getRedis();
    await app.register(fastifyRateLimit, {
      global: true,
      ...LIMITS.global,
      ...(redis ? { redis, nameSpace: 'guardtab-rl-' } : {}),
      keyGenerator: rateLimitKey,
      // Thrown -> the §25.5 error handler renders the envelope; the plugin has already set Retry-After.
      errorResponseBuilder: (request, context) => {
        metrics.rateLimitHits.inc({ route: request.routeOptions?.url ?? 'unknown' });
        return new AppError('RATE_LIMITED', 'Too many requests', {
          retryAfter: Math.ceil(context.ttl / 1000),
        });
      },
    });

    const checkers = new Map<BucketName, ReturnType<FastifyInstance['createRateLimit']>>();
    for (const [name, config] of Object.entries(BUCKETS) as Array<[BucketName, (typeof BUCKETS)[BucketName]]>) {
      checkers.set(
        name,
        app.createRateLimit({ max: config.max, timeWindow: config.timeWindow, keyGenerator: (req) => `${name}:${rateLimitKey(req)}` })
      );
    }

    app.decorate('checkBucket', async (request: FastifyRequest, bucket: BucketName) => {
      const result = await checkers.get(bucket)!(request);
      if (!result.isAllowed && result.isExceeded) {
        metrics.rateLimitHits.inc({ route: `bucket:${bucket}` });
        throw new AppError('RATE_LIMITED', `Too many ${bucket} requests`, { retryAfter: result.ttlInSeconds });
      }
    });
  },
  { name: 'rate-limit-plugin' }
);
