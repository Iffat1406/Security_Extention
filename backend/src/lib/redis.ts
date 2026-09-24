import { Redis } from 'ioredis';
import { env } from '../config/env';

/**
 * Optional Redis (§6.2 "Cache + queue"). When REDIS_URL is unset GuardTab
 * runs entirely on PostgreSQL + in-process state: rate-limit counters are
 * per-instance and jobs run on node-cron. Set it once there is more than
 * one API instance.
 */
let client: Redis | null = null;

export function getRedis(): Redis | null {
  if (!env.REDIS_URL) return null;
  client ??= new Redis(env.REDIS_URL, { maxRetriesPerRequest: null, enableOfflineQueue: false, lazyConnect: false });
  return client;
}

export async function redisHealthy(): Promise<boolean | null> {
  const redis = getRedis();
  if (!redis) return null;
  try {
    return (await redis.ping()) === 'PONG';
  } catch {
    return false;
  }
}

export async function closeRedis(): Promise<void> {
  if (client) {
    await client.quit().catch(() => undefined);
    client = null;
  }
}
