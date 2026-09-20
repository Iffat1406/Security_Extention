import { z } from 'zod';

/**
 * Validated process environment. Only variables actually consumed by
 * Phase 1 and Phase 2 are required here — later phases extend this schema
 * when they introduce the env vars they need (see .env.example for the
 * full list).
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),

  // §13 "JWT signed with strong secret ... at least 32 random characters".
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters (§13)'),
  JWT_ACCESS_TTL: z.string().default('1h'),
  JWT_REFRESH_TTL_DAYS: z.coerce.number().int().positive().default(30),

  // Signs the HttpOnly refresh-token cookie — deliberately separate from
  // JWT_SECRET so rotating one never invalidates the other.
  COOKIE_SECRET: z.string().min(32, 'COOKIE_SECRET must be at least 32 characters'),

  // §28.4 "ip_hash ... SHA-256 of the IP with a server-side salt".
  AUDIT_IP_HASH_SALT: z.string().min(16, 'AUDIT_IP_HASH_SALT must be at least 16 characters'),

  GOOGLE_CLIENT_ID: z.string().min(1, 'GOOGLE_CLIENT_ID is required'),
  GOOGLE_CLIENT_SECRET: z.string().min(1, 'GOOGLE_CLIENT_SECRET is required'),
  GOOGLE_CALLBACK_URL: z.string().url().default('http://localhost:3000/api/v1/auth/google/callback'),
});

export type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // Fail fast and loud — a misconfigured env must never start the server
    // silently with a wrong default.
    console.error('Invalid environment configuration:', parsed.error.flatten().fieldErrors);
    throw new Error('Invalid environment configuration');
  }
  return parsed.data;
}

export const env = loadEnv();
