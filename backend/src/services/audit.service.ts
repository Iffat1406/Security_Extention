import { createHash } from 'node:crypto';
import { Prisma, type PrismaClient } from '@prisma/client';
import { env } from '../config/env';

/** Accepts either the top-level client or an interactive-transaction client
 * so a caller can write an audit row atomically with the change it describes. */
type Db = PrismaClient | Prisma.TransactionClient;

/** §28.4 "ip_hash ... SHA-256 of the IP with a server-side salt. Never the
 * raw address." The salt keeps the hash from being brute-forced back to an
 * IP by an attacker who only has the database. */
export function hashIp(ip: string): string {
  return createHash('sha256').update(`${env.AUDIT_IP_HASH_SALT}:${ip}`).digest('hex');
}

/** The fixed event vocabulary from §28.4. Kept open-ended (string) rather
 * than a Prisma enum so a new action doesn't require a migration — but
 * every call site should use one of these names. */
export type AuditAction =
  | 'LOGIN'
  | 'LOGOUT'
  | 'TOKEN_REFRESH'
  | 'TOKEN_REUSE_DETECTED'
  | 'ACCOUNT_EXPORT'
  | 'ACCOUNT_DELETE_REQUESTED'
  | 'ACCOUNT_DELETE'
  | 'SETTINGS_UPDATE'
  | 'EXCLUSION_ADD'
  | 'EXCLUSION_REMOVE'
  | 'SCAN_DELETE'
  | 'HISTORY_PURGE'
  | 'FEEDBACK_SUBMIT'
  | 'ADMIN_ROLE_CHANGE'
  | 'ADMIN_SUSPEND'
  | 'ADMIN_INDICATOR_OVERRIDE'
  | 'ADMIN_FEEDBACK_RESOLVE'
  | 'ADMIN_ALLOWLIST_CHANGE'
  | 'FORBIDDEN_ACCESS_ATTEMPT'
  /** §22.4 "Every reputation transition ... writes an audit row with the inputs that caused it". */
  | 'REPUTATION_CHANGE'
  /** §21.2 ANALYST "Propose" an indicator override — recorded for an ADMIN to act on. */
  | 'ANALYST_OVERRIDE_PROPOSAL'
  | 'SESSIONS_REVOKED';

export interface AuditLogInput {
  userId?: string | null;
  action: AuditAction;
  /** user | scan | domain | indicator | settings | token (§28.4) */
  resourceType?: string | null;
  resourceId?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
  /** Before/after values for role changes and overrides. Never PII (§28.4). */
  metadata?: Record<string, unknown> | null;
}

/** Audit rows are append-only (§28.4) — nothing in this codebase updates or
 * deletes one; retention is a cleanup job's responsibility (Phase 11). */
export async function writeAuditLog(db: Db, input: AuditLogInput): Promise<void> {
  await db.auditLog.create({
    data: {
      userId: input.userId ?? null,
      action: input.action,
      resourceType: input.resourceType ?? null,
      resourceId: input.resourceId ?? null,
      ipHash: input.ipHash ?? null,
      // Truncated per §28.4 "user_agent ... Truncated".
      userAgent: input.userAgent ? input.userAgent.slice(0, 255) : null,
      metadata: input.metadata ? (input.metadata as Prisma.InputJsonObject) : undefined,
    },
  });
}
