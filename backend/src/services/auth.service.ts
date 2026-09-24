import { createHash, randomBytes, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { PrismaClient, Role, User } from '@prisma/client';
import { env } from '../config/env';
import { AppError } from '../lib/errors';
import { writeAuditLog } from './audit.service';

/**
 * auth.service.ts — §9 "Authentication flow", §18.3 "JWT forgery or
 * manipulation" / "Refresh token reuse", §26.5 security test cases.
 *
 * Pure DB + token logic, deliberately independent of the actual Google
 * OAuth handshake (that lives in plugins/auth.ts + routes/auth.routes.ts)
 * so it can be unit- and integration-tested without a live Google round trip.
 */

// Explicit algorithm pinning (§18.3 "JWT forgery or manipulation ... alg:none,
// tampered claims") — a token signed with a different algorithm, or none at
// all, is rejected before signature verification even runs.
const JWT_ALGORITHM = 'HS256' as const;

export interface AccessTokenPayload {
  sub: string;
  role: Role;
  /** Seconds since epoch of the actual Google sign-in (OIDC `auth_time`). */
  authTime: number;
}

/**
 * @param authenticatedAt When the user actually signed in with Google. A
 *   refresh keeps the original value, so `auth_time` answers "how recently
 *   did a human authenticate?" rather than "how recently was a token minted?"
 *   — the question the export endpoint needs answered (§18.3).
 */
export function signAccessToken(user: Pick<User, 'id' | 'role'>, authenticatedAt: Date = new Date()): string {
  return jwt.sign(
    { sub: user.id, role: user.role, auth_time: Math.floor(authenticatedAt.getTime() / 1000) },
    env.JWT_SECRET,
    { algorithm: JWT_ALGORITHM, expiresIn: env.JWT_ACCESS_TTL as jwt.SignOptions['expiresIn'] }
  );
}

/** Throws on any invalid token (bad signature, wrong/missing alg, expired,
 * malformed payload) — callers should treat every failure as AUTH_INVALID. */
export function verifyAccessToken(token: string): AccessTokenPayload {
  const decoded = jwt.verify(token, env.JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  if (typeof decoded === 'string' || typeof decoded.sub !== 'string' || typeof decoded.role !== 'string') {
    throw new Error('Malformed access token payload');
  }
  const authTime = typeof decoded.auth_time === 'number' ? decoded.auth_time : (decoded.iat ?? 0);
  return { sub: decoded.sub, role: decoded.role as Role, authTime };
}

const REFRESH_TOKEN_BYTES = 48;

function generateRawRefreshToken(): string {
  return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
}

/** §13 "Refresh tokens hashed in DB ... only its SHA-256 hash is stored". */
function hashRefreshToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

function refreshExpiry(): Date {
  return new Date(Date.now() + env.JWT_REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000);
}

export interface IssuedRefreshToken {
  raw: string;
  familyId: string;
}

/** Issues a brand-new refresh token family — used at login only. Every
 * token later produced by rotating this one keeps the same familyId. */
export async function issueRefreshToken(
  prisma: PrismaClient,
  userId: string,
  authenticatedAt: Date = new Date()
): Promise<IssuedRefreshToken> {
  const raw = generateRawRefreshToken();
  const familyId = randomUUID();
  await prisma.refreshToken.create({
    data: { userId, tokenHash: hashRefreshToken(raw), familyId, authenticatedAt, expiresAt: refreshExpiry() },
  });
  return { raw, familyId };
}

export interface RotatedRefreshToken {
  user: User;
  raw: string;
  authenticatedAt: Date;
}

type RotationOutcome =
  | { kind: 'not_found' }
  | { kind: 'reuse' }
  | { kind: 'expired' }
  | { kind: 'inactive' }
  | { kind: 'rotated'; user: User; raw: string; authenticatedAt: Date };

/**
 * §18.3/§26.5 refresh rotation with reuse detection. A valid refresh
 * exchanges the presented token for a new one in the same family and
 * revokes the old one (one-time use). Presenting a token that is already
 * revoked means it was already used or stolen — the entire family is
 * revoked and the caller is forced to re-login (§26.5 "Refresh token
 * replayed after rotation" -> 401 TOKEN_REUSE_DETECTED; the whole family
 * is revoked").
 *
 * The revoke-and-audit side effects for the reuse case must survive even
 * though the overall call throws — so the transaction always commits
 * (returning an outcome tag) and the corresponding AppError is thrown
 * afterward, outside the transaction. Throwing inside an interactive
 * Prisma transaction rolls it back, which would silently undo the very
 * revocation this function exists to perform.
 */
export async function rotateRefreshToken(prisma: PrismaClient, rawToken: string): Promise<RotatedRefreshToken> {
  const tokenHash = hashRefreshToken(rawToken);

  const outcome = await prisma.$transaction(async (tx): Promise<RotationOutcome> => {
    const existing = await tx.refreshToken.findUnique({ where: { tokenHash }, include: { user: true } });
    if (!existing) {
      return { kind: 'not_found' };
    }

    if (existing.revokedAt) {
      await tx.refreshToken.updateMany({
        where: { familyId: existing.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await writeAuditLog(tx, {
        userId: existing.userId,
        action: 'TOKEN_REUSE_DETECTED',
        resourceType: 'token',
        resourceId: existing.id,
      });
      return { kind: 'reuse' };
    }

    if (existing.expiresAt.getTime() < Date.now()) {
      return { kind: 'expired' };
    }
    if (!existing.user.isActive) {
      return { kind: 'inactive' };
    }

    const raw = generateRawRefreshToken();
    await tx.refreshToken.update({ where: { id: existing.id }, data: { revokedAt: new Date() } });
    await tx.refreshToken.create({
      data: {
        userId: existing.userId,
        tokenHash: hashRefreshToken(raw),
        familyId: existing.familyId,
        authenticatedAt: existing.authenticatedAt,
        expiresAt: refreshExpiry(),
      },
    });

    return { kind: 'rotated', user: existing.user, raw, authenticatedAt: existing.authenticatedAt };
  });

  switch (outcome.kind) {
    case 'not_found':
      throw new AppError('AUTH_INVALID', 'Refresh token not recognised');
    case 'reuse':
      throw new AppError('TOKEN_REUSE_DETECTED', 'Refresh token was replayed after rotation; session revoked');
    case 'expired':
      throw new AppError('AUTH_INVALID', 'Refresh token has expired');
    case 'inactive':
      throw new AppError('AUTH_INVALID', 'Account is not active');
    case 'rotated':
      return { user: outcome.user, raw: outcome.raw, authenticatedAt: outcome.authenticatedAt };
  }
}

/** Used by logout — revokes only the presented token (not necessarily the
 * whole family; logging out on one device shouldn't sign out every device). */
export async function revokeRefreshTokenByRaw(prisma: PrismaClient, rawToken: string): Promise<void> {
  const tokenHash = hashRefreshToken(rawToken);
  await prisma.refreshToken.updateMany({ where: { tokenHash, revokedAt: null }, data: { revokedAt: new Date() } });
}

/** Account suspension (§21.4), deletion requests (§29.2) and "sign out all devices" (§29.4). */
export async function revokeAllUserRefreshTokens(prisma: PrismaClient, userId: string): Promise<void> {
  await prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
}
