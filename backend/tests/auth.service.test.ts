import jwt from 'jsonwebtoken';
import { describe, expect, it } from 'vitest';
import { env } from '../src/config/env';
import { AppError } from '../src/lib/errors';
import {
  issueRefreshToken,
  rotateRefreshToken,
  signAccessToken,
  verifyAccessToken,
} from '../src/services/auth.service';
import { createTestUser, prisma } from './helpers/test-db';

describe('signAccessToken / verifyAccessToken — §18.3 "JWT forgery or manipulation"', () => {
  it('round-trips a valid token', async () => {
    const user = await createTestUser();
    const token = signAccessToken(user);
    expect(verifyAccessToken(token)).toEqual({ sub: user.id, role: user.role });
  });

  it('rejects a token signed with alg:none (§26.5 "JWT with alg set to none")', () => {
    // jsonwebtoken refuses to *sign* with none unless explicitly allowed —
    // construct the token by hand to simulate a forged one.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'attacker', role: 'ADMIN' })).toString('base64url');
    const forged = `${header}.${payload}.`;
    expect(() => verifyAccessToken(forged)).toThrow();
  });

  it('rejects a token with a tampered claim (§26.5 "tampered user_id claim")', async () => {
    const user = await createTestUser();
    const token = signAccessToken(user);
    const [header, , signature] = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'someone-else', role: 'ADMIN' })).toString(
      'base64url'
    );
    const tampered = `${header}.${tamperedPayload}.${signature}`;
    expect(() => verifyAccessToken(tampered)).toThrow();
  });

  it('rejects an expired token (§26.5 "Expired JWT")', () => {
    const expired = jwt.sign({ sub: 'x', role: 'USER' }, env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: -1,
    });
    expect(() => verifyAccessToken(expired)).toThrow();
  });

  it('rejects a token signed with a different algorithm', () => {
    const hs384Token = jwt.sign({ sub: 'x', role: 'USER' }, env.JWT_SECRET, { algorithm: 'HS384' });
    expect(() => verifyAccessToken(hs384Token)).toThrow();
  });
});

describe('rotateRefreshToken — §18.3/§26.5 refresh rotation + reuse detection', () => {
  it('rotates a valid token into a new one in the same family', async () => {
    const user = await createTestUser();
    const { raw, familyId } = await issueRefreshToken(prisma, user.id);

    const rotated = await rotateRefreshToken(prisma, raw);
    expect(rotated.user.id).toBe(user.id);
    expect(rotated.raw).not.toBe(raw);

    const rows = await prisma.refreshToken.findMany({ where: { familyId } });
    expect(rows).toHaveLength(2);
    expect(rows.filter((r) => r.revokedAt !== null)).toHaveLength(1);
  });

  it('replaying an already-rotated token revokes the whole family (§26.5)', async () => {
    const user = await createTestUser();
    const { raw, familyId } = await issueRefreshToken(prisma, user.id);
    const rotated = await rotateRefreshToken(prisma, raw); // legitimate rotation; `raw` is now spent

    await expect(rotateRefreshToken(prisma, raw)).rejects.toMatchObject({
      code: 'TOKEN_REUSE_DETECTED',
    } satisfies Partial<AppError>);

    const rows = await prisma.refreshToken.findMany({ where: { familyId } });
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);

    // Even the legitimately-rotated token is now unusable — the whole
    // family was burned by the replay, not just the replayed token.
    await expect(rotateRefreshToken(prisma, rotated.raw)).rejects.toMatchObject({
      code: 'TOKEN_REUSE_DETECTED',
    } satisfies Partial<AppError>);
  });

  it('writes a TOKEN_REUSE_DETECTED audit row on replay', async () => {
    const user = await createTestUser();
    const { raw } = await issueRefreshToken(prisma, user.id);
    await rotateRefreshToken(prisma, raw);
    await rotateRefreshToken(prisma, raw).catch(() => undefined);

    const auditRow = await prisma.auditLog.findFirst({
      where: { userId: user.id, action: 'TOKEN_REUSE_DETECTED' },
    });
    expect(auditRow).not.toBeNull();
  });

  it('rejects a token that does not exist', async () => {
    await expect(rotateRefreshToken(prisma, 'not-a-real-token')).rejects.toMatchObject({
      code: 'AUTH_INVALID',
    } satisfies Partial<AppError>);
  });

  it('rejects a refresh token belonging to a suspended account', async () => {
    const user = await createTestUser({ isActive: false });
    const { raw } = await issueRefreshToken(prisma, user.id);
    await expect(rotateRefreshToken(prisma, raw)).rejects.toMatchObject({
      code: 'AUTH_INVALID',
    } satisfies Partial<AppError>);
  });
});
