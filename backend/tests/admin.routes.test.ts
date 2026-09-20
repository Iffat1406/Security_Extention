import { randomUUID } from 'node:crypto';
import { Role } from '@prisma/client';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { issueRefreshToken, signAccessToken } from '../src/services/auth.service';
import { createTestUser, prisma } from './helpers/test-db';

describe('§21 RBAC & Admin Architecture', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('§32 Phase 2 milestone: an admin route rejects a USER token', async () => {
    const user = await createTestUser({ role: Role.USER });
    const token = signAccessToken(user);

    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/users',
      headers: { authorization: `Bearer ${token}` },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe('FORBIDDEN');

    // §21.3 "403 FORBIDDEN on failure — logged to audit_logs".
    const auditRow = await prisma.auditLog.findFirst({
      where: { userId: user.id, action: 'FORBIDDEN_ACCESS_ATTEMPT' },
      orderBy: { createdAt: 'desc' },
    });
    expect(auditRow).not.toBeNull();
  });

  it('an ANALYST token is also rejected by an ADMIN-only route (§21.2 permission matrix)', async () => {
    const analyst = await createTestUser({ role: Role.ANALYST });
    const token = signAccessToken(analyst);

    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/users',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.statusCode).toBe(403);
  });

  it('requires authentication before authorization', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/v1/admin/users' });
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe('AUTH_REQUIRED');
  });

  describe('as an ADMIN', () => {
    it('lists users without emails in the list view (§21.4)', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      await createTestUser(); // ensure at least one more row exists
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/users',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(200);

      const body = response.json() as { users: Record<string, unknown>[]; total: number; page: number };
      expect(Array.isArray(body.users)).toBe(true);
      expect(body.users.length).toBeGreaterThan(0);
      for (const row of body.users) {
        expect(row).not.toHaveProperty('email');
        expect(row).toHaveProperty('scanCount');
      }
    });

    it('returns single-user administrative detail', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      const target = await createTestUser();
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/admin/users/${target.id}`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ id: target.id, email: target.email });
    });

    it('returns 404 for a non-existent user id (never leaks existence via a different code)', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/admin/users/${randomUUID()}`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(404);
    });

    it('changes a role and writes an audit row with before/after (§21.4, §28.4)', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      const target = await createTestUser({ role: Role.USER });
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/users/${target.id}/role`,
        headers: { authorization: `Bearer ${token}` },
        payload: { role: 'ANALYST' },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ id: target.id, role: 'ANALYST' });

      const updated = await prisma.user.findUniqueOrThrow({ where: { id: target.id } });
      expect(updated.role).toBe(Role.ANALYST);

      const auditRow = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_ROLE_CHANGE', resourceId: target.id },
        orderBy: { createdAt: 'desc' },
      });
      expect(auditRow?.metadata).toMatchObject({ before: 'USER', after: 'ANALYST' });
      expect(auditRow?.userId).toBe(admin.id);
    });

    it('rejects an invalid role value', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      const target = await createTestUser();
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/users/${target.id}/role`,
        headers: { authorization: `Bearer ${token}` },
        payload: { role: 'SUPERUSER' },
      });
      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe('VALIDATION_ERROR');
    });

    it('suspends a user: deactivates the account and revokes every refresh token (§21.4)', async () => {
      const admin = await createTestUser({ role: Role.ADMIN });
      const target = await createTestUser({ role: Role.USER });
      await issueRefreshToken(prisma, target.id);
      await issueRefreshToken(prisma, target.id);
      const token = signAccessToken(admin);

      const response = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/users/${target.id}/suspend`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ success: true });

      const updated = await prisma.user.findUniqueOrThrow({ where: { id: target.id } });
      expect(updated.isActive).toBe(false);

      const tokens = await prisma.refreshToken.findMany({ where: { userId: target.id } });
      expect(tokens.length).toBeGreaterThan(0);
      expect(tokens.every((t) => t.revokedAt !== null)).toBe(true);

      const auditRow = await prisma.auditLog.findFirst({
        where: { action: 'ADMIN_SUSPEND', resourceId: target.id },
      });
      expect(auditRow).not.toBeNull();
    });
  });
});
