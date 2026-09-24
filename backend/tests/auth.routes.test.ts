import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { issueRefreshToken, signAccessToken } from '../src/services/auth.service';
import { createTestUser, prisma } from './helpers/test-db';

const REFRESH_COOKIE_NAME = 'guardtab_rt';

describe('§11 Authentication endpoints (excluding the live Google handshake)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /api/v1/auth/me', () => {
    it('rejects a missing bearer token', async () => {
      const response = await app.inject({ method: 'GET', url: '/api/v1/auth/me' });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.code).toBe('AUTH_REQUIRED');
    });

    it('rejects a malformed/invalid token', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { authorization: 'Bearer not-a-real-jwt' },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.code).toBe('AUTH_INVALID');
    });

    it('returns the caller profile for a valid token — §32 Phase 2 milestone', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(200);
      // §11's { id, email, displayName, avatarUrl }, plus role (the dashboard
      // shows admin navigation from it) and any pending deletion (§29.2).
      expect(response.json()).toEqual({
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
        role: 'USER',
        deletionRequestedAt: null,
      });
    });

    it('rejects a token for a suspended account even though the signature is valid', async () => {
      const user = await createTestUser({ isActive: false });
      const token = signAccessToken(user);
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.code).toBe('AUTH_INVALID');
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    it('rejects a missing refresh cookie', async () => {
      const response = await app.inject({ method: 'POST', url: '/api/v1/auth/refresh' });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.code).toBe('AUTH_REQUIRED');
    });

    it('rejects a cookie that fails signature verification', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=not-signed-by-us` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.code).toBe('AUTH_INVALID');
    });

    it('rotates a valid refresh cookie and returns a new access token', async () => {
      const user = await createTestUser();
      const { raw } = await issueRefreshToken(prisma, user.id);
      const signed = app.signCookie(raw);

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${signed}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toHaveProperty('accessToken');
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('§26.5 "Refresh token replayed after rotation" -> 401 TOKEN_REUSE_DETECTED', async () => {
      const user = await createTestUser();
      const { raw } = await issueRefreshToken(prisma, user.id);
      const signed = app.signCookie(raw);

      const first = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${signed}` },
      });
      expect(first.statusCode).toBe(200);

      const replay = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${signed}` },
      });
      expect(replay.statusCode).toBe(401);
      expect(replay.json().error.code).toBe('TOKEN_REUSE_DETECTED');
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('requires authentication', async () => {
      const response = await app.inject({ method: 'POST', url: '/api/v1/auth/logout' });
      expect(response.statusCode).toBe(401);
    });

    it('revokes the presented refresh token and clears the cookie', async () => {
      const user = await createTestUser();
      const accessToken = signAccessToken(user);
      const { raw } = await issueRefreshToken(prisma, user.id);
      const signed = app.signCookie(raw);

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { authorization: `Bearer ${accessToken}`, cookie: `${REFRESH_COOKIE_NAME}=${signed}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ success: true });

      const refreshAttempt = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${signed}` },
      });
      expect(refreshAttempt.statusCode).toBe(401);
    });
  });
});
