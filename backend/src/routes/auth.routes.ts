import type { FastifyReply, FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import type { Profile } from 'passport-google-oauth20';
import { z } from 'zod';
import { AUTH_CLIENTS, type AuthTokenResponse } from '@guardtab/shared';
import { env, isGoogleAuthConfigured } from '../config/env';
import { AppError } from '../lib/errors';
import { LIMITS } from '../lib/rate-limit';
import { authenticate } from '../middleware/auth.middleware';
import { fastifyPassport } from '../plugins/auth';
import { hashIp, writeAuditLog } from '../services/audit.service';
import {
  issueRefreshToken,
  revokeAllUserRefreshTokens,
  revokeRefreshTokenByRaw,
  rotateRefreshToken,
  signAccessToken,
} from '../services/auth.service';
import { OAUTH_NONCE_COOKIE, createOAuthState, tokenRedirectTarget, verifyOAuthState } from '../services/oauth-state.service';

/**
 * §11 "Authentication endpoints" + §9 "Authentication flow".
 *
 * The refresh cookie is HttpOnly, SameSite=Strict, Secure in production and
 * scoped to /api/v1/auth, so only /auth/refresh and /auth/logout ever see
 * it (§18.3 "CSRF on cookie endpoints").
 */
export const REFRESH_COOKIE_NAME = 'guardtab_rt';
const REFRESH_COOKIE_PATH = '/api/v1/auth';

function setRefreshCookie(reply: FastifyReply, rawToken: string): void {
  reply.setCookie(REFRESH_COOKIE_NAME, rawToken, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    signed: true,
    path: REFRESH_COOKIE_PATH,
    maxAge: env.JWT_REFRESH_TTL_DAYS * 24 * 60 * 60,
  });
}

function clearRefreshCookie(reply: FastifyReply): void {
  reply.clearCookie(REFRESH_COOKIE_NAME, { path: REFRESH_COOKIE_PATH });
}

function requireGoogle(): void {
  if (!isGoogleAuthConfigured) {
    throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', 'Google sign-in is not configured on this server', { reason: 'NOT_CONFIGURED' });
  }
}

function readRefreshCookie(request: FastifyRequest): string | null {
  const raw = request.cookies[REFRESH_COOKIE_NAME];
  if (!raw) return null;
  const unsigned = request.unsignCookie(raw);
  return unsigned.valid && unsigned.value ? unsigned.value : null;
}

const authRoutes: FastifyPluginAsyncZod = async (app) => {
  // Steps 1–3 of §9: redirect to Google's consent screen with a signed state.
  app.get(
    '/auth/google',
    {
      config: { rateLimit: LIMITS.auth },
      schema: { tags: ['auth'], querystring: z.object({ client: z.enum(AUTH_CLIENTS).optional() }) },
    },
    async (request, reply) => {
      requireGoogle();
      const { state, nonce } = createOAuthState(request.query.client ?? null);
      // SameSite=Lax (not Strict): the cookie must come back on Google's
      // top-level redirect to the callback, which is a cross-site navigation.
      reply.setCookie(OAUTH_NONCE_COOKIE, nonce, {
        httpOnly: true,
        secure: env.NODE_ENV === 'production',
        sameSite: 'lax',
        signed: true,
        path: '/api/v1/auth/google',
        maxAge: 10 * 60,
      });
      const handler = fastifyPassport.authenticate('google', { session: false, scope: ['profile', 'email'], state });
      await handler.call(app, request, reply);
      return reply;
    }
  );

  // Steps 4–6: verify state, find-or-create the user, issue tokens, hand them back.
  app.get('/auth/google/callback', { config: { rateLimit: LIMITS.auth }, schema: { tags: ['auth'] } }, async (request, reply) => {
    requireGoogle();
    const query = request.query as { state?: string };
    const rawNonce = request.cookies[OAUTH_NONCE_COOKIE];
    const unsignedNonce = rawNonce ? request.unsignCookie(rawNonce) : null;
    const verified = verifyOAuthState(query.state, unsignedNonce?.valid ? (unsignedNonce.value ?? undefined) : undefined);
    reply.clearCookie(OAUTH_NONCE_COOKIE, { path: '/api/v1/auth/google' });
    if (!verified) throw new AppError('AUTH_INVALID', 'Sign-in state is missing, expired or does not match this browser');

    const handler = fastifyPassport.authenticate('google', { session: false }, async (req, rep, err, profile) => {
      if (err || !profile) {
        req.log.warn({ err: err?.message }, 'google oauth callback did not produce a profile');
        throw new AppError('AUTH_INVALID', 'Google sign-in failed');
      }
      const googleProfile = profile as Profile;
      const email = googleProfile.emails?.[0]?.value;
      if (!email) throw new AppError('AUTH_INVALID', 'Google profile did not include an email address');
      const displayName = googleProfile.displayName || email;
      const avatarUrl = googleProfile.photos?.[0]?.value ?? null;

      const user = await req.server.prisma.user.upsert({
        where: { googleId: googleProfile.id },
        update: { email, displayName, avatarUrl, lastSeenAt: new Date() },
        create: { googleId: googleProfile.id, email, displayName, avatarUrl },
      });
      if (!user.isActive) throw new AppError('AUTH_INVALID', 'This account is suspended');

      const authenticatedAt = new Date();
      const accessToken = signAccessToken(user, authenticatedAt);
      const { raw } = await issueRefreshToken(req.server.prisma, user.id, authenticatedAt);
      setRefreshCookie(rep, raw);
      await writeAuditLog(req.server.prisma, {
        userId: user.id,
        action: 'LOGIN',
        resourceType: 'user',
        resourceId: user.id,
        ipHash: hashIp(req.ip),
        userAgent: req.headers['user-agent'],
        metadata: { client: verified.client },
      });

      const body: AuthTokenResponse = {
        accessToken,
        user: { id: user.id, email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl },
      };
      const target = verified.client ? tokenRedirectTarget(verified.client) : null;
      if (target) {
        // Tokens travel in the fragment, which is never sent to any server.
        const fragment = new URLSearchParams({
          access_token: accessToken,
          user: Buffer.from(JSON.stringify(body.user)).toString('base64url'),
        });
        rep.header('cache-control', 'no-store').redirect(`${target}#${fragment.toString()}`);
        return;
      }
      rep.header('cache-control', 'no-store').send(body);
    });
    await handler.call(app, request, reply);
    return reply;
  });

  app.post('/auth/refresh', { config: { rateLimit: LIMITS.auth }, schema: { tags: ['auth'] } }, async (request, reply) => {
    if (!request.cookies[REFRESH_COOKIE_NAME]) throw new AppError('AUTH_REQUIRED', 'No refresh token cookie present');
    const raw = readRefreshCookie(request);
    if (!raw) throw new AppError('AUTH_INVALID', 'Refresh token cookie failed signature verification');

    const rotated = await rotateRefreshToken(app.prisma, raw);
    setRefreshCookie(reply, rotated.raw);
    await writeAuditLog(app.prisma, {
      userId: rotated.user.id,
      action: 'TOKEN_REFRESH',
      resourceType: 'token',
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });
    reply.header('cache-control', 'no-store');
    return { accessToken: signAccessToken(rotated.user, rotated.authenticatedAt) };
  });

  app.post('/auth/logout', { preHandler: authenticate, schema: { tags: ['auth'] } }, async (request, reply) => {
    const raw = readRefreshCookie(request);
    if (raw) await revokeRefreshTokenByRaw(app.prisma, raw);
    clearRefreshCookie(reply);
    await writeAuditLog(app.prisma, {
      userId: request.authUser!.id,
      action: 'LOGOUT',
      resourceType: 'user',
      resourceId: request.authUser!.id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });
    return { success: true };
  });

  // §29.4 "Sign out all devices — revokes every refresh token".
  app.post('/auth/logout-all', { preHandler: authenticate, schema: { tags: ['auth'] } }, async (request, reply) => {
    await revokeAllUserRefreshTokens(app.prisma, request.authUser!.id);
    clearRefreshCookie(reply);
    await writeAuditLog(app.prisma, {
      userId: request.authUser!.id,
      action: 'SESSIONS_REVOKED',
      resourceType: 'user',
      resourceId: request.authUser!.id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });
    return { success: true };
  });

  app.get('/auth/me', { preHandler: authenticate, schema: { tags: ['auth'] } }, async (request) => {
    const { id, email, displayName, avatarUrl, deletionRequestedAt } = request.authUser!;
    return { id, email, displayName, avatarUrl, role: request.authUser!.role, deletionRequestedAt };
  });
};

export default authRoutes;
