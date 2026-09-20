import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Profile } from 'passport-google-oauth20';
import { env } from '../config/env';
import { AppError } from '../lib/errors';
import { authenticate } from '../middleware/auth.middleware';
import { fastifyPassport } from '../plugins/auth';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { issueRefreshToken, revokeRefreshTokenByRaw, rotateRefreshToken, signAccessToken } from '../services/auth.service';

/**
 * §11 "Authentication endpoints" + §9 "Authentication flow".
 *
 * The refresh cookie is scoped to /api/v1/auth (not the whole site) — only
 * the two routes that need it (`/auth/refresh`, `/auth/logout`) ever see it,
 * which shrinks the CSRF surface described in §18.3 "CSRF on cookie
 * endpoints" alongside the SameSite=Strict + HttpOnly settings below.
 */
const REFRESH_COOKIE_NAME = 'guardtab_rt';
const REFRESH_COOKIE_PATH = '/api/v1/auth';

function setRefreshCookie(reply: FastifyReply, rawToken: string): void {
  reply.setCookie(REFRESH_COOKIE_NAME, rawToken, {
    httpOnly: true,
    // Secure requires HTTPS; disabled only for plain-HTTP local dev (§13
    // "HTTPS only in production" — this cookie follows the same rule).
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

function extractGoogleEmail(profile: Profile): string {
  const email = profile.emails?.[0]?.value;
  if (!email) {
    throw new AppError('AUTH_INVALID', 'Google profile did not include an email address');
  }
  return email;
}

export default async function authRoutes(app: FastifyInstance) {
  // Step 1-3 of §9 "Authentication flow": the preValidation hook itself
  // performs the redirect to Google's consent screen — this handler never runs.
  app.get(
    '/auth/google',
    { preValidation: fastifyPassport.authenticate('google', { session: false, scope: ['profile', 'email'] }) },
    async () => {
      /* unreachable */
    }
  );

  // Steps 4-6 of §9: exchange the code, find-or-create the user, issue the
  // JWT + refresh pair. Done inside the authenticate() callback (rather than
  // via `request.user` in a separate handler) so this route fully owns
  // sending the response — see plugins/auth.ts for why the verify function
  // itself does none of this work.
  app.get(
    '/auth/google/callback',
    {
      preValidation: fastifyPassport.authenticate('google', { session: false }, async (request, reply, err, profile) => {
        if (err || !profile) {
          request.log.warn({ err }, 'google oauth callback did not produce a profile');
          throw new AppError('AUTH_INVALID', 'Google sign-in failed');
        }

        const googleProfile = profile as Profile;
        const email = extractGoogleEmail(googleProfile);
        const displayName = googleProfile.displayName || email;
        const avatarUrl = googleProfile.photos?.[0]?.value ?? null;

        const user = await request.server.prisma.user.upsert({
          where: { googleId: googleProfile.id },
          update: { email, displayName, avatarUrl, lastSeenAt: new Date() },
          create: { googleId: googleProfile.id, email, displayName, avatarUrl },
        });

        const accessToken = signAccessToken(user);
        const { raw: refreshToken } = await issueRefreshToken(request.server.prisma, user.id);
        setRefreshCookie(reply, refreshToken);

        await writeAuditLog(request.server.prisma, {
          userId: user.id,
          action: 'LOGIN',
          resourceType: 'user',
          resourceId: user.id,
          ipHash: hashIp(request.ip),
          userAgent: request.headers['user-agent'],
        });

        reply.send({
          accessToken,
          user: { id: user.id, email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl },
        });
      }),
    },
    async () => {
      /* unreachable — the callback above always sends the reply itself */
    }
  );

  app.post('/auth/refresh', async (request, reply) => {
    const rawCookie = request.cookies[REFRESH_COOKIE_NAME];
    if (!rawCookie) {
      throw new AppError('AUTH_REQUIRED', 'No refresh token cookie present');
    }
    const unsigned = request.unsignCookie(rawCookie);
    if (!unsigned.valid || !unsigned.value) {
      throw new AppError('AUTH_INVALID', 'Refresh token cookie failed signature verification');
    }

    const { user, raw } = await rotateRefreshToken(request.server.prisma, unsigned.value);
    setRefreshCookie(reply, raw);

    await writeAuditLog(request.server.prisma, {
      userId: user.id,
      action: 'TOKEN_REFRESH',
      resourceType: 'token',
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });

    return { accessToken: signAccessToken(user) };
  });

  app.post('/auth/logout', { preHandler: authenticate }, async (request, reply) => {
    const rawCookie = request.cookies[REFRESH_COOKIE_NAME];
    if (rawCookie) {
      const unsigned = request.unsignCookie(rawCookie);
      if (unsigned.valid && unsigned.value) {
        await revokeRefreshTokenByRaw(request.server.prisma, unsigned.value);
      }
    }
    clearRefreshCookie(reply);

    await writeAuditLog(request.server.prisma, {
      userId: request.authUser!.id,
      action: 'LOGOUT',
      resourceType: 'user',
      resourceId: request.authUser!.id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });

    return { success: true };
  });

  app.get('/auth/me', { preHandler: authenticate }, async (request) => {
    const { id, email, displayName, avatarUrl } = request.authUser!;
    return { id, email, displayName, avatarUrl };
  });
}
