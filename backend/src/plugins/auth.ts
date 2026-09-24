import fastifyPassport from '@fastify/passport';
import fp from 'fastify-plugin';
import type { FastifyInstance } from 'fastify';
import { Strategy as GoogleStrategy, type Profile, type VerifyCallback } from 'passport-google-oauth20';
import { env, isGoogleAuthConfigured } from '../config/env';

/**
 * §6.2 "Passport.js (google-oauth2 strategy)" + §9 "Authentication flow".
 *
 * Only the strategy is configured here. Finding/creating the user, issuing
 * tokens and writing the audit log happen in routes/auth.routes.ts so that
 * logic stays testable without a live Google round trip.
 *
 * Google credentials are optional (§33.3 graceful degradation): without
 * them the strategy isn't registered and /auth/google answers 503, while
 * every other part of the API keeps working.
 *
 * `fastifyPassport.initialize()` unconditionally registers `@fastify/flash`,
 * which hard-requires a `session` request decorator. GuardTab has no server
 * sessions (the backend issues its own JWT/refresh pair), so the decorator
 * is stubbed rather than pulling in a session plugin nothing uses.
 */
export default fp(
  async function authPlugin(app: FastifyInstance) {
    app.decorateRequest('session', null);
    await app.register(fastifyPassport.initialize());

    if (!isGoogleAuthConfigured) {
      app.log.warn('GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET not set — Google sign-in is disabled');
      return;
    }

    fastifyPassport.use(
      'google',
      new GoogleStrategy(
        {
          clientID: env.GOOGLE_CLIENT_ID!,
          clientSecret: env.GOOGLE_CLIENT_SECRET!,
          callbackURL: env.GOOGLE_CALLBACK_URL,
        },
        (_accessToken: string, _refreshToken: string, profile: Profile, done: VerifyCallback) => {
          done(null, profile);
        }
      )
    );
  },
  { name: 'auth-plugin' }
);

export { fastifyPassport };
