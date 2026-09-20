import fastifyPassport from '@fastify/passport';
import fp from 'fastify-plugin';
import type { FastifyInstance } from 'fastify';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { env } from '../config/env';

/**
 * §6.2 "Passport.js (google-oauth2 strategy)" + §9 "Authentication flow".
 *
 * Only the strategy is configured here. Every stateful concern — finding or
 * creating the user, issuing tokens, writing the audit log — lives in
 * routes/auth.routes.ts's authenticate() callback, not in the verify
 * function below, so that logic stays testable without a live Google round
 * trip (see auth.service.ts).
 *
 * `session: false` is used everywhere this strategy is invoked (§9 step 5:
 * the backend issues its own JWT/refresh pair) — there is no server-side
 * Passport session, so no secureSession() plugin is registered.
 *
 * `fastifyPassport.initialize()` unconditionally registers `@fastify/flash`
 * internally, which hard-requires a `session` request decorator to exist
 * (it's meant to store flash messages there). We never use sessions or
 * flash messages — stub the decorator so the dependency check passes
 * rather than pulling in a real session plugin nothing else uses.
 */
export default fp(
  async function authPlugin(app: FastifyInstance) {
    app.decorateRequest('session', null);
    await app.register(fastifyPassport.initialize());

    fastifyPassport.use(
      'google',
      new GoogleStrategy(
        {
          clientID: env.GOOGLE_CLIENT_ID,
          clientSecret: env.GOOGLE_CLIENT_SECRET,
          callbackURL: env.GOOGLE_CALLBACK_URL,
        },
        // The verify callback just hands the Google profile through — see
        // the module comment above for why the DB/JWT work isn't done here.
        (_accessToken, _refreshToken, profile, done) => {
          done(null, profile);
        }
      )
    );
  },
  { name: 'auth-plugin' }
);

export { fastifyPassport };
