import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { AUTH_CLIENTS, type AuthClient } from '@guardtab/shared';
import { env } from '../config/env';

/**
 * OAuth `state` for the Google flow. Two jobs:
 *   1. Login CSRF protection — the state carries a nonce that must match an
 *      HttpOnly cookie set on the same browser when the flow started.
 *   2. Remembering which client asked (extension / dashboard / plain JSON)
 *      across the Google round trip, so the callback knows where to hand the
 *      tokens back — only ever to an allow-listed destination.
 */
export const OAUTH_NONCE_COOKIE = 'guardtab_oauth';
const MAX_AGE_MS = 10 * 60 * 1000;

const sign = (payload: string) => createHmac('sha256', env.COOKIE_SECRET).update(`oauth-state:${payload}`).digest('base64url');

export function createOAuthState(client: AuthClient | null): { state: string; nonce: string } {
  const nonce = randomBytes(16).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ c: client, n: nonce, t: Date.now() })).toString('base64url');
  return { state: `${payload}.${sign(payload)}`, nonce };
}

export function verifyOAuthState(state: string | undefined, cookieNonce: string | undefined): { client: AuthClient | null } | null {
  if (!state || !cookieNonce) return null;
  const [payload, signature] = state.split('.');
  if (!payload || !signature) return null;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;
  try {
    const { c, n, t } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { c: unknown; n: unknown; t: unknown };
    if (typeof n !== 'string' || n !== cookieNonce) return null;
    if (typeof t !== 'number' || Date.now() - t > MAX_AGE_MS) return null;
    const client = typeof c === 'string' && (AUTH_CLIENTS as readonly string[]).includes(c) ? (c as AuthClient) : null;
    return { client };
  } catch {
    return null;
  }
}

/** The only places tokens are ever redirected to. Never a caller-supplied URL. */
export function tokenRedirectTarget(client: AuthClient): string | null {
  if (client === 'dashboard') return `${env.PUBLIC_BASE_URL}/dashboard/`;
  if (client === 'extension' && env.EXTENSION_ID && /^[a-p]{32}$/.test(env.EXTENSION_ID)) {
    // chrome.identity.launchWebAuthFlow captures redirects to this origin.
    return `https://${env.EXTENSION_ID}.chromiumapp.org/oauth`;
  }
  return null;
}
