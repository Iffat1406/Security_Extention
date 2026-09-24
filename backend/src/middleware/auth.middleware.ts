import type { Role } from '@prisma/client';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../lib/errors';
import { metrics } from '../lib/metrics';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { verifyAccessToken } from '../services/auth.service';

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  role: Role;
  /** Seconds since epoch of the Google sign-in behind this token. */
  authTime: number;
  deletionRequestedAt: Date | null;
}

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Set by `authenticate` once the bearer token has been verified and the
     * user re-loaded from the database. Named `authUser` (not `user`) to
     * stay clear of Passport's own `request.user`, which only ever holds a
     * raw Google profile during the OAuth callback.
     */
    authUser?: AuthenticatedUser;
  }
}

async function resolveUser(request: FastifyRequest, token: string): Promise<AuthenticatedUser> {
  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    metrics.authFailures.inc({ reason: 'invalid_token' });
    throw new AppError('AUTH_INVALID', 'Access token is invalid or expired');
  }

  // Role — and whether the account is even still active — is read fresh on
  // every request, never trusted from the token claim. A token issued
  // before a demotion or suspension must not retain elevated access beyond
  // this one request (§21.3).
  const user = await request.server.prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || !user.isActive) {
    metrics.authFailures.inc({ reason: 'inactive_account' });
    throw new AppError('AUTH_INVALID', 'Account not found or inactive');
  }

  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    role: user.role,
    authTime: payload.authTime,
    deletionRequestedAt: user.deletionRequestedAt,
  };
}

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  return header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
}

/**
 * §21.3 "authenticate() ... verify JWT signature + exp, load user_id" then
 * "loadUser() ... fetch users.role from the database". preHandler for
 * protected routes.
 */
export async function authenticate(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const token = bearerToken(request);
  if (!token) {
    metrics.authFailures.inc({ reason: 'missing_token' });
    throw new AppError('AUTH_REQUIRED', 'Missing bearer token');
  }
  request.authUser = await resolveUser(request, token);
}

/**
 * For routes where auth is optional (POST /scans — §11 "Optional (anon
 * allowed)"). No token → anonymous. A token that is *present but invalid*
 * is still rejected: silently downgrading a broken session to anonymous
 * would make the extension believe results were being saved.
 */
export async function optionalAuthenticate(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const token = bearerToken(request);
  if (token) request.authUser = await resolveUser(request, token);
}

/**
 * §21.3 "authorize(\"ADMIN\") ... 403 FORBIDDEN on failure — logged to
 * audit_logs". Takes a role *set* because the §21.2 permission matrix is
 * capability-specific, not a strict ladder.
 */
export function authorize(...allowedRoles: Role[]) {
  return async function authorizeHook(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
    const authUser = request.authUser;
    if (!authUser) throw new AppError('AUTH_REQUIRED', 'authenticate must run before authorize');

    if (!allowedRoles.includes(authUser.role)) {
      await writeAuditLog(request.server.prisma, {
        userId: authUser.id,
        action: 'FORBIDDEN_ACCESS_ATTEMPT',
        resourceType: 'user',
        resourceId: authUser.id,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { route: request.routeOptions?.url, requiredRoles: allowedRoles, actualRole: authUser.role },
      });
      metrics.authFailures.inc({ reason: 'forbidden' });
      throw new AppError('FORBIDDEN', 'Insufficient role for this action');
    }
  };
}

/**
 * §18.3 "Export ... requires a fresh authentication": the Google sign-in
 * behind this token must be recent. A refreshed access token doesn't
 * count — `auth_time` survives refresh rotation unchanged.
 */
export function requireFreshAuth(maxAgeSeconds: number) {
  return async function freshAuthHook(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
    const authUser = request.authUser;
    if (!authUser) throw new AppError('AUTH_REQUIRED', 'authenticate must run before requireFreshAuth');
    const age = Math.floor(Date.now() / 1000) - authUser.authTime;
    if (age > maxAgeSeconds) {
      throw new AppError('AUTH_REQUIRED', 'Please sign in again to continue', {
        reason: 'FRESH_AUTH_REQUIRED',
        maxAgeSeconds,
      });
    }
  };
}
