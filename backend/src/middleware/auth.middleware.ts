import type { Role } from '@prisma/client';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../lib/errors';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { verifyAccessToken } from '../services/auth.service';

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  role: Role;
}

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Set by `authenticate` once the bearer token has been verified and the
     * user re-loaded from the database. Named `authUser` (not `user`) to
     * stay clear of Passport's own `request.user`, which only ever holds a
     * raw Google profile during the OAuth callback (see plugins/auth.ts).
     */
    authUser?: AuthenticatedUser;
  }
}

/**
 * §21.3 "authenticate() ... verify JWT signature + exp, load user_id" then
 * "loadUser() ... fetch users.role from the database (the role claim in the
 * token is advisory only)". Register as a `preHandler` on any protected route.
 */
export async function authenticate(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    throw new AppError('AUTH_REQUIRED', 'Missing bearer token');
  }
  const token = header.slice('Bearer '.length);

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    throw new AppError('AUTH_INVALID', 'Access token is invalid or expired');
  }

  // Role — and whether the account is even still active — is read fresh on
  // every request, never trusted from the token claim. A token issued
  // before a demotion or suspension must not retain elevated access beyond
  // this one request (§21.3).
  const user = await request.server.prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || !user.isActive) {
    throw new AppError('AUTH_INVALID', 'Account not found or inactive');
  }

  request.authUser = {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    role: user.role,
  };
}

/**
 * §21.3 "authorize(\"ADMIN\") ... compare against the required role ...
 * 403 FORBIDDEN on failure — logged to audit_logs". Must run after
 * `authenticate` (which populates `request.authUser`).
 *
 * Takes a role *set* rather than a single role/hierarchy because the
 * permission matrix in §21.2 is capability-specific, not a strict ladder
 * (e.g. ANALYST can read threat intelligence but not manage users) — each
 * route lists exactly the roles the spec grants it.
 */
export function authorize(...allowedRoles: Role[]) {
  return async function authorizeHook(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
    const authUser = request.authUser;
    if (!authUser) {
      // Programmer error (authorize used without authenticate first) — not
      // a real anonymous-caller case, but still safe to treat as "no creds".
      throw new AppError('AUTH_REQUIRED', 'authenticate must run before authorize');
    }

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
      throw new AppError('FORBIDDEN', 'Insufficient role for this action');
    }
  };
}
