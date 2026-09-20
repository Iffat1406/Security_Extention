import { Role } from '@prisma/client';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AppError } from '../lib/errors';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { revokeAllUserRefreshTokens } from '../services/auth.service';

/**
 * §21.4 "Admin API surface" — only the four routes that depend solely on
 * tables Phase 2 owns (users, refresh_tokens, audit_logs). The rest of
 * §21.4 (threats, domain overrides, feedback, statistics) needs the
 * threat-intelligence tables from Phase 10 and is deferred until then.
 *
 * §21.3: "Admin routes are registered under a separate Fastify plugin scope
 * with the RBAC hook applied at the plugin level — so a new admin route
 * cannot be added without inheriting the guard." The two preHandler hooks
 * below apply to every route added in this encapsulated plugin context.
 */
const roleChangeBodySchema = z.object({
  role: z.nativeEnum(Role),
});

export default async function adminRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticate);
  app.addHook('preHandler', authorize('ADMIN'));

  app.get('/admin/users', async (request) => {
    const query = z
      .object({ page: z.coerce.number().int().positive().default(1), limit: z.coerce.number().int().min(1).max(100).default(20) })
      .parse(request.query);

    const [users, total] = await Promise.all([
      request.server.prisma.user.findMany({
        // No emails in the list view (§21.4).
        select: {
          id: true,
          createdAt: true,
          lastSeenAt: true,
          role: true,
          isActive: true,
          _count: { select: { scanResults: true } },
        },
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.limit,
        take: query.limit,
      }),
      request.server.prisma.user.count(),
    ]);

    return {
      users: users.map((u) => ({
        id: u.id,
        createdAt: u.createdAt,
        lastSeenAt: u.lastSeenAt,
        role: u.role,
        isActive: u.isActive,
        scanCount: u._count.scanResults,
      })),
      total,
      page: query.page,
    };
  });

  app.get('/admin/users/:id', async (request) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(request.params);

    // Administrative detail only — does not return scan history (§21.4).
    const user = await request.server.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        displayName: true,
        avatarUrl: true,
        role: true,
        isActive: true,
        createdAt: true,
        lastSeenAt: true,
        _count: { select: { scanResults: true } },
      },
    });
    if (!user) {
      throw new AppError('SCAN_NOT_FOUND', 'User not found');
    }
    const { _count, ...rest } = user;
    return { ...rest, scanCount: _count.scanResults };
  });

  app.post('/admin/users/:id/role', async (request) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(request.params);
    const { role } = roleChangeBodySchema.parse(request.body);

    const target = await request.server.prisma.user.findUnique({ where: { id } });
    if (!target) {
      throw new AppError('SCAN_NOT_FOUND', 'User not found');
    }

    const updated = await request.server.prisma.user.update({ where: { id }, data: { role } });

    await writeAuditLog(request.server.prisma, {
      userId: request.authUser!.id,
      action: 'ADMIN_ROLE_CHANGE',
      resourceType: 'user',
      resourceId: id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
      metadata: { before: target.role, after: updated.role },
    });

    return { id: updated.id, role: updated.role };
  });

  app.post('/admin/users/:id/suspend', async (request) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(request.params);

    const target = await request.server.prisma.user.findUnique({ where: { id } });
    if (!target) {
      throw new AppError('SCAN_NOT_FOUND', 'User not found');
    }

    await request.server.prisma.user.update({ where: { id }, data: { isActive: false } });
    await revokeAllUserRefreshTokens(request.server.prisma, id);

    await writeAuditLog(request.server.prisma, {
      userId: request.authUser!.id,
      action: 'ADMIN_SUSPEND',
      resourceType: 'user',
      resourceId: id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });

    return { success: true };
  });
}
