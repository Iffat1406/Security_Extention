import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  MAX_EXCLUDED_DOMAINS,
  exclusionBodySchema,
  hostMatchesDomain,
  settingsPatchSchema,
  withSettingsDefaults,
  type SettingsResponse,
} from '@guardtab/shared';
import { env } from '../config/env';
import { AppError } from '../lib/errors';
import { LIMITS } from '../lib/rate-limit';
import { authenticate, requireFreshAuth } from '../middleware/auth.middleware';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { revokeAllUserRefreshTokens } from '../services/auth.service';
import { buildExport, buildScanCsv, createExportToken, verifyExportToken } from '../services/export.service';

/**
 * §23.4 settings + exclusions, §29 retention controls ("My account" §29.4).
 */

/** Exclusion entries are hostnames (a subdomain entry is valid, §23.2), lowercased and punycoded. */
export function normalizeExclusion(input: string): string {
  const trimmed = input.trim().toLowerCase();
  let host: string;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `http://${trimmed}`).hostname;
  } catch {
    throw new AppError('INVALID_URL', 'That is not a valid domain');
  }
  host = host.replace(/^www\./, '').replace(/\.$/, '');
  if (!host.includes('.') && host !== 'localhost') throw new AppError('INVALID_URL', 'That is not a valid domain');
  return host;
}

const FRESH_AUTH_MAX_AGE_SECONDS = 15 * 60;

const usersRoutes: FastifyPluginAsyncZod = async (app) => {
  const loadSettings = async (userId: string): Promise<SettingsResponse> => {
    const row = await app.prisma.userSettings.upsert({
      where: { userId },
      create: { userId, settings: {}, excludedDomains: [] },
      update: {},
    });
    return { settings: withSettingsDefaults(row.settings), excludedDomains: row.excludedDomains, updatedAt: row.updatedAt.toISOString() };
  };

  // ---- settings (§23.4) --------------------------------------------------------
  app.get('/users/me/settings', { preHandler: authenticate, schema: { tags: ['settings'] } }, async (request) =>
    loadSettings(request.authUser!.id)
  );

  app.patch(
    '/users/me/settings',
    { preHandler: authenticate, config: { rateLimit: LIMITS.settingsWrite }, schema: { tags: ['settings'], body: settingsPatchSchema } },
    async (request) => {
      const userId = request.authUser!.id;
      const current = await loadSettings(userId);
      const next = { ...current.settings, ...request.body };
      await app.prisma.userSettings.update({ where: { userId }, data: { settings: next } });
      await writeAuditLog(app.prisma, {
        userId,
        action: 'SETTINGS_UPDATE',
        resourceType: 'settings',
        resourceId: userId,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { changed: Object.keys(request.body) },
      });
      return loadSettings(userId);
    }
  );

  // ---- exclusions (§23.2) -------------------------------------------------------
  app.post(
    '/users/me/exclusions',
    { preHandler: authenticate, config: { rateLimit: LIMITS.settingsWrite }, schema: { tags: ['settings'], body: exclusionBodySchema } },
    async (request) => {
      const userId = request.authUser!.id;
      const domain = normalizeExclusion(request.body.domain);
      const current = await loadSettings(userId);
      if (!current.excludedDomains.includes(domain)) {
        if (current.excludedDomains.length >= MAX_EXCLUDED_DOMAINS) {
          throw new AppError('VALIDATION_ERROR', `At most ${MAX_EXCLUDED_DOMAINS} excluded domains`, { reason: 'EXCLUSION_LIMIT' });
        }
        await app.prisma.userSettings.update({ where: { userId }, data: { excludedDomains: [...current.excludedDomains, domain] } });
      }
      // §23.2 "adds the current registrable domain and clears any stored scans for it".
      const scans = await app.prisma.scanResult.findMany({ where: { userId }, select: { id: true, host: true } });
      const toDelete = scans.filter((s) => hostMatchesDomain(s.host, domain)).map((s) => s.id);
      if (toDelete.length > 0) await app.prisma.scanResult.deleteMany({ where: { id: { in: toDelete }, userId } });

      await writeAuditLog(app.prisma, {
        userId,
        action: 'EXCLUSION_ADD',
        resourceType: 'settings',
        resourceId: userId,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { scansRemoved: toDelete.length },
      });
      return loadSettings(userId);
    }
  );

  app.delete(
    '/users/me/exclusions/:domain',
    { preHandler: authenticate, schema: { tags: ['settings'], params: z.object({ domain: z.string().min(1).max(253) }) } },
    async (request) => {
      const userId = request.authUser!.id;
      const domain = normalizeExclusion(request.params.domain);
      const current = await loadSettings(userId);
      await app.prisma.userSettings.update({
        where: { userId },
        data: { excludedDomains: current.excludedDomains.filter((d) => d !== domain) },
      });
      await writeAuditLog(app.prisma, {
        userId,
        action: 'EXCLUSION_REMOVE',
        resourceType: 'settings',
        resourceId: userId,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
      });
      return loadSettings(userId);
    }
  );

  // ---- history purges (§29.2) -------------------------------------------------------
  app.delete('/users/me/scans', { preHandler: authenticate, schema: { tags: ['account'] } }, async (request) => {
    const userId = request.authUser!.id;
    const { count } = await app.prisma.scanResult.deleteMany({ where: { userId } });
    await writeAuditLog(app.prisma, {
      userId,
      action: 'HISTORY_PURGE',
      resourceType: 'scan',
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
      metadata: { scansDeleted: count },
    });
    return { success: true, deleted: count };
  });

  app.delete('/users/me/chats', { preHandler: authenticate, schema: { tags: ['account'] } }, async (request) => {
    const userId = request.authUser!.id;
    const { count } = await app.prisma.scanChat.deleteMany({ where: { userId } });
    await writeAuditLog(app.prisma, {
      userId,
      action: 'HISTORY_PURGE',
      resourceType: 'scan',
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
      metadata: { chatsDeleted: count },
    });
    return { success: true, deleted: count };
  });

  // ---- account deletion (§29.2) ------------------------------------------------------
  app.delete(
    '/users/me',
    {
      preHandler: authenticate,
      config: { rateLimit: LIMITS.accountDeletion },
      schema: { tags: ['account'], body: z.object({ confirm: z.literal('DELETE') }).strict() },
    },
    async (request) => {
      const userId = request.authUser!.id;
      const requestedAt = new Date();
      await app.prisma.user.update({ where: { id: userId }, data: { deletionRequestedAt: requestedAt } });
      // "revokes every refresh token, signs out all devices".
      await revokeAllUserRefreshTokens(app.prisma, userId);
      await writeAuditLog(app.prisma, {
        userId,
        action: 'ACCOUNT_DELETE_REQUESTED',
        resourceType: 'user',
        resourceId: userId,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
      });
      const finalAt = new Date(requestedAt.getTime() + env.DELETION_GRACE_DAYS * 86_400_000);
      return { success: true, deletionScheduledFor: finalAt.toISOString() };
    }
  );

  app.post('/users/me/cancel-deletion', { preHandler: authenticate, schema: { tags: ['account'] } }, async (request) => {
    const userId = request.authUser!.id;
    await app.prisma.user.update({ where: { id: userId }, data: { deletionRequestedAt: null } });
    await writeAuditLog(app.prisma, {
      userId,
      action: 'ACCOUNT_DELETE_REQUESTED',
      resourceType: 'user',
      resourceId: userId,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
      metadata: { cancelled: true },
    });
    return { success: true };
  });

  // ---- export (§29.3) ---------------------------------------------------------------
  app.get(
    '/users/me/export',
    { preHandler: [authenticate, requireFreshAuth(FRESH_AUTH_MAX_AGE_SECONDS)], schema: { tags: ['account'] } },
    async (request) => {
      const userId = request.authUser!.id;
      const user = await app.prisma.user.findUniqueOrThrow({ where: { id: userId } });
      // "Limited to one export per 24 hours (users.last_export_at)".
      if (user.lastExportAt && Date.now() - user.lastExportAt.getTime() < 86_400_000) {
        const retryAfter = Math.ceil((user.lastExportAt.getTime() + 86_400_000 - Date.now()) / 1000);
        throw new AppError('RATE_LIMITED', 'One export per 24 hours', { retryAfter });
      }
      await app.prisma.user.update({ where: { id: userId }, data: { lastExportAt: new Date() } });
      await writeAuditLog(app.prisma, {
        userId,
        action: 'ACCOUNT_EXPORT',
        resourceType: 'user',
        resourceId: userId,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
      });
      const { token, expiresAt } = createExportToken(userId);
      const base = `${env.PUBLIC_BASE_URL}/api/v1/users/me/export/download?token=${encodeURIComponent(token)}`;
      return { json: `${base}&format=json`, csv: `${base}&format=csv`, expiresAt: expiresAt.toISOString() };
    }
  );

  // The signed link is the credential here (no bearer token) — it's short-lived and single-purpose.
  app.get(
    '/users/me/export/download',
    { schema: { tags: ['account'], querystring: z.object({ token: z.string().min(1).max(512), format: z.enum(['json', 'csv']).default('json') }) } },
    async (request, reply) => {
      const userId = verifyExportToken(request.query.token);
      if (!userId) throw new AppError('AUTH_INVALID', 'This download link is invalid or has expired');
      const stamp = new Date().toISOString().slice(0, 10);
      reply.header('cache-control', 'no-store');
      if (request.query.format === 'csv') {
        reply.header('content-type', 'text/csv; charset=utf-8').header('content-disposition', `attachment; filename="guardtab-scans-${stamp}.csv"`);
        return buildScanCsv(app.prisma, userId);
      }
      reply.header('content-disposition', `attachment; filename="guardtab-export-${stamp}.json"`);
      return buildExport(app.prisma, userId);
    }
  );
};

export default usersRoutes;
