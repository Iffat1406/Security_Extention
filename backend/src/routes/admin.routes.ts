import { IndicatorSeverity, IndicatorSource, IndicatorType, Role, type Prisma } from '@prisma/client';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { feedbackResolveSchema } from '@guardtab/shared';
import { AppError } from '../lib/errors';
import { LIMITS } from '../lib/rate-limit';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { revokeAllUserRefreshTokens } from '../services/auth.service';
import { recomputeDomainReputation } from '../services/reputation.service';
import { virusTotalBudget } from '../services/external/virustotal.service';

/**
 * §21.4 "Admin API surface".
 *
 * §21.3: "Admin routes are registered under a separate Fastify plugin scope
 * with the RBAC hook applied at the plugin level — so a new admin route
 * cannot be added without inheriting the guard." Two scopes, one per grant
 * set in the §21.2 permission matrix:
 *
 *   adminOnly        — ADMIN
 *   analystOrAdmin   — ANALYST + ADMIN (threat intel, triage, statistics)
 *
 * Both are tighter-rate-limited than user routes. Neither ever returns a
 * user's scan history — "Read another user's scans: not available to any role".
 */
const idParams = z.object({ id: z.uuid() });
const domainParams = z.object({ domain: z.string().min(1).max(253) });
const pageQuery = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const adminOnly: FastifyPluginAsyncZod = async (app) => {
  app.addHook('preHandler', authenticate);
  app.addHook('preHandler', authorize('ADMIN'));

  app.get('/admin/users', { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], querystring: pageQuery } }, async (request) => {
    const { page, limit } = request.query;
    const [users, total] = await Promise.all([
      app.prisma.user.findMany({
        // No emails in the list view (§21.4).
        select: { id: true, createdAt: true, lastSeenAt: true, role: true, isActive: true, _count: { select: { scanResults: true } } },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      app.prisma.user.count(),
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
      page,
    };
  });

  app.get('/admin/users/:id', { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: idParams } }, async (request) => {
    // Administrative detail only — no scan history (§21.4).
    const user = await app.prisma.user.findUnique({
      where: { id: request.params.id },
      select: {
        id: true,
        email: true,
        displayName: true,
        avatarUrl: true,
        role: true,
        isActive: true,
        createdAt: true,
        lastSeenAt: true,
        deletionRequestedAt: true,
        _count: { select: { scanResults: true } },
      },
    });
    if (!user) throw new AppError('NOT_FOUND', 'User not found');
    const { _count, ...rest } = user;
    return { ...rest, scanCount: _count.scanResults };
  });

  app.post(
    '/admin/users/:id/role',
    { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: idParams, body: z.object({ role: z.enum(Role) }).strict() } },
    async (request) => {
      const target = await app.prisma.user.findUnique({ where: { id: request.params.id } });
      if (!target) throw new AppError('NOT_FOUND', 'User not found');
      const updated = await app.prisma.user.update({ where: { id: target.id }, data: { role: request.body.role } });
      await writeAuditLog(app.prisma, {
        userId: request.authUser!.id,
        action: 'ADMIN_ROLE_CHANGE',
        resourceType: 'user',
        resourceId: target.id,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { before: target.role, after: updated.role },
      });
      return { id: updated.id, role: updated.role };
    }
  );

  app.post('/admin/users/:id/suspend', { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: idParams } }, async (request) => {
    const target = await app.prisma.user.findUnique({ where: { id: request.params.id } });
    if (!target) throw new AppError('NOT_FOUND', 'User not found');
    await app.prisma.user.update({ where: { id: target.id }, data: { isActive: false } });
    await revokeAllUserRefreshTokens(app.prisma, target.id);
    await writeAuditLog(app.prisma, {
      userId: request.authUser!.id,
      action: 'ADMIN_SUSPEND',
      resourceType: 'user',
      resourceId: target.id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });
    return { success: true };
  });
};

const overrideBody = z.discriminatedUnion('action', [
  z.object({ action: z.literal('SUPPRESS'), indicatorId: z.uuid(), reason: z.string().trim().min(5).max(500) }).strict(),
  z.object({ action: z.literal('UNSUPPRESS'), indicatorId: z.uuid(), reason: z.string().trim().min(5).max(500) }).strict(),
  z
    .object({
      action: z.literal('FORCE'),
      type: z.enum(IndicatorType),
      severity: z.enum(IndicatorSeverity).default('HIGH'),
      reason: z.string().trim().min(5).max(500),
    })
    .strict(),
  z.object({ action: z.literal('ALLOWLIST'), allowlisted: z.boolean(), reason: z.string().trim().min(5).max(500) }).strict(),
]);

const analystOrAdmin: FastifyPluginAsyncZod = async (app) => {
  app.addHook('preHandler', authenticate);
  app.addHook('preHandler', authorize('ANALYST', 'ADMIN'));

  // Threat indicator feed with filters: type, severity, source, date range.
  app.get(
    '/admin/threats',
    {
      config: { rateLimit: LIMITS.admin },
      schema: {
        tags: ['admin'],
        querystring: pageQuery.extend({
          type: z.enum(IndicatorType).optional(),
          severity: z.enum(IndicatorSeverity).optional(),
          source: z.enum(IndicatorSource).optional(),
          from: z.coerce.date().optional(),
          to: z.coerce.date().optional(),
          includeSuppressed: z.coerce.boolean().default(false),
        }),
      },
    },
    async (request) => {
      const q = request.query;
      const where: Prisma.ThreatIndicatorWhereInput = {
        type: q.type,
        severity: q.severity,
        source: q.source,
        lastDetectedAt: { gte: q.from, lte: q.to },
        ...(q.includeSuppressed ? {} : { suppressedAt: null }),
      };
      const [indicators, total] = await Promise.all([
        app.prisma.threatIndicator.findMany({
          where,
          orderBy: { lastDetectedAt: 'desc' },
          skip: (q.page - 1) * q.limit,
          take: q.limit,
          include: { domain: { select: { domain: true, reputation: true, reputationConfidence: true } } },
        }),
        app.prisma.threatIndicator.count({ where }),
      ]);
      return { indicators, total, page: q.page };
    }
  );

  // Full intelligence record for a domain.
  app.get('/admin/domains/:domain', { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: domainParams } }, async (request) => {
    const domain = await app.prisma.domain.findUnique({
      where: { domain: request.params.domain.toLowerCase() },
      include: { indicators: { orderBy: { lastDetectedAt: 'desc' } } },
    });
    if (!domain) throw new AppError('NOT_FOUND', 'No record for that domain');
    const feedback = await app.prisma.scanFeedback.groupBy({
      by: ['feedbackType', 'status'],
      where: { domain: domain.domain },
      _count: { _all: true },
    });
    return {
      ...domain,
      reputationConfidence: Number(domain.reputationConfidence),
      reportCounts: feedback.map((f) => ({ feedbackType: f.feedbackType, status: f.status, count: f._count._all })),
    };
  });

  // Suppress / force an indicator, or toggle the allowlist. ADMIN applies it;
  // an ANALYST's call is recorded as a proposal for an ADMIN to act on (§21.2 "Propose").
  app.post(
    '/admin/domains/:domain/override',
    { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: domainParams, body: overrideBody } },
    async (request, reply) => {
      const actor = request.authUser!;
      const domain = await app.prisma.domain.findUnique({ where: { domain: request.params.domain.toLowerCase() } });
      if (!domain) throw new AppError('NOT_FOUND', 'No record for that domain');
      const body = request.body;
      const auditBase = {
        userId: actor.id,
        resourceType: 'domain',
        resourceId: domain.id,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
      };

      if (actor.role !== 'ADMIN') {
        await writeAuditLog(app.prisma, { ...auditBase, action: 'ANALYST_OVERRIDE_PROPOSAL', metadata: { proposal: body } });
        reply.status(202);
        return { status: 'PROPOSED' };
      }

      if (body.action === 'SUPPRESS' || body.action === 'UNSUPPRESS') {
        const indicator = await app.prisma.threatIndicator.findFirst({ where: { id: body.indicatorId, domainId: domain.id } });
        if (!indicator) throw new AppError('NOT_FOUND', 'No such indicator on this domain');
        await app.prisma.threatIndicator.update({
          where: { id: indicator.id },
          data: body.action === 'SUPPRESS' ? { suppressedAt: new Date(), suppressedReason: body.reason } : { suppressedAt: null, suppressedReason: null },
        });
        await writeAuditLog(app.prisma, {
          ...auditBase,
          action: 'ADMIN_INDICATOR_OVERRIDE',
          metadata: { action: body.action, indicatorId: indicator.id, before: indicator.suppressedAt ? 'SUPPRESSED' : 'ACTIVE', reason: body.reason },
        });
      } else if (body.action === 'FORCE') {
        await app.prisma.threatIndicator.upsert({
          where: { domainId_type_source: { domainId: domain.id, type: body.type, source: 'ADMIN' } },
          create: { domainId: domain.id, type: body.type, source: 'ADMIN', severity: body.severity, confidence: 1, evidence: { reason: body.reason } },
          update: { severity: body.severity, confidence: 1, evidence: { reason: body.reason }, lastDetectedAt: new Date(), suppressedAt: null, suppressedReason: null },
        });
        await writeAuditLog(app.prisma, { ...auditBase, action: 'ADMIN_INDICATOR_OVERRIDE', metadata: { action: 'FORCE', type: body.type, reason: body.reason } });
      } else {
        await app.prisma.domain.update({ where: { id: domain.id }, data: { isAllowlisted: body.allowlisted } });
        await writeAuditLog(app.prisma, {
          ...auditBase,
          action: 'ADMIN_ALLOWLIST_CHANGE',
          metadata: { before: domain.isAllowlisted, after: body.allowlisted, reason: body.reason },
        });
      }

      await recomputeDomainReputation(app.prisma, domain.id);
      const updated = await app.prisma.domain.findUniqueOrThrow({ where: { id: domain.id } });
      return { status: 'APPLIED', reputation: updated.reputation, confidence: Number(updated.reputationConfidence) };
    }
  );

  // False-positive queue sorted by report volume.
  app.get(
    '/admin/feedback',
    {
      config: { rateLimit: LIMITS.admin },
      schema: { tags: ['admin'], querystring: z.object({ status: z.enum(['NEW', 'REVIEWING', 'CONFIRMED', 'REJECTED']).default('NEW') }) },
    },
    async (request) => {
      const groups = await app.prisma.scanFeedback.groupBy({
        by: ['domain', 'feedbackType', 'reportedSignal'],
        where: { status: request.query.status },
        _count: { _all: true },
        orderBy: { _count: { domain: 'desc' } },
        take: 100,
      });
      const items = await app.prisma.scanFeedback.findMany({
        where: { status: request.query.status },
        orderBy: { createdAt: 'desc' },
        take: 200,
        // Reporter identity is not needed to triage and is not exposed (§17.1).
        select: { id: true, domain: true, feedbackType: true, reportedSignal: true, reason: true, status: true, createdAt: true },
      });
      return {
        queue: groups.map((g) => ({ domain: g.domain, feedbackType: g.feedbackType, reportedSignal: g.reportedSignal, reports: g._count._all })),
        items,
      };
    }
  );

  app.post(
    '/admin/feedback/:id/resolve',
    { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], params: idParams, body: feedbackResolveSchema } },
    async (request) => {
      const feedback = await app.prisma.scanFeedback.findUnique({ where: { id: request.params.id } });
      if (!feedback) throw new AppError('NOT_FOUND', 'No such feedback');
      const updated = await app.prisma.scanFeedback.update({
        where: { id: feedback.id },
        data: { status: request.body.status, resolvedById: request.authUser!.id, resolvedAt: new Date() },
      });
      await writeAuditLog(app.prisma, {
        userId: request.authUser!.id,
        action: 'ADMIN_FEEDBACK_RESOLVE',
        resourceType: 'feedback',
        resourceId: feedback.id,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { before: feedback.status, after: updated.status },
      });
      // Confirmed/rejected reports change the false-positive rate and reporter weight (§22.4).
      const domain = await app.prisma.domain.findUnique({ where: { domain: feedback.domain } });
      if (domain) await recomputeDomainReputation(app.prisma, domain.id);
      return { id: updated.id, status: updated.status };
    }
  );

  // Platform metrics: scans/day, top threat types, external API quota, error rates.
  app.get(
    '/admin/statistics',
    { config: { rateLimit: LIMITS.admin }, schema: { tags: ['admin'], querystring: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }) } },
    async (request) => {
      const since = new Date(Date.now() - request.query.days * 86_400_000);
      const [daily, topThreatTypes, aiUsage] = await Promise.all([
        app.prisma.dailyStat.findMany({ where: { date: { gte: since } }, orderBy: { date: 'asc' } }),
        app.prisma.threatIndicator.groupBy({ by: ['type'], where: { lastDetectedAt: { gte: since } }, _count: { _all: true } }),
        app.prisma.aiUsage.findMany({ orderBy: { month: 'desc' }, take: 3 }),
      ]);
      return {
        scansPerDay: daily,
        topThreatTypes: topThreatTypes.sort((a, b) => b._count._all - a._count._all).map((t) => ({ type: t.type, count: t._count._all })),
        quota: { virusTotal: virusTotalBudget.remaining() },
        aiUsage: aiUsage.map((u) => ({ ...u, inputTokens: u.inputTokens.toString(), outputTokens: u.outputTokens.toString(), estimatedCostUsd: Number(u.estimatedCostUsd) })),
      };
    }
  );

  // Audit search. ADMIN: everything. ANALYST: own actions only (§21.2).
  app.get(
    '/admin/audit',
    {
      config: { rateLimit: LIMITS.admin },
      schema: {
        tags: ['admin'],
        querystring: pageQuery.extend({
          actor: z.uuid().optional(),
          action: z.string().max(32).optional(),
          resourceType: z.string().max(32).optional(),
          resourceId: z.string().max(64).optional(),
          from: z.coerce.date().optional(),
          to: z.coerce.date().optional(),
        }),
      },
    },
    async (request) => {
      const q = request.query;
      const actor = request.authUser!;
      const where: Prisma.AuditLogWhereInput = {
        userId: actor.role === 'ADMIN' ? q.actor : actor.id,
        action: q.action,
        resourceType: q.resourceType,
        resourceId: q.resourceId,
        createdAt: { gte: q.from, lte: q.to },
      };
      const [entries, total] = await Promise.all([
        app.prisma.auditLog.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (q.page - 1) * q.limit, take: q.limit }),
        app.prisma.auditLog.count({ where }),
      ]);
      return { entries, total, page: q.page };
    }
  );
};

const adminRoutes: FastifyPluginAsyncZod = async (app) => {
  await app.register(adminOnly);
  await app.register(analystOrAdmin);
};

export default adminRoutes;
