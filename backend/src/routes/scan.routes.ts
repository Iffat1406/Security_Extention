import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { feedbackBodySchema, scanHistoryQuerySchema, scanSubmissionSchema, scanUpdateSchema } from '@guardtab/shared';
import { AppError } from '../lib/errors';
import { LIMITS } from '../lib/rate-limit';
import { authenticate, optionalAuthenticate } from '../middleware/auth.middleware';
import { hashIp, writeAuditLog } from '../services/audit.service';
import { recordCommunityReport } from '../services/reputation.service';
import { rowToScanResult, runScan, updateScanChecks } from '../services/scan.service';

/** §11 "Scan endpoints" + §22.5 feedback, contract per §24.2. */
const idParams = z.object({ id: z.uuid() });

/** §22.3 reason: free text, never rendered as HTML — strip control characters on the way in. */
const sanitizeReason = (reason: string | undefined) =>
  reason
    ?.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .trim()
    .slice(0, 500) || null;

const scanRoutes: FastifyPluginAsyncZod = async (app) => {
  // POST /scans — §11 "Optional (anon allowed)". 202 once the deterministic score exists (§24.2).
  app.post(
    '/scans',
    {
      preHandler: optionalAuthenticate,
      config: { rateLimit: LIMITS.scanCreate },
      schema: { tags: ['scans'], summary: 'Submit local checker results; returns the deterministic score', body: scanSubmissionSchema },
    },
    async (request, reply) => {
      if (request.body.rescan) await app.checkBucket(request, 'rescan');

      const { result, logFields, afterResponse } = await runScan(
        { prisma: app.prisma, log: request.log, userId: request.authUser?.id ?? null, httpClient: app.externalHttp, dnsLookup: app.dnsLookup },
        request.body
      );
      request.scanLog = logFields;

      if (afterResponse) {
        // "The AI explanation is additive and never blocks the response" (§24.2).
        void afterResponse().catch((error: unknown) =>
          request.log.warn({ err: error instanceof Error ? error.message : 'unknown' }, 'post-response AI explanation failed')
        );
      }
      reply.status(result.status === 'NOT_SUPPORTED' ? 200 : 202);
      return result;
    }
  );

  app.get(
    '/scans/history',
    { preHandler: authenticate, schema: { tags: ['scans'], summary: "The caller's scan history (paginated)", querystring: scanHistoryQuerySchema } },
    async (request) => {
      const { page, limit } = request.query;
      const where = { userId: request.authUser!.id };
      const [rows, total] = await Promise.all([
        app.prisma.scanResult.findMany({
          where,
          orderBy: { scannedAt: 'desc' },
          skip: (page - 1) * limit,
          take: limit,
          select: {
            id: true,
            host: true,
            registrableDomain: true,
            path: true,
            scannedAt: true,
            scanStatus: true,
            securityScore: true,
            privacyScore: true,
            overallScore: true,
            riskBand: true,
            riskEngineVersion: true,
          },
        }),
        app.prisma.scanResult.count({ where }),
      ]);
      return { scans: rows, total, page };
    }
  );

  // GET /scans/domain/:domain — the caller's own latest scan of that domain. Never another user's (§21.2).
  app.get(
    '/scans/domain/:domain',
    { preHandler: authenticate, schema: { tags: ['scans'], params: z.object({ domain: z.string().min(1).max(253) }) } },
    async (request) => {
      const row = await app.prisma.scanResult.findFirst({
        where: { userId: request.authUser!.id, registrableDomain: request.params.domain.toLowerCase() },
        orderBy: { scannedAt: 'desc' },
      });
      if (!row) throw new AppError('SCAN_NOT_FOUND', 'No scan of that domain');
      return rowToScanResult(row);
    }
  );

  // §18.3 IDOR: "Every read filters on user_id ... 404 rather than 403 to avoid ID enumeration".
  const ownScan = async (id: string, userId: string) => {
    const row = await app.prisma.scanResult.findFirst({ where: { id, userId } });
    if (!row) throw new AppError('SCAN_NOT_FOUND', 'No scan with that id');
    return row;
  };

  app.get('/scans/:id', { preHandler: authenticate, schema: { tags: ['scans'], params: idParams } }, async (request) =>
    rowToScanResult(await ownScan(request.params.id, request.authUser!.id))
  );

  // PATCH /scans/:id — later local results (e.g. the breach check once a password is typed).
  app.patch(
    '/scans/:id',
    { preHandler: authenticate, config: { rateLimit: LIMITS.scanUpdate }, schema: { tags: ['scans'], params: idParams, body: scanUpdateSchema } },
    async (request) => {
      const row = await ownScan(request.params.id, request.authUser!.id);
      return updateScanChecks(app.prisma, row, request.body.checks, request.authUser!.id);
    }
  );

  app.delete('/scans/:id', { preHandler: authenticate, schema: { tags: ['scans'], params: idParams } }, async (request) => {
    const row = await ownScan(request.params.id, request.authUser!.id);
    await app.prisma.scanResult.delete({ where: { id: row.id } });
    await writeAuditLog(app.prisma, {
      userId: request.authUser!.id,
      action: 'SCAN_DELETE',
      resourceType: 'scan',
      resourceId: row.id,
      ipHash: hashIp(request.ip),
      userAgent: request.headers['user-agent'],
    });
    return { success: true };
  });

  // POST /scans/:id/feedback — §22.3 / §22.5.
  app.post(
    '/scans/:id/feedback',
    { preHandler: authenticate, schema: { tags: ['threat intelligence'], params: idParams, body: feedbackBodySchema } },
    async (request, reply) => {
      const userId = request.authUser!.id;
      const row = await ownScan(request.params.id, userId);
      await app.checkBucket(request, 'feedback');

      const existing = await app.prisma.scanFeedback.findUnique({ where: { scanId_userId: { scanId: row.id, userId } } });
      if (existing) throw new AppError('VALIDATION_ERROR', 'Feedback for this scan was already submitted', { reason: 'DUPLICATE' });

      const feedback = await app.prisma.scanFeedback.create({
        data: {
          scanId: row.id,
          userId,
          domain: row.registrableDomain,
          feedbackType: request.body.feedbackType,
          reportedSignal: request.body.reportedSignal ?? null,
          reason: sanitizeReason(request.body.reason),
        },
      });

      // "This site is dangerous" becomes a weighted COMMUNITY signal (§22.4); false-positive
      // reports go to the analyst triage queue and only affect confidence once CONFIRMED.
      if (request.body.feedbackType === 'FALSE_NEGATIVE') await recordCommunityReport(app.prisma, row.registrableDomain);

      await writeAuditLog(app.prisma, {
        userId,
        action: 'FEEDBACK_SUBMIT',
        resourceType: 'feedback',
        resourceId: feedback.id,
        ipHash: hashIp(request.ip),
        userAgent: request.headers['user-agent'],
        metadata: { feedbackType: feedback.feedbackType, reportedSignal: feedback.reportedSignal },
      });
      reply.status(201);
      return { id: feedback.id, status: feedback.status };
    }
  );
};

export default scanRoutes;

declare module 'fastify' {
  interface FastifyRequest {
    /** Fields POST /scans adds to the §28.1 request log line. */
    scanLog?: { domain: string | null; scanStatus: string; deps: Record<string, number> };
  }
}
