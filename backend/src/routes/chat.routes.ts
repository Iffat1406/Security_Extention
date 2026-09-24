import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { chatMessageBodySchema, withSettingsDefaults, type EvidenceItem } from '@guardtab/shared';
import { AppError } from '../lib/errors';
import { authenticate } from '../middleware/auth.middleware';
import { chatAboutScan } from '../services/ai-explainer.service';

/** §11 "Chat endpoints" — Feature 14. Messages live in scan_chats (30-day retention, §29.1). */
const params = z.object({ scanId: z.uuid() });

const chatRoutes: FastifyPluginAsyncZod = async (app) => {
  const loadScan = async (scanId: string, userId: string) => {
    const scan = await app.prisma.scanResult.findFirst({ where: { id: scanId, userId } });
    if (!scan) throw new AppError('SCAN_NOT_FOUND', 'No scan with that id');
    return scan;
  };

  app.get('/scans/:scanId/chat', { preHandler: authenticate, schema: { tags: ['chat'], params } }, async (request) => {
    await loadScan(request.params.scanId, request.authUser!.id);
    const messages = await app.prisma.scanChat.findMany({
      where: { scanId: request.params.scanId, userId: request.authUser!.id },
      orderBy: { createdAt: 'asc' },
      select: { role: true, content: true, createdAt: true },
    });
    return { messages };
  });

  app.post(
    '/scans/:scanId/chat',
    { preHandler: authenticate, schema: { tags: ['chat'], params, body: chatMessageBodySchema } },
    async (request) => {
      const userId = request.authUser!.id;
      const scan = await loadScan(request.params.scanId, userId);

      // §23.1 "AI chat OFF — Chat panel hidden; no scan_chats rows are created".
      const settingsRow = await app.prisma.userSettings.findUnique({ where: { userId } });
      if (!withSettingsDefaults(settingsRow?.settings).aiChat) {
        throw new AppError('FORBIDDEN', 'AI chat is turned off in your settings', { reason: 'AI_CHAT_DISABLED' });
      }
      await app.checkBucket(request, 'chat');

      const history = await app.prisma.scanChat.findMany({
        where: { scanId: scan.id, userId },
        orderBy: { createdAt: 'asc' },
        select: { role: true, content: true },
      });
      const evidence = ((scan.riskEvidence as { evidence?: EvidenceItem[] } | null)?.evidence ?? []) as EvidenceItem[];

      const outcome = await chatAboutScan(
        app.prisma,
        {
          registrableDomain: scan.registrableDomain,
          securityScore: scan.securityScore,
          privacyScore: scan.privacyScore,
          overall: scan.overallScore,
          band: scan.riskBand,
          evidence,
          checks: (scan.checkStatus ?? {}) as never,
        },
        history.map((h) => ({ role: h.role as 'user' | 'assistant', content: h.content })),
        request.body.message,
        request.log
      );
      if (outcome.status !== 'OK') {
        throw new AppError('EXTERNAL_SERVICE_UNAVAILABLE', 'The assistant is temporarily unavailable', { reason: outcome.reason });
      }

      // Explicit, strictly increasing timestamps — two rows from one insert would
      // otherwise share now() and the history order could flip.
      const now = Date.now();
      await app.prisma.scanChat.createMany({
        data: [
          { scanId: scan.id, userId, role: 'user', content: request.body.message, createdAt: new Date(now) },
          { scanId: scan.id, userId, role: 'assistant', content: outcome.reply, createdAt: new Date(now + 1) },
        ],
      });
      return { role: 'assistant' as const, content: outcome.reply };
    }
  );
};

export default chatRoutes;
