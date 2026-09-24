import { PrismaClient } from '@prisma/client';
import fp from 'fastify-plugin';
import type { FastifyInstance } from 'fastify';
import { metrics } from '../lib/metrics';

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
  }
}

export function createPrismaClient(): PrismaClient {
  const base = new PrismaClient({ log: ['warn', 'error'] });
  // §28.2 db_query_duration_seconds — every model operation, against the §13 < 50ms target.
  const extended = base.$extends({
    query: {
      async $allOperations({ args, query }) {
        const end = metrics.dbQueryDuration.startTimer();
        try {
          return await query(args);
        } finally {
          end();
        }
      },
    },
  });
  return extended as unknown as PrismaClient;
}

/** Prisma client initialisation and graceful shutdown (§8 "backend/src/plugins/db.ts"). */
export default fp(
  async function dbPlugin(app: FastifyInstance) {
    const prisma = createPrismaClient();
    await prisma.$connect();
    app.decorate('prisma', prisma);
    app.addHook('onClose', async (instance) => {
      await instance.prisma.$disconnect();
    });
  },
  { name: 'db-plugin' }
);
