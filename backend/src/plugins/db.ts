import { PrismaClient } from '@prisma/client';
import fp from 'fastify-plugin';
import type { FastifyInstance } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
  }
}

/**
 * Initialises the Prisma client and closes it gracefully on server
 * shutdown (§8 "backend/src/plugins/db.ts").
 */
export default fp(
  async function dbPlugin(app: FastifyInstance) {
    const prisma = new PrismaClient({
      log: ['warn', 'error'],
    });

    await prisma.$connect();
    app.decorate('prisma', prisma);

    app.addHook('onClose', async (instance) => {
      await instance.prisma.$disconnect();
    });
  },
  { name: 'db-plugin' }
);
