import { buildApp } from './app';
import { env } from './config/env';
import { startScheduler, type Scheduler } from './jobs/scheduler';
import { closeRedis } from './lib/redis';

async function main() {
  const app = buildApp();
  let scheduler: Scheduler | null = null;

  try {
    await app.listen({ port: env.PORT, host: env.HOST });
    scheduler = await startScheduler(app.prisma, app.log);
  } catch (error) {
    app.log.error(error, 'failed to start server');
    process.exit(1);
  }

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'shutting down');
    try {
      await scheduler?.stop();
      await app.close();
      await closeRedis();
      process.exit(0);
    } catch (error) {
      app.log.error(error, 'error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void main();
