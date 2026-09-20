import { randomBytes } from 'node:crypto';
import fastifyCookie from '@fastify/cookie';
import Fastify, {
  LogController,
  type FastifyError,
  type FastifyInstance,
  type FastifyRequest,
} from 'fastify';
import { ZodError } from 'zod';
import { env } from './config/env';
import { AppError } from './lib/errors';
import authPlugin from './plugins/auth';
import dbPlugin from './plugins/db';
import adminRoutes from './routes/admin.routes';
import authRoutes from './routes/auth.routes';
import healthRoutes from './routes/health.routes';

const API_PREFIX = '/api/v1';

/** `req_` + 8 hex chars, matching the format in §25.5/§28.1 examples. Not a
 * secret — only used to correlate a log line with an error response. */
function generateRequestId(): string {
  return `req_${randomBytes(4).toString('hex')}`;
}

/** Route pattern only — never the populated path or query string (§28.1
 * "route ... Route pattern, never the populated path"). `routeOptions.url`
 * is the Fastify v5 replacement for the deprecated/removed `routerPath`. */
function routeLabel(request: FastifyRequest): string {
  return request.routeOptions?.url ?? request.url.split('?')[0]!;
}

export function buildApp(): FastifyInstance {
  const app = Fastify({
    genReqId: generateRequestId,
    trustProxy: true,
    // Fastify's own "incoming request"/"request completed" lines are
    // replaced by the single onResponse hook below, shaped to §28.1 exactly
    // (requestId, route, status, durationMs) — this avoids double-logging.
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: env.LOG_LEVEL,
      // Redaction rules from §28.1 "Redaction rules" — tokens and cookies
      // must never reach a log line, even nested in an object.
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["set-cookie"]',
          'res.headers["set-cookie"]',
        ],
        censor: '[redacted]',
      },
      serializers: {
        req(request) {
          return { method: request.method, route: routeLabel(request as FastifyRequest), requestId: request.id };
        },
        res(reply) {
          return { statusCode: reply.statusCode };
        },
      },
      ...(env.NODE_ENV === 'development'
        ? { transport: { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss', ignore: 'pid,hostname' } } }
        : {}),
    },
  });

  app.register(dbPlugin);
  app.register(fastifyCookie, { secret: env.COOKIE_SECRET });
  app.register(authPlugin);
  app.register(healthRoutes);
  app.register(authRoutes, { prefix: API_PREFIX });
  app.register(adminRoutes, { prefix: API_PREFIX });

  // §28.1 structured request log line: requestId, route, status, durationMs,
  // plus userId whenever `authenticate` ran (never the email — §28.1 "Never
  // the email address"). `domain`/`deps` are added once scans exist (Phase 4+).
  app.addHook('onResponse', async (request, reply) => {
    request.log.info(
      {
        requestId: request.id,
        route: routeLabel(request),
        userId: request.authUser?.id ?? null,
        status: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
      },
      'request completed'
    );
  });

  // Standard error envelope — §25.5. Every non-2xx response uses this shape.
  app.setErrorHandler((error: FastifyError | AppError | ZodError, request, reply) => {
    const requestId = request.id;

    if (error instanceof AppError) {
      request.log.warn({ requestId, errorCode: error.code, err: error.message }, 'handled application error');
      reply.status(error.httpStatus).send({
        error: {
          code: error.code,
          message: error.message,
          requestId,
          ...(error.details ? { details: error.details } : {}),
        },
      });
      return;
    }

    // Route handlers validate query/params/body with Zod directly (§25.6
    // notes Fastify JSON Schema as the longer-term source of truth, but a
    // ZodError must still map to the same VALIDATION_ERROR shape either way).
    // Checked before the FastifyError `.validation` branch below, since
    // ZodError doesn't have that property.
    if (error instanceof ZodError) {
      reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          requestId,
          details: { issues: error.flatten() },
        },
      });
      return;
    }

    if (error.validation) {
      reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          requestId,
          details: { issues: error.validation },
        },
      });
      return;
    }

    request.log.error({ requestId, err: error }, 'unhandled error');
    reply.status(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId },
    });
  });

  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      error: {
        code: 'NOT_FOUND',
        message: `Route ${request.method} ${request.url.split('?')[0]} not found`,
        requestId: request.id,
      },
    });
  });

  return app;
}
