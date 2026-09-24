import { randomBytes } from 'node:crypto';
import path from 'node:path';
import fastifyCookie from '@fastify/cookie';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import fastifyStatic from '@fastify/static';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import Fastify, { LogController, type FastifyError, type FastifyInstance, type FastifyRequest } from 'fastify';
import { jsonSchemaTransform, serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { ZodError, z } from 'zod';
import { API_PREFIX, SCANNER_VERSION } from '@guardtab/shared';
import { env } from './config/env';
import { AppError } from './lib/errors';
import rateLimitPlugin from './lib/rate-limit';
import { authenticate, authorize } from './middleware/auth.middleware';
import authPlugin from './plugins/auth';
import dbPlugin from './plugins/db';
import { RISK_ENGINE_VERSION } from './risk-engine/weights';
import { defaultHttpClient, type HttpClient } from './services/external/types';
import { systemDnsLookup, type DnsLookup } from './services/url-safety.service';
import adminRoutes from './routes/admin.routes';
import authRoutes from './routes/auth.routes';
import chatRoutes from './routes/chat.routes';
import dashboardRoutes from './routes/dashboard.routes';
import healthRoutes from './routes/health.routes';
import scanRoutes from './routes/scan.routes';
import threatsRoutes from './routes/threats.routes';
import usersRoutes from './routes/users.routes';

/** `req_` + 8 hex chars, matching §25.5/§28.1. Not a secret — it correlates a log line with an error. */
function generateRequestId(): string {
  return `req_${randomBytes(4).toString('hex')}`;
}

/** Route pattern only — never the populated path or query string (§28.1). */
function routeLabel(request: FastifyRequest): string {
  return request.routeOptions?.url ?? request.url.split('?')[0]!;
}

/** §26.5 "12MB JSON body posted to /scans -> 413 payload rejected before parsing". A real scan payload is a few KB. */
const BODY_LIMIT_BYTES = 256 * 1024;

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/** §18.3 / §34 "CORS allow-list — Only the extension id and dashboard origin accepted". */
function corsAllowList(): Set<string> {
  const origins = new Set<string>([new URL(env.PUBLIC_BASE_URL).origin]);
  if (env.EXTENSION_ID) origins.add(`chrome-extension://${env.EXTENSION_ID}`);
  for (const o of (env.CORS_ORIGIN ?? '').split(',').map((s) => s.trim()).filter(Boolean)) origins.add(o);
  return origins;
}

export interface BuildAppOptions {
  /** Replaces every outbound third-party call (tests: §26.3 "External APIs are intercepted"). */
  httpClient?: HttpClient;
  /** Replaces DNS for the POST /scans SSRF check (tests only). */
  dnsLookup?: DnsLookup;
}

declare module 'fastify' {
  interface FastifyInstance {
    externalHttp: HttpClient;
    dnsLookup: DnsLookup;
  }
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const app = Fastify({
    genReqId: generateRequestId,
    trustProxy: true,
    bodyLimit: BODY_LIMIT_BYTES,
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: env.LOG_LEVEL,
      // §28.1 redaction rules, configured centrally so a new log call can't leak a token.
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["set-cookie"]',
          'res.headers["set-cookie"]',
          '*.accessToken',
          '*.refreshToken',
          '*.password',
          '*.url',
          '*.email',
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

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('externalHttp', options.httpClient ?? defaultHttpClient);
  app.decorate('dnsLookup', options.dnsLookup ?? systemDnsLookup);

  // ---- security headers (§34 "CSP, HSTS, X-Content-Type-Options, Referrer-Policy set") ----
  app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https://lh3.googleusercontent.com'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    strictTransportSecurity: env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginResourcePolicy: { policy: 'same-site' },
  });

  const allowList = corsAllowList();
  app.register(fastifyCors, {
    origin: (origin, callback) => callback(null, origin === undefined || allowList.has(origin)),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['authorization', 'content-type'],
    exposedHeaders: ['x-request-id', 'retry-after'],
    maxAge: 600,
  });

  app.register(dbPlugin);
  app.register(fastifyCookie, { secret: env.COOKIE_SECRET });
  app.register(rateLimitPlugin);
  app.register(authPlugin);

  // ---- OpenAPI (§25.6) — generated from the same Zod schemas that validate requests ----
  app.register(fastifySwagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'GuardTab API',
        version: '0.1.0',
        description: `Risk engine ${RISK_ENGINE_VERSION}, scanner ${SCANNER_VERSION}.`,
      },
      components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
    },
    transform: jsonSchemaTransform,
  });
  app.register(fastifySwaggerUi, {
    routePrefix: '/docs',
    staticCSP: true,
    // "Swagger UI is served at /docs in development and staging, and behind ADMIN authentication in production."
    uiHooks:
      env.NODE_ENV === 'production'
        ? {
            onRequest: async (request, reply) => {
              await authenticate(request, reply);
              await authorize('ADMIN')(request, reply);
            },
          }
        : {},
  });

  // ---- static: dashboard (Phase 8) and privacy policy (§17.5) ----
  app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: '/', index: false, wildcard: false });
  app.get('/', { schema: { hide: true } }, (_request, reply) => reply.redirect('/dashboard/'));
  app.get('/dashboard', { schema: { hide: true } }, (_request, reply) => reply.redirect('/dashboard/'));
  app.get('/dashboard/', { schema: { hide: true } }, (_request, reply) => reply.sendFile('dashboard/index.html'));
  app.get('/privacy', { schema: { hide: true } }, (_request, reply) => reply.sendFile('privacy.html'));

  // ---- routes ----
  app.register(healthRoutes);
  app.register(authRoutes, { prefix: API_PREFIX });
  app.register(scanRoutes, { prefix: API_PREFIX });
  app.register(chatRoutes, { prefix: API_PREFIX });
  app.register(usersRoutes, { prefix: API_PREFIX });
  app.register(threatsRoutes, { prefix: API_PREFIX });
  app.register(dashboardRoutes, { prefix: API_PREFIX });
  app.register(adminRoutes, { prefix: API_PREFIX });

  // §28.1 "requestId ... returned in every error envelope and in a response header".
  app.addHook('onSend', async (request, reply) => {
    reply.header('x-request-id', request.id);
  });

  // §28.1 structured request log line.
  app.addHook('onResponse', async (request, reply) => {
    request.log.info(
      {
        requestId: request.id,
        route: routeLabel(request),
        userId: request.authUser?.id ?? null,
        status: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
        ...(request.scanLog ? { domain: request.scanLog.domain, scanStatus: request.scanLog.scanStatus, deps: request.scanLog.deps } : {}),
        ...(request.errorCode ? { errorCode: request.errorCode } : {}),
      },
      'request completed'
    );
  });

  // Standard error envelope — §25.5. Every non-2xx response uses this shape and never leaks a stack trace.
  app.setErrorHandler((error: FastifyError | AppError | ZodError, request, reply) => {
    const requestId = request.id;
    const send = (status: number, code: string, message: string, details?: Record<string, unknown>) => {
      request.errorCode = code;
      reply.status(status).send({ error: { code, message, requestId, ...(details ? { details } : {}) } });
    };

    if (error instanceof AppError) {
      request.log.warn({ requestId, errorCode: error.code, err: error.message }, 'handled application error');
      if (error.code === 'RATE_LIMITED' && typeof error.details?.retryAfter === 'number') {
        reply.header('retry-after', String(error.details.retryAfter));
      }
      return send(error.httpStatus, error.code, error.message, error.details);
    }
    if (error instanceof ZodError) {
      return send(400, 'VALIDATION_ERROR', 'Request validation failed', { issues: z.flattenError(error) });
    }
    if (error.validation) {
      return send(400, 'VALIDATION_ERROR', 'Request validation failed', {
        issues: error.validation.map((v) => ({ path: v.instancePath, message: v.message })),
      });
    }
    if (error.statusCode === 413) return send(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    if (error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') return send(415, 'VALIDATION_ERROR', 'Unsupported content type');
    // Malformed JSON, empty JSON body, bad content-length — client errors, not server faults.
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return send(error.statusCode === 404 ? 404 : 400, error.statusCode === 404 ? 'NOT_FOUND' : 'VALIDATION_ERROR', 'Malformed request');
    }

    request.log.error({ requestId, err: error }, 'unhandled error');
    return send(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  });

  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      error: { code: 'NOT_FOUND', message: `Route ${request.method} ${request.url.split('?')[0]} not found`, requestId: request.id },
    });
  });

  return app;
}

declare module 'fastify' {
  interface FastifyRequest {
    errorCode?: string;
  }
}
