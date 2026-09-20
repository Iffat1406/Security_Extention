import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app';

// Exercises the real app end to end against the dev Postgres container
// (docker-compose.yml) — requires `docker compose up -d` to have been run.
describe('health endpoints — §28.3', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health returns only { status: "ok" }, never a dependency check', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });

  it('GET /health/ready reports postgres and migrations as healthy', async () => {
    const response = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: 'ok',
      dependencies: { postgres: true, migrations: true },
    });
  });

  it('an unknown route returns the standard error envelope with a requestId', async () => {
    const response = await app.inject({ method: 'GET', url: '/no-such-route' });
    expect(response.statusCode).toBe(404);
    const body = response.json();
    expect(body.error.code).toBe('NOT_FOUND');
    expect(body.error.requestId).toMatch(/^req_[0-9a-f]{8}$/);
  });
});
