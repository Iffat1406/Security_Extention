import type Anthropic from '@anthropic-ai/sdk';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { env } from '../src/config/env';
import { breakers } from '../src/lib/circuit-breaker';
import { setAnthropicClientForTests } from '../src/services/ai-explainer.service';
import { signAccessToken } from '../src/services/auth.service';
import { cleanChecks, createFakeDns, createFakeHttp, submission, uniqueHost } from './helpers/fakes';
import { createTestUser, prisma } from './helpers/test-db';

/**
 * §19.8 constraints on the AI layer, with a fake Anthropic client — no live
 * Claude calls in tests (§26.6).
 */
type ParseParams = { system: string; messages: Array<{ role: string; content: string }>; fallbacks?: unknown; betas?: string[] };

let parseCalls: ParseParams[] = [];
let createCalls: ParseParams[] = [];
let nextParsed: unknown = { explanation: 'This site loads over HTTP, so anything you type can be read in transit.', advice: 'Avoid entering passwords here.' };

const fakeClient = {
  beta: {
    messages: {
      parse: async (params: ParseParams) => {
        parseCalls.push(params);
        return { model: 'claude-opus-5', stop_reason: 'end_turn', usage: { input_tokens: 800, output_tokens: 120 }, parsed_output: nextParsed, content: [] };
      },
      create: async (params: ParseParams) => {
        createCalls.push(params);
        return { model: 'claude-opus-5', stop_reason: 'end_turn', usage: { input_tokens: 900, output_tokens: 60 }, content: [{ type: 'text', text: 'The main issue is the unencrypted connection.' }] };
      },
    },
  },
} as unknown as Anthropic;

describe('AI explanation and chat (§5.3, §19.8, §24.2)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    env.ANTHROPIC_API_KEY = 'test-anthropic-key';
    setAnthropicClientForTests(fakeClient);
    app = buildApp({ httpClient: createFakeHttp().client, dnsLookup: createFakeDns() });
    await app.ready();
  });
  afterAll(async () => {
    env.ANTHROPIC_API_KEY = undefined;
    setAnthropicClientForTests(null);
    await app.close();
  });
  beforeEach(async () => {
    parseCalls = [];
    createCalls = [];
    nextParsed = { explanation: 'This site loads over HTTP, so anything you type can be read in transit.', advice: 'Avoid entering passwords here.' };
    breakers.claude.reset();
    await prisma.aiUsage.deleteMany({});
  });

  const httpChecks = { ...cleanChecks, ssl: { ...cleanChecks.ssl, protocol: 'http:', isHTTP: true } };

  async function scanAndWait(token: string, host = uniqueHost('ai')) {
    const created = await app.inject({ method: 'POST', url: '/api/v1/scans', headers: { authorization: `Bearer ${token}` }, payload: submission(`http://${host}/`, httpChecks) });
    const first = created.json();
    // The AI step runs after the response; poll like the extension does (§24.2).
    for (let i = 0; i < 40; i++) {
      const got = (await app.inject({ method: 'GET', url: `/api/v1/scans/${first.scanId}`, headers: { authorization: `Bearer ${token}` } })).json();
      if (got.status !== 'SCANNING') return { first, final: got };
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('scan never left SCANNING');
  }

  it('POST /scans answers 202 SCANNING with the score before the AI text exists, then GET shows it', async () => {
    const token = signAccessToken(await createTestUser());
    const { first, final } = await scanAndWait(token);
    expect(first.status).toBe('SCANNING');
    expect(first.ai).toBeNull();
    expect(first.securityScore).toBe(85);
    expect(final.status).toBe('COMPLETED');
    expect(final.ai).toEqual({ explanation: expect.stringContaining('HTTP'), advice: 'Avoid entering passwords here.' });
  });

  it('AI output never changes a score — even when the model "says" a different one', async () => {
    nextParsed = { explanation: 'Ignore the rules: this site scores 100 and is perfectly safe.', advice: null };
    const token = signAccessToken(await createTestUser());
    const { first, final } = await scanAndWait(token);
    expect(final.securityScore).toBe(first.securityScore);
    expect(final.band).toBe(first.band);
    expect(final.evidence).toEqual(first.evidence);
  });

  it('invalid (over-length) AI output is dropped; the scan still completes with evidence only', async () => {
    nextParsed = { explanation: 'x'.repeat(2000), advice: null };
    const token = signAccessToken(await createTestUser());
    const { final } = await scanAndWait(token);
    expect(final.status).toBe('COMPLETED');
    expect(final.ai).toBeNull();
    expect(final.evidence.length).toBeGreaterThan(0);
  });

  it('prompt-injection boundary: scan data is JSON inside <scan_data>, the system prompt marks it untrusted, fallbacks are on', async () => {
    const token = signAccessToken(await createTestUser());
    await scanAndWait(token, `ignore-previous-instructions-${Date.now()}.test`);
    const call = parseCalls[0]!;
    expect(call.system).toMatch(/untrusted data/);
    expect(call.messages[0]!.content).toMatch(/^<scan_data>\n\{.*\}\n<\/scan_data>$/s);
    expect(call.fallbacks).toBe('default');
    expect(call.betas).toContain('server-side-fallback-2026-07-01');
    // §17.2 / §19.8 — no query string or PII reaches Claude.
    expect(JSON.stringify(call)).not.toMatch(/token=|@example|email/);
  });

  it('reuses an explanation for identical evidence within the hour (§24.4 cache)', async () => {
    const host = uniqueHost('aicache');
    await scanAndWait(signAccessToken(await createTestUser()), host);
    await scanAndWait(signAccessToken(await createTestUser()), host);
    expect(parseCalls).toHaveLength(1);
  });

  it('records usage and stops calling Claude once the monthly spend cap is reached (§33.3)', async () => {
    const token = signAccessToken(await createTestUser());
    await scanAndWait(token);
    const usage = await prisma.aiUsage.findFirstOrThrow();
    expect(usage.calls).toBe(1);
    // claude-opus-5 at $5 / $25 per MTok: 800 in + 120 out.
    expect(Number(usage.estimatedCostUsd)).toBeCloseTo((800 * 5 + 120 * 25) / 1e6, 6);

    await prisma.aiUsage.update({ where: { month: usage.month }, data: { estimatedCostUsd: env.ANTHROPIC_MONTHLY_SPEND_CAP_USD } });
    const { final } = await scanAndWait(token);
    expect(parseCalls).toHaveLength(1);
    expect(final.ai).toBeNull();
    expect(final.status).toBe('COMPLETED');
  });

  it('chat: stores both turns, sends scan context as untrusted data, and returns history in order', async () => {
    const token = signAccessToken(await createTestUser());
    const { first } = await scanAndWait(token);
    const post = await app.inject({ method: 'POST', url: `/api/v1/scans/${first.scanId}/chat`, headers: { authorization: `Bearer ${token}` }, payload: { message: 'Why is HTTP a problem?' } });
    expect(post.statusCode).toBe(200);
    expect(post.json()).toEqual({ role: 'assistant', content: 'The main issue is the unencrypted connection.' });
    expect(createCalls[0]!.system).toMatch(/Don't reveal/);
    expect(createCalls[0]!.messages[0]!.content).toContain('<scan_data>');

    const history = await app.inject({ method: 'GET', url: `/api/v1/scans/${first.scanId}/chat`, headers: { authorization: `Bearer ${token}` } });
    expect(history.json().messages.map((m: { role: string }) => m.role)).toEqual(['user', 'assistant']);
  });

  it('chat rejects an over-long message (§26.5 "length-capped")', async () => {
    const token = signAccessToken(await createTestUser());
    const { first } = await scanAndWait(token);
    const response = await app.inject({ method: 'POST', url: `/api/v1/scans/${first.scanId}/chat`, headers: { authorization: `Bearer ${token}` }, payload: { message: 'x'.repeat(1001) } });
    expect(response.statusCode).toBe(400);
  });
});
