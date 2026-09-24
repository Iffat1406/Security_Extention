import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { env } from '../src/config/env';
import { breakers } from '../src/lib/circuit-breaker';
import { signAccessToken } from '../src/services/auth.service';
import { RESPONSES, cleanChecks, createFakeDns, createFakeHttp, submission, uniqueHost, type FakeHttpHandlers } from './helpers/fakes';
import { createTestUser, prisma } from './helpers/test-db';

/**
 * POST /scans end to end against real PostgreSQL, with every external
 * service faked (§26.3). Covers the Phase 5 milestone ("A known-bad test URL
 * turns the badge red; a VirusTotal outage yields PARTIAL, not FAILED") and
 * the §26.5 SSRF cases.
 */
describe('POST /api/v1/scans', () => {
  let app: FastifyInstance;
  let handlers: FakeHttpHandlers;
  const fakeHttp = createFakeHttp({
    safeBrowsing: (b) => (handlers.safeBrowsing ?? RESPONSES.sbClean)(b),
    virusTotal: (u) => (handlers.virusTotal ?? RESPONSES.vtNotFound)(u),
    rdap: (d) => (handlers.rdap ?? (() => RESPONSES.rdapAge(4000)))(d),
  });

  beforeAll(async () => {
    // Keys are only ever sent to the fake client above.
    env.SAFE_BROWSING_API_KEY = 'test-sb-key';
    env.VIRUSTOTAL_API_KEY = 'test-vt-key';
    app = buildApp({
      httpClient: fakeHttp.client,
      dnsLookup: createFakeDns({ 'resolves-private.example.com': '10.0.0.5', 'metadata-alias.example.com': '169.254.169.254' }),
    });
    await app.ready();
  });

  afterAll(async () => {
    env.SAFE_BROWSING_API_KEY = undefined;
    env.VIRUSTOTAL_API_KEY = undefined;
    await app.close();
  });

  beforeEach(() => {
    handlers = {};
    for (const b of Object.values(breakers)) b.reset();
  });

  const post = (payload: unknown, token?: string) =>
    app.inject({
      method: 'POST',
      url: '/api/v1/scans',
      payload: payload as Record<string, unknown>,
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });

  it('anonymous: scores the page but persists nothing (§17.4, §34 "Anonymous mode persists nothing")', async () => {
    const host = uniqueHost('anon');
    const response = await post(submission(`https://${host}/products?id=1&token=abc`));
    expect(response.statusCode).toBe(202);
    const body = response.json();
    expect(body).toMatchObject({ scanId: null, persisted: false, registrableDomain: host, band: 'SAFE', status: 'COMPLETED' });
    expect(await prisma.scanResult.count({ where: { registrableDomain: host } })).toBe(0);
  });

  it('signed in: persists the scan without the query string or fragment (§17.2)', async () => {
    const user = await createTestUser();
    const host = uniqueHost('stored');
    const response = await post(submission(`https://www.${host}/Account/Orders?email=a%40b.com&token=secret#frag`), signAccessToken(user));
    expect(response.statusCode).toBe(202);
    const body = response.json();
    expect(body.persisted).toBe(true);
    expect(body.scanId).toBeTruthy();

    const row = await prisma.scanResult.findUniqueOrThrow({ where: { id: body.scanId } });
    expect(row).toMatchObject({ host: `www.${host}`, registrableDomain: host, path: '/Account/Orders', riskEngineVersion: '1.0.0', scannerVersion: '1.0.0' });
    // §34 "No full URLs in the database": nothing anywhere in the row carries the query.
    const serialized = JSON.stringify(row);
    expect(serialized).not.toContain('secret');
    expect(serialized).not.toContain('a%40b.com');
    expect(serialized).not.toContain('frag');
  });

  it('Phase 5 milestone: a known-bad URL turns the badge red, and VirusTotal is skipped once Safe Browsing flags it', async () => {
    handlers.safeBrowsing = () => RESPONSES.sbMalicious('SOCIAL_ENGINEERING');
    const response = await post(submission(`https://${uniqueHost('phish')}/login`, { ...cleanChecks, ssl: { ...cleanChecks.ssl, isValid: false, certError: 'net::ERR_CERT_DATE_INVALID' } }));
    const body = response.json();
    // 60 + 20 penalty -> security 20: HIGH, which like CRITICAL is a red badge (§19.4).
    expect(body.securityScore).toBe(20);
    expect(['HIGH', 'CRITICAL']).toContain(body.band);
    expect(body.evidence[0].signal).toBe('SAFE_BROWSING_MALICIOUS');
    expect(body.checks.virusTotal).toBe('SKIPPED');
    expect(body.skipped).toContainEqual({ signal: 'VIRUSTOTAL', reason: 'SAFE_BROWSING_MALICIOUS' });
    expect(body.details.safeBrowsing).toEqual({ isMalicious: true, threatTypes: ['SOCIAL_ENGINEERING'] });
  });

  it('Phase 5 milestone: a VirusTotal outage yields PARTIAL, not FAILED, and the scan still scores', async () => {
    handlers.virusTotal = () => RESPONSES.serverError();
    const response = await post(submission(`https://${uniqueHost('vtdown')}/`));
    const body = response.json();
    expect(response.statusCode).toBe(202);
    expect(body.status).toBe('PARTIAL');
    expect(body.securityScore).toBe(100);
    expect(body.checks.virusTotal).toBe('UNAVAILABLE');
  });

  it('§26.3: every external source failing still produces a score from local signals', async () => {
    handlers.safeBrowsing = () => 'timeout';
    handlers.virusTotal = () => 'network-error';
    handlers.rdap = () => RESPONSES.serverError();
    const response = await post(
      submission(`http://${uniqueHost('alldown')}/`, { ...cleanChecks, ssl: { ...cleanChecks.ssl, protocol: 'http:', isHTTP: true } })
    );
    const body = response.json();
    expect(body.status).toBe('PARTIAL');
    expect(body.securityScore).toBe(85 - 3 + 3); // HTTP (−15); HSTS isn't charged on an HTTP page
    expect(body.evidence.map((e: { signal: string }) => e.signal)).toContain('SERVED_OVER_HTTP');
  });

  it('cross-user dedup: the same page within 10 minutes calls Safe Browsing once (§5.1 Feature 2)', async () => {
    const url = `https://${uniqueHost('dedup')}/page`;
    const before = fakeHttp.count('safeBrowsing');
    await post(submission(url));
    await post(submission(url), signAccessToken(await createTestUser()));
    expect(fakeHttp.count('safeBrowsing') - before).toBe(1);
  });

  it('rescan bypasses the Safe Browsing dedup window (§23.3)', async () => {
    const url = `https://${uniqueHost('rescan')}/`;
    const token = signAccessToken(await createTestUser());
    const before = fakeHttp.count('safeBrowsing');
    await post(submission(url), token);
    await post(submission(url, cleanChecks, { rescan: true }), token);
    expect(fakeHttp.count('safeBrowsing') - before).toBe(2);
  });

  it('the circuit breaker opens after five consecutive failures and fails fast (§24.4)', async () => {
    handlers.safeBrowsing = () => RESPONSES.serverError();
    // A call and its one retry count as a single breaker failure.
    for (let i = 0; i < 5; i++) await post(submission(`https://${uniqueHost('cb')}/`));
    expect(breakers.safeBrowsing.state).toBe('OPEN');
    const callsBefore = fakeHttp.count('safeBrowsing');
    const body = (await post(submission(`https://${uniqueHost('cb')}/`))).json();
    expect(fakeHttp.count('safeBrowsing')).toBe(callsBefore);
    expect(body.skipped).toContainEqual({ signal: 'SAFEBROWSING', reason: 'EXTERNAL_SERVICE_UNAVAILABLE:CIRCUIT_OPEN' });
  });

  it('Safe Browsing receives the URL with sensitive parameters stripped (§20.3)', async () => {
    const host = uniqueHost('params');
    await post(submission(`https://${host}/reset?token=abc&page=2&email=x%40y.com`));
    const sent = fakeHttp.calls.filter((c) => c.service === 'safeBrowsing').at(-1)!;
    const url = JSON.parse(sent.request.body!).threatInfo.threatEntries[0].url as string;
    expect(url).toContain('page=2');
    expect(url).not.toContain('token');
    expect(url).not.toContain('email');
  });

  it('flags a lookalike domain and a young domain from WHOIS', async () => {
    handlers.rdap = () => RESPONSES.rdapAge(6);
    const body = (await post(submission('https://paypal-login.com/'))).json();
    const signals = body.evidence.map((e: { signal: string }) => e.signal);
    expect(signals).toContain('LOOKALIKE_DOMAIN');
    expect(signals).toContain('DOMAIN_VERY_YOUNG');
    expect(body.details.lookalike.brand).toBe('PayPal');
  });

  describe('§26.5 SSRF cases — 400 before anything is attempted', () => {
    it.each([
      ['http://169.254.169.254/latest/meta-data', 'BLOCKED_TARGET'],
      ['http://127.0.0.1:5432', 'BLOCKED_TARGET'],
      ['http://2130706433', 'BLOCKED_TARGET'],
      ['file:///etc/passwd', 'UNSUPPORTED_SCHEME'],
      ['https://resolves-private.example.com/', 'BLOCKED_TARGET'],
      ['https://metadata-alias.example.com/', 'BLOCKED_TARGET'],
      ['https://user:pass@example.com/', 'INVALID_URL'],
      [`https://example.com/${'a'.repeat(2100)}`, 'URL_TOO_LONG'],
    ])('%s -> %s', async (url, code) => {
      const response = await post(submission(url));
      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe(code);
    });
  });

  it('browser-internal pages are 200 NOT_SUPPORTED with nothing stored (§20.5)', async () => {
    const response = await post(submission('chrome://settings'));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: 'NOT_SUPPORTED', notSupportedReason: 'BROWSER_INTERNAL', persisted: false });
  });

  it('user-excluded domains are NOT_SUPPORTED and never stored, even if the extension sends them (§23.2)', async () => {
    const user = await createTestUser();
    const host = uniqueHost('excluded');
    await prisma.userSettings.create({ data: { userId: user.id, settings: {}, excludedDomains: [host] } });
    const response = await post(submission(`https://intranet.${host}/`), signAccessToken(user));
    expect(response.json()).toMatchObject({ status: 'NOT_SUPPORTED', notSupportedReason: 'USER_EXCLUDED' });
    expect(await prisma.scanResult.count({ where: { userId: user.id } })).toBe(0);
  });

  it('"Store scan history: OFF" scans without persisting (§23.1)', async () => {
    const user = await createTestUser();
    await prisma.userSettings.create({ data: { userId: user.id, settings: { storeScanHistory: false }, excludedDomains: [] } });
    const body = (await post(submission(`https://${uniqueHost('nostore')}/`), signAccessToken(user))).json();
    expect(body.persisted).toBe(false);
    expect(await prisma.scanResult.count({ where: { userId: user.id } })).toBe(0);
  });

  it('"Store page paths: OFF" keeps only the domain (§17.2)', async () => {
    const user = await createTestUser();
    await prisma.userSettings.create({ data: { userId: user.id, settings: { storePagePaths: false }, excludedDomains: [] } });
    const body = (await post(submission(`https://${uniqueHost('nopath')}/secret/area`), signAccessToken(user))).json();
    const row = await prisma.scanResult.findUniqueOrThrow({ where: { id: body.scanId } });
    expect(row.path).toBeNull();
  });

  it('"Tracker detection: OFF" drops tracker data even if posted, and privacy is unavailable (§23.1, §18.4)', async () => {
    const user = await createTestUser();
    await prisma.userSettings.create({ data: { userId: user.id, settings: { trackerDetection: false }, excludedDomains: [] } });
    const body = (await post(submission(`https://${uniqueHost('notrack')}/`), signAccessToken(user))).json();
    expect(body.privacyScore).toBeNull();
    expect((await prisma.scanResult.findUniqueOrThrow({ where: { id: body.scanId } })).trackerData).toBeNull();
  });

  it('§26.5 "12MB JSON body" -> 413 before parsing', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/scans',
      headers: { 'content-type': 'application/json' },
      payload: `{"url":"${'a'.repeat(12 * 1024 * 1024)}"}`,
    });
    expect(response.statusCode).toBe(413);
    expect(response.json().error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  it('§26.5 malformed JSON -> 400 VALIDATION_ERROR with no stack trace', async () => {
    const response = await app.inject({ method: 'POST', url: '/api/v1/scans', headers: { 'content-type': 'application/json' }, payload: '{"url": ' });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(response.body).not.toMatch(/at \w+ \(|node_modules/);
  });

  it('rejects unknown fields in a check payload (§18.4 "the extension is not a trusted client")', async () => {
    const response = await post(submission(`https://${uniqueHost()}/`, { passwordBreach: { status: 'OK', isBreached: true, breachCount: 1, hashPrefix: 'ABCDE' } }));
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
  });

  it('§26.5 rate limit boundary: the 11th rescan in an hour is 429 with Retry-After', async () => {
    const token = signAccessToken(await createTestUser());
    const url = `https://${uniqueHost('rl')}/`;
    for (let i = 0; i < 10; i++) expect((await post(submission(url, cleanChecks, { rescan: true }), token)).statusCode).toBe(202);
    const blocked = await post(submission(url, cleanChecks, { rescan: true }), token);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json().error.code).toBe('RATE_LIMITED');
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('feeds threat intelligence: a Safe Browsing hit makes the domain MALICIOUS in the public feed (§22)', async () => {
    handlers.safeBrowsing = () => RESPONSES.sbMalicious('MALWARE');
    const host = uniqueHost('intel');
    await post(submission(`https://${host}/`));
    const response = await app.inject({ method: 'GET', url: `/api/v1/threats/domain/${host}` });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.reputation).toBe('MALICIOUS');
    expect(body.indicators.map((i: { type: string }) => i.type)).toContain('MALWARE');
    // §22.5 "No individual browsing history is exposed."
    expect(JSON.stringify(body)).not.toMatch(/userId|user_id|email/);
  });
});

describe('scan reads, updates and feedback', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    app = buildApp({ httpClient: createFakeHttp().client, dnsLookup: createFakeDns() });
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
  });

  async function scanAs(token: string, host = uniqueHost()) {
    const response = await app.inject({ method: 'POST', url: '/api/v1/scans', payload: submission(`https://${host}/`), headers: { authorization: `Bearer ${token}` } });
    return response.json() as { scanId: string; securityScore: number };
  }

  it('GET /scans/:id returns the owner their scan', async () => {
    const token = signAccessToken(await createTestUser());
    const { scanId } = await scanAs(token);
    const response = await app.inject({ method: 'GET', url: `/api/v1/scans/${scanId}`, headers: { authorization: `Bearer ${token}` } });
    expect(response.statusCode).toBe(200);
    expect(response.json().scanId).toBe(scanId);
  });

  it('§26.5 IDOR: another user\'s scan id is 404 SCAN_NOT_FOUND, never 403', async () => {
    const { scanId } = await scanAs(signAccessToken(await createTestUser()));
    const intruder = signAccessToken(await createTestUser());
    for (const method of ['GET', 'DELETE'] as const) {
      const response = await app.inject({ method, url: `/api/v1/scans/${scanId}`, headers: { authorization: `Bearer ${intruder}` } });
      expect(response.statusCode).toBe(404);
      expect(response.json().error.code).toBe('SCAN_NOT_FOUND');
    }
  });

  it('PATCH /scans/:id merges a later local result and re-scores (§30.3)', async () => {
    const token = signAccessToken(await createTestUser());
    const { scanId, securityScore } = await scanAs(token);
    const response = await app.inject({
      method: 'PATCH',
      url: `/api/v1/scans/${scanId}`,
      headers: { authorization: `Bearer ${token}` },
      payload: { checks: { mixedContent: { status: 'OK', mixedCount: 1, activeCount: 1, passiveCount: 0, resources: [{ type: 'script', host: 'cdn.example.test', active: true }] } } },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().securityScore).toBe(securityScore - 10);
  });

  it('GET /scans/history paginates the caller\'s scans only', async () => {
    const token = signAccessToken(await createTestUser());
    await scanAs(token);
    await scanAs(token);
    const response = await app.inject({ method: 'GET', url: '/api/v1/scans/history?limit=1', headers: { authorization: `Bearer ${token}` } });
    expect(response.json()).toMatchObject({ total: 2, page: 1 });
    expect(response.json().scans).toHaveLength(1);
  });

  it('feedback: one per scan, and a FALSE_NEGATIVE report creates a COMMUNITY indicator (§22.3)', async () => {
    const token = signAccessToken(await createTestUser());
    const host = uniqueHost('report');
    const { scanId } = await scanAs(token, host);
    const url = `/api/v1/scans/${scanId}/feedback`;
    const first = await app.inject({ method: 'POST', url, headers: { authorization: `Bearer ${token}` }, payload: { feedbackType: 'FALSE_NEGATIVE', reason: 'Asked for my bank <script>alert(1)</script> password' } });
    expect(first.statusCode).toBe(201);
    const second = await app.inject({ method: 'POST', url, headers: { authorization: `Bearer ${token}` }, payload: { feedbackType: 'FALSE_NEGATIVE' } });
    expect(second.statusCode).toBe(400);

    const domain = await prisma.domain.findUniqueOrThrow({ where: { domain: host }, include: { indicators: true } });
    expect(domain.indicators.map((i) => `${i.type}/${i.source}`)).toContain('SCAM/COMMUNITY');
    // Community-only: never MALICIOUS (§22.4).
    expect(domain.reputation).not.toBe('MALICIOUS');
    // Stored literally, never interpreted (§26.5).
    const stored = await prisma.scanFeedback.findFirstOrThrow({ where: { scanId } });
    expect(stored.reason).toContain('<script>');
  });

  it('§26.5 SQL metacharacters in a domain are stored and returned literally', async () => {
    const response = await app.inject({ method: 'GET', url: `/api/v1/threats/domain/${encodeURIComponent("x' OR 1=1; DROP TABLE users; --")}` });
    expect(response.statusCode).toBe(404);
    expect(await prisma.user.count()).toBeGreaterThan(0);
  });
});
