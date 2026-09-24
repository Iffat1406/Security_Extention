import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { JOBS, finaliseAccountDeletion } from '../src/jobs/definitions';
import { issueRefreshToken, signAccessToken } from '../src/services/auth.service';
import { createExportToken, verifyExportToken } from '../src/services/export.service';
import { createFakeDns, createFakeHttp, submission, uniqueHost } from './helpers/fakes';
import { createTestUser, prisma } from './helpers/test-db';

const job = (name: string) => JOBS.find((j) => j.name === name)!;
const silentLog = { info: () => undefined, warn: () => undefined };

describe('§23 settings, §29 retention, export and deletion', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    app = buildApp({ httpClient: createFakeHttp().client, dnsLookup: createFakeDns() });
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
  });

  const auth = (token: string) => ({ authorization: `Bearer ${token}` });
  const scan = async (token: string, host = uniqueHost()) =>
    (await app.inject({ method: 'POST', url: '/api/v1/scans', payload: submission(`https://${host}/`), headers: auth(token) })).json() as { scanId: string };

  describe('settings', () => {
    it('returns defaults, applies a partial update, and audits it', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const initial = await app.inject({ method: 'GET', url: '/api/v1/users/me/settings', headers: auth(token) });
      expect(initial.json().settings).toMatchObject({ autoScan: true, scanRetentionDays: 90 });

      const patched = await app.inject({ method: 'PATCH', url: '/api/v1/users/me/settings', headers: auth(token), payload: { aiChat: false, scanRetentionDays: 30 } });
      expect(patched.statusCode).toBe(200);
      expect(patched.json().settings).toMatchObject({ aiChat: false, scanRetentionDays: 30, autoScan: true });
      expect(await prisma.auditLog.count({ where: { userId: user.id, action: 'SETTINGS_UPDATE' } })).toBe(1);
    });

    it('rejects unknown keys (§23.4)', async () => {
      const token = signAccessToken(await createTestUser());
      const response = await app.inject({ method: 'PATCH', url: '/api/v1/users/me/settings', headers: auth(token), payload: { telemetry: true } });
      expect(response.statusCode).toBe(400);
    });

    it('adding an exclusion normalises it and clears stored scans for that domain and its subdomains (§23.2)', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const host = uniqueHost('exclude');
      await scan(token, host);
      await scan(token, `www.${host}`);
      const keep = await scan(token);

      const response = await app.inject({ method: 'POST', url: '/api/v1/users/me/exclusions', headers: auth(token), payload: { domain: `HTTPS://WWW.${host.toUpperCase()}/some/path` } });
      expect(response.json().excludedDomains).toEqual([host]);
      const remaining = await prisma.scanResult.findMany({ where: { userId: user.id }, select: { id: true } });
      expect(remaining.map((r) => r.id)).toEqual([keep.scanId]);

      const removed = await app.inject({ method: 'DELETE', url: `/api/v1/users/me/exclusions/${host}`, headers: auth(token) });
      expect(removed.json().excludedDomains).toEqual([]);
    });

    it('turning AI chat off makes the chat endpoint refuse (§23.1)', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const { scanId } = await scan(token);
      await app.inject({ method: 'PATCH', url: '/api/v1/users/me/settings', headers: auth(token), payload: { aiChat: false } });
      const response = await app.inject({ method: 'POST', url: `/api/v1/scans/${scanId}/chat`, headers: auth(token), payload: { message: 'Is this safe?' } });
      expect(response.statusCode).toBe(403);
      expect(await prisma.scanChat.count({ where: { userId: user.id } })).toBe(0);
    });
  });

  describe('export (§29.3)', () => {
    it('requires a fresh sign-in — a token whose sign-in is an hour old is refused (§18.3)', async () => {
      const user = await createTestUser();
      const stale = signAccessToken(user, new Date(Date.now() - 60 * 60 * 1000));
      const response = await app.inject({ method: 'GET', url: '/api/v1/users/me/export', headers: auth(stale) });
      expect(response.statusCode).toBe(401);
      expect(response.json().error.details.reason).toBe('FRESH_AUTH_REQUIRED');
    });

    it('issues signed links, is limited to one per 24h, and the JSON matches the database', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const { scanId } = await scan(token);

      const first = await app.inject({ method: 'GET', url: '/api/v1/users/me/export', headers: auth(token) });
      expect(first.statusCode).toBe(200);
      const links = first.json() as { json: string; csv: string };
      expect(await prisma.auditLog.count({ where: { userId: user.id, action: 'ACCOUNT_EXPORT' } })).toBe(1);

      const second = await app.inject({ method: 'GET', url: '/api/v1/users/me/export', headers: auth(token) });
      expect(second.statusCode).toBe(429);

      const jsonPath = new URL(links.json).pathname + new URL(links.json).search;
      const download = await app.inject({ method: 'GET', url: jsonPath });
      expect(download.statusCode).toBe(200);
      expect(download.headers['content-disposition']).toContain('attachment');
      const archive = download.json();
      expect(archive.profile.id).toBe(user.id);
      expect(archive.scans.map((s: { id: string }) => s.id)).toEqual([scanId]);

      const csvPath = new URL(links.csv).pathname + new URL(links.csv).search;
      const csv = await app.inject({ method: 'GET', url: csvPath });
      expect(csv.headers['content-type']).toContain('text/csv');
      expect(csv.body.split('\r\n')[0]).toContain('registrableDomain');
    });

    it('export tokens are tamper-proof and expire', () => {
      const { token } = createExportToken('user-1');
      expect(verifyExportToken(token)).toBe('user-1');
      expect(verifyExportToken(`${token}x`)).toBeNull();
      expect(verifyExportToken(token, Date.now() + 11 * 60 * 1000)).toBeNull();
      const [payload] = token.split('.');
      const forged = Buffer.from(JSON.stringify({ u: 'someone-else', exp: Date.now() + 60_000 })).toString('base64url');
      expect(verifyExportToken(token.replace(payload!, forged))).toBeNull();
    });
  });

  describe('deletion (§29.2)', () => {
    it('DELETE /users/me needs the word DELETE, starts the grace period and signs out every device', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      await issueRefreshToken(prisma, user.id);
      expect((await app.inject({ method: 'DELETE', url: '/api/v1/users/me', headers: auth(token), payload: { confirm: 'yes' } })).statusCode).toBe(400);

      const response = await app.inject({ method: 'DELETE', url: '/api/v1/users/me', headers: auth(token), payload: { confirm: 'DELETE' } });
      expect(response.statusCode).toBe(200);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).deletionRequestedAt).not.toBeNull();
      expect(await prisma.refreshToken.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);

      const cancel = await app.inject({ method: 'POST', url: '/api/v1/users/me/cancel-deletion', headers: auth(token) });
      expect(cancel.statusCode).toBe(200);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).deletionRequestedAt).toBeNull();
    });

    it('§34 "Delete a test account; confirm no rows remain in any table" — and domain counters are decremented', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const host = uniqueHost('deleteme');
      const { scanId } = await scan(token, host);
      await app.inject({ method: 'POST', url: `/api/v1/scans/${scanId}/feedback`, headers: auth(token), payload: { feedbackType: 'HELPFUL' } });
      await prisma.scanChat.create({ data: { scanId, userId: user.id, role: 'user', content: 'hi' } });
      await prisma.userSettings.create({ data: { userId: user.id, settings: {}, excludedDomains: [] } });
      await issueRefreshToken(prisma, user.id);
      const before = await prisma.domain.findUniqueOrThrow({ where: { domain: host } });

      await finaliseAccountDeletion(prisma, user.id);

      const counts = await Promise.all([
        prisma.user.count({ where: { id: user.id } }),
        prisma.scanResult.count({ where: { userId: user.id } }),
        prisma.scanChat.count({ where: { userId: user.id } }),
        prisma.scanFeedback.count({ where: { userId: user.id } }),
        prisma.userSettings.count({ where: { userId: user.id } }),
        prisma.refreshToken.count({ where: { userId: user.id } }),
        prisma.auditLog.count({ where: { userId: user.id } }),
      ]);
      expect(counts).toEqual([0, 0, 0, 0, 0, 0, 0]);
      // Audit rows are anonymised, not erased.
      expect(await prisma.auditLog.count({ where: { action: 'ACCOUNT_DELETE', resourceId: user.id, userId: null } })).toBe(1);
      const after = await prisma.domain.findUniqueOrThrow({ where: { domain: host } });
      expect(after.scanCount).toBe(before.scanCount - 1);
      expect(after.uniqueUserCount).toBe(before.uniqueUserCount - 1);
    });

    it('finalise_account_deletions only acts once the grace period has passed', async () => {
      const recent = await createTestUser();
      const due = await createTestUser();
      await prisma.user.update({ where: { id: recent.id }, data: { deletionRequestedAt: new Date() } });
      await prisma.user.update({ where: { id: due.id }, data: { deletionRequestedAt: new Date(Date.now() - 8 * 86_400_000) } });
      await job('finalise_account_deletions').run({ prisma, now: new Date(), log: silentLog });
      expect(await prisma.user.count({ where: { id: recent.id } })).toBe(1);
      expect(await prisma.user.count({ where: { id: due.id } })).toBe(0);
    });
  });

  describe('retention jobs actually delete (§34 "Seed rows past the window, run the job, confirm deletion")', () => {
    it('purge_expired_scans honours each user\'s retention window, including "forever"', async () => {
      const defaultUser = await createTestUser();
      const thirtyDayUser = await createTestUser();
      const foreverUser = await createTestUser();
      await prisma.userSettings.create({ data: { userId: thirtyDayUser.id, settings: { scanRetentionDays: 30 }, excludedDomains: [] } });
      await prisma.userSettings.create({ data: { userId: foreverUser.id, settings: { scanRetentionDays: null }, excludedDomains: [] } });
      const old = (userId: string, days: number) =>
        prisma.scanResult.create({ data: { userId, registrableDomain: 'old.test', host: 'old.test', scannedAt: new Date(Date.now() - days * 86_400_000) } });

      const [d45, d100, t45, t10, f400] = await Promise.all([
        old(defaultUser.id, 45),
        old(defaultUser.id, 100),
        old(thirtyDayUser.id, 45),
        old(thirtyDayUser.id, 10),
        old(foreverUser.id, 400),
      ]);
      await job('purge_expired_scans').run({ prisma, now: new Date(), log: silentLog });
      const exists = async (id: string) => (await prisma.scanResult.count({ where: { id } })) === 1;
      expect(await exists(d45.id)).toBe(true); // default 90 days
      expect(await exists(d100.id)).toBe(false);
      expect(await exists(t45.id)).toBe(false);
      expect(await exists(t10.id)).toBe(true);
      expect(await exists(f400.id)).toBe(true); // forever
    });

    it('purge_expired_chats removes chats older than 30 days', async () => {
      const user = await createTestUser();
      const token = signAccessToken(user);
      const { scanId } = await scan(token);
      const oldChat = await prisma.scanChat.create({ data: { scanId, userId: user.id, role: 'user', content: 'old', createdAt: new Date(Date.now() - 31 * 86_400_000) } });
      const newChat = await prisma.scanChat.create({ data: { scanId, userId: user.id, role: 'user', content: 'new' } });
      await job('purge_expired_chats').run({ prisma, now: new Date(), log: silentLog });
      expect(await prisma.scanChat.count({ where: { id: oldChat.id } })).toBe(0);
      expect(await prisma.scanChat.count({ where: { id: newChat.id } })).toBe(1);
    });

    it('purge_revoked_tokens keeps tokens until expiry + 7 days', async () => {
      const user = await createTestUser();
      const expiredLongAgo = await prisma.refreshToken.create({
        data: { userId: user.id, tokenHash: `h-${Math.random()}`, familyId: crypto.randomUUID(), expiresAt: new Date(Date.now() - 8 * 86_400_000) },
      });
      const recentlyExpired = await prisma.refreshToken.create({
        data: { userId: user.id, tokenHash: `h-${Math.random()}`, familyId: crypto.randomUUID(), expiresAt: new Date(Date.now() - 86_400_000) },
      });
      await job('purge_revoked_tokens').run({ prisma, now: new Date(), log: silentLog });
      expect(await prisma.refreshToken.count({ where: { id: expiredLongAgo.id } })).toBe(0);
      expect(await prisma.refreshToken.count({ where: { id: recentlyExpired.id } })).toBe(1);
    });

    it('aggregate_daily_stats is idempotent', async () => {
      const run = () => job('aggregate_daily_stats').run({ prisma, now: new Date(), log: silentLog });
      await run();
      const first = await prisma.dailyStat.findMany({ orderBy: { date: 'asc' } });
      await run();
      const second = await prisma.dailyStat.findMany({ orderBy: { date: 'asc' } });
      expect(second.map((s) => s.date.getTime())).toEqual(first.map((s) => s.date.getTime()));
    });
  });
});
