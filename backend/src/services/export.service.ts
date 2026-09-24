import { createHmac, timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { env } from '../config/env';

/**
 * §29.3 data export — "delivered as a short-lived signed download link
 * rather than inline in the response", and "contains exactly what the
 * database holds — no reconstruction, no enrichment".
 */
export const EXPORT_LINK_TTL_MS = 10 * 60 * 1000;

const sign = (payload: string) => createHmac('sha256', env.COOKIE_SECRET).update(`export:${payload}`).digest('base64url');

export function createExportToken(userId: string, now = Date.now()): { token: string; expiresAt: Date } {
  const expiresAt = new Date(now + EXPORT_LINK_TTL_MS);
  const payload = Buffer.from(JSON.stringify({ u: userId, exp: expiresAt.getTime() })).toString('base64url');
  return { token: `${payload}.${sign(payload)}`, expiresAt };
}

/** Returns the user id, or null for a forged, tampered or expired token. */
export function verifyExportToken(token: string, now = Date.now()): string | null {
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;
  try {
    const { u, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { u?: string; exp?: number };
    return typeof u === 'string' && typeof exp === 'number' && exp > now ? u : null;
  } catch {
    return null;
  }
}

const bigIntSafe = (_key: string, value: unknown) => (typeof value === 'bigint' ? value.toString() : value);

export async function buildExport(prisma: PrismaClient, userId: string) {
  const [user, settings, scans, chats, feedback] = await Promise.all([
    prisma.user.findUniqueOrThrow({ where: { id: userId } }),
    prisma.userSettings.findUnique({ where: { userId } }),
    prisma.scanResult.findMany({ where: { userId }, orderBy: { scannedAt: 'desc' } }),
    prisma.scanChat.findMany({ where: { userId }, orderBy: { createdAt: 'asc' } }),
    prisma.scanFeedback.findMany({ where: { userId }, orderBy: { createdAt: 'desc' } }),
  ]);
  return JSON.parse(
    JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        profile: user,
        settings: settings?.settings ?? {},
        exclusions: settings?.excludedDomains ?? [],
        scans,
        chats,
        feedback,
      },
      bigIntSafe
    )
  ) as Record<string, unknown>;
}

const CSV_COLUMNS = [
  'id', 'scannedAt', 'host', 'registrableDomain', 'path', 'scanStatus',
  'securityScore', 'privacyScore', 'overallScore', 'riskBand', 'riskEngineVersion', 'scannerVersion',
] as const;

/** RFC 4180 quoting, plus a leading apostrophe on formula-looking cells (spreadsheet injection). */
function csvCell(value: unknown): string {
  let s = value instanceof Date ? value.toISOString() : value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export async function buildScanCsv(prisma: PrismaClient, userId: string): Promise<string> {
  const scans = await prisma.scanResult.findMany({ where: { userId }, orderBy: { scannedAt: 'desc' } });
  const lines = [CSV_COLUMNS.join(',')];
  for (const scan of scans) lines.push(CSV_COLUMNS.map((c) => csvCell(scan[c])).join(','));
  return `${lines.join('\r\n')}\r\n`;
}
