import { Prisma, type IndicatorSeverity, type IndicatorSource, type IndicatorType, type PrismaClient } from '@prisma/client';
import type { EvidenceItem } from '@guardtab/shared';
import { writeAuditLog } from './audit.service';
import { computeReputation } from './reputation-model';

/**
 * reputation.service.ts — §22 threat intelligence persistence.
 *
 * Domain rows describe websites, never people (§17.4): nothing written
 * here carries a user id. Unique-user counting uses the user's own
 * scan_results rows (which retention and deletion already govern) rather
 * than a separate user↔domain table in the intelligence layer.
 */

type Db = PrismaClient | Prisma.TransactionClient;

interface IndicatorSpec {
  type: IndicatorType;
  source: IndicatorSource;
  severity: IndicatorSeverity;
  confidence: number;
  evidence: Record<string, unknown>;
}

/** Evidence signal -> threat indicator (§22.2 indicator types). */
export function indicatorsFromEvidence(
  evidence: EvidenceItem[],
  context: { safeBrowsingThreatTypes?: string[]; trackerCount?: number; lookalikeSimilarity?: number; lookalikeBrand?: string }
): IndicatorSpec[] {
  const specs: IndicatorSpec[] = [];
  const has = (signal: string) => evidence.some((e) => e.signal === signal);

  if (has('SAFE_BROWSING_MALICIOUS')) {
    const types = context.safeBrowsingThreatTypes ?? [];
    specs.push({
      type: types.includes('SOCIAL_ENGINEERING') ? 'PHISHING' : 'MALWARE',
      source: 'SAFE_BROWSING',
      severity: 'CRITICAL',
      confidence: 0.95,
      evidence: { threatTypes: types },
    });
  }
  if (has('VIRUSTOTAL_MALICIOUS')) specs.push({ type: 'MALWARE', source: 'VIRUSTOTAL', severity: 'HIGH', confidence: 0.8, evidence: {} });
  else if (has('VIRUSTOTAL_SUSPICIOUS')) specs.push({ type: 'MALWARE', source: 'VIRUSTOTAL', severity: 'MEDIUM', confidence: 0.5, evidence: {} });
  if (has('DOMAIN_VERY_YOUNG')) specs.push({ type: 'SUSPICIOUS_DOMAIN', source: 'SCANNER', severity: 'MEDIUM', confidence: 0.5, evidence: {} });
  if (has('LOOKALIKE_DOMAIN')) {
    specs.push({
      type: 'LOOKALIKE',
      source: 'SCANNER',
      severity: 'HIGH',
      confidence: Math.min(1, context.lookalikeSimilarity ?? 0.9),
      evidence: { brand: context.lookalikeBrand, similarity: context.lookalikeSimilarity },
    });
  }
  // §22.2 "TRACKER_HEAVY — 11+ unique trackers observed consistently".
  if ((context.trackerCount ?? 0) >= 11) {
    specs.push({ type: 'TRACKER_HEAVY', source: 'SCANNER', severity: 'LOW', confidence: 0.6, evidence: { trackerCount: context.trackerCount } });
  }
  if (has('FINGERPRINTING')) specs.push({ type: 'FINGERPRINTING', source: 'SCANNER', severity: 'LOW', confidence: 0.6, evidence: {} });
  const js = evidence.find((e) => e.signal.startsWith('JS_VULN_'));
  if (js) {
    const severity: IndicatorSeverity = js.signal === 'JS_VULN_CRITICAL' ? 'CRITICAL' : js.signal === 'JS_VULN_HIGH' ? 'HIGH' : 'MEDIUM';
    specs.push({ type: 'VULNERABLE_JS', source: 'SCANNER', severity, confidence: 0.7, evidence: { detail: js.detail } });
  }
  if (has('MIXED_CONTENT_ACTIVE')) specs.push({ type: 'MIXED_CONTENT', source: 'SCANNER', severity: 'MEDIUM', confidence: 0.7, evidence: {} });
  if (has('CERT_INVALID') || has('CERT_EXPIRED')) specs.push({ type: 'EXPIRED_CERT', source: 'SCANNER', severity: 'HIGH', confidence: 0.7, evidence: {} });
  if (has('SUSPICIOUS_REDIRECT_CHAIN')) specs.push({ type: 'REDIRECT_ABUSE', source: 'SCANNER', severity: 'MEDIUM', confidence: 0.6, evidence: {} });
  return specs;
}

async function upsertIndicator(db: Db, domainId: string, spec: IndicatorSpec, now: Date): Promise<void> {
  await db.threatIndicator.upsert({
    where: { domainId_type_source: { domainId, type: spec.type, source: spec.source } },
    create: {
      domainId,
      type: spec.type,
      source: spec.source,
      severity: spec.severity,
      confidence: spec.confidence,
      evidence: spec.evidence as Prisma.InputJsonValue,
      firstDetectedAt: now,
      lastDetectedAt: now,
    },
    // Never un-suppresses: an ADMIN override outlives new observations.
    update: {
      severity: spec.severity,
      confidence: spec.confidence,
      evidence: spec.evidence as Prisma.InputJsonValue,
      lastDetectedAt: now,
      observationCount: { increment: 1 },
    },
  });
}

export interface ObservationArgs {
  registrableDomain: string;
  /** True when this user has never scanned this domain before (for unique_user_count). */
  newUserForDomain: boolean;
  securityScore: number | null;
  domainAgeDays: number | null;
  evidence: EvidenceItem[];
  context: Parameters<typeof indicatorsFromEvidence>[1];
}

/**
 * Records one scan into the intelligence layer. Skipped entirely when the
 * user turned off "Contribute to threat intelligence" (§23.1) — the caller
 * checks that before calling.
 */
export async function recordScanObservation(prisma: PrismaClient, args: ObservationArgs, now = new Date()): Promise<void> {
  const domain = await prisma.domain.upsert({
    where: { domain: args.registrableDomain },
    create: {
      domain: args.registrableDomain,
      firstSeenAt: now,
      lastSeenAt: now,
      scanCount: 1,
      uniqueUserCount: args.newUserForDomain ? 1 : 0,
      latestSecurityScore: args.securityScore,
      domainAgeDays: args.domainAgeDays,
    },
    update: {
      lastSeenAt: now,
      scanCount: { increment: 1 },
      ...(args.newUserForDomain ? { uniqueUserCount: { increment: 1 } } : {}),
      ...(args.securityScore !== null ? { latestSecurityScore: args.securityScore } : {}),
      ...(args.domainAgeDays !== null ? { domainAgeDays: args.domainAgeDays } : {}),
    },
  });

  const specs = indicatorsFromEvidence(args.evidence, args.context);
  for (const spec of specs) await upsertIndicator(prisma, domain.id, spec, now);

  await recomputeDomainReputation(prisma, domain.id, now);
}

/** Recomputes one domain's reputation from its indicator and feedback rows; audits any transition (§22.4). */
export async function recomputeDomainReputation(prisma: PrismaClient, domainId: string, now = new Date()): Promise<void> {
  const domain = await prisma.domain.findUnique({ where: { id: domainId }, include: { indicators: true } });
  if (!domain) return;

  const [reporters, fpConfirmed, tpConfirmed] = await Promise.all([
    prisma.scanFeedback.findMany({
      where: { domain: domain.domain, feedbackType: 'FALSE_NEGATIVE', status: { not: 'REJECTED' } },
      select: { userId: true, createdAt: true, user: { select: { createdAt: true } } },
      distinct: ['userId'],
    }),
    prisma.scanFeedback.count({ where: { domain: domain.domain, feedbackType: 'FALSE_POSITIVE', status: 'CONFIRMED' } }),
    prisma.scanFeedback.count({ where: { domain: domain.domain, feedbackType: 'FALSE_NEGATIVE', status: 'CONFIRMED' } }),
  ]);
  // §22.4 "Submissions from accounts younger than 24 hours carry half weight."
  const weightedReporters = reporters.reduce(
    (sum, r) => sum + (r.createdAt.getTime() - r.user.createdAt.getTime() < 86_400_000 ? 0.5 : 1),
    0
  );

  const result = computeReputation({
    indicators: domain.indicators.map((i) => ({
      type: i.type,
      source: i.source,
      lastDetectedAt: i.lastDetectedAt,
      suppressed: i.suppressedAt !== null,
    })),
    weightedReporters,
    confirmedFalsePositives: fpConfirmed,
    confirmedTruePositives: tpConfirmed,
    isAllowlisted: domain.isAllowlisted,
    scanCount: domain.scanCount,
    now,
  });

  const before = { reputation: domain.reputation, confidence: Number(domain.reputationConfidence) };
  await prisma.domain.update({
    where: { id: domainId },
    data: { reputation: result.reputation, reputationConfidence: result.confidence },
  });

  if (before.reputation !== result.reputation) {
    await writeAuditLog(prisma, {
      userId: null,
      action: 'REPUTATION_CHANGE',
      resourceType: 'domain',
      resourceId: domainId,
      metadata: { before: before.reputation, after: result.reputation, confidence: result.confidence, components: result.components },
    });
  }
}

export interface CommunitySignal {
  status: 'OK' | 'NOT_SUPPORTED';
  reputation: 'UNKNOWN' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  confidence: number;
  uniqueReporters: number;
  indicatorTypes: string[];
}

/** The domain's current community standing, read before scoring a scan. */
export async function getCommunitySignal(prisma: PrismaClient, registrableDomain: string): Promise<CommunitySignal> {
  const domain = await prisma.domain.findUnique({
    where: { domain: registrableDomain },
    include: { indicators: { where: { suppressedAt: null }, select: { type: true } } },
  });
  if (!domain) return { status: 'OK', reputation: 'UNKNOWN', confidence: 0, uniqueReporters: 0, indicatorTypes: [] };

  const uniqueReporters = domain.isAllowlisted
    ? 0
    : (
        await prisma.scanFeedback.findMany({
          where: { domain: registrableDomain, feedbackType: 'FALSE_NEGATIVE', status: { not: 'REJECTED' } },
          select: { userId: true },
          distinct: ['userId'],
        })
      ).length;

  return {
    status: 'OK',
    reputation: domain.reputation,
    confidence: Number(domain.reputationConfidence),
    uniqueReporters,
    indicatorTypes: [...new Set(domain.indicators.map((i) => i.type))],
  };
}

/** A FALSE_NEGATIVE report ("this site is dangerous") becomes / refreshes a COMMUNITY SCAM indicator. */
export async function recordCommunityReport(prisma: PrismaClient, registrableDomain: string, now = new Date()): Promise<void> {
  const domain = await prisma.domain.upsert({
    where: { domain: registrableDomain },
    create: { domain: registrableDomain, firstSeenAt: now, lastSeenAt: now },
    update: {},
  });
  await upsertIndicator(prisma, domain.id, { type: 'SCAM', source: 'COMMUNITY', severity: 'MEDIUM', confidence: 0.3, evidence: {} }, now);
  await recomputeDomainReputation(prisma, domain.id, now);
}
