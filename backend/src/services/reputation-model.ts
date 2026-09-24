import type { IndicatorSource, IndicatorType, Reputation } from '@prisma/client';

/**
 * §22.4 confidence model — a pure function over indicator rows, so it is
 * unit-testable with fixtures and recomputable nightly for decay.
 *
 *   External source agreement   0.40   Safe Browsing + VirusTotal agreeing
 *   Unique reporting users      0.20   log-scaled, capped
 *   Scanner-derived indicators  0.20   deterministic observations
 *   Recency                     0.10   full for 7 days, linear to 0 at 90
 *   Historical false positives −0.10
 *
 * The positive weights sum to 0.90; the positive part is divided by 0.90 so
 * that a domain with every signal at full strength can reach 1.00 (the
 * spec's example feed shows 0.96), then the false-positive penalty applies.
 */
export const REPUTATION_WEIGHTS = {
  external: 0.4,
  reporters: 0.2,
  scanner: 0.2,
  recency: 0.1,
  falsePositive: 0.1,
} as const;

export const REPUTATION_THRESHOLDS = {
  /** Unique reporters at which the reporter component saturates ("the 50th reporter adds almost nothing"). */
  REPORTER_CAP: 20,
  /** Distinct scanner indicator types at which the scanner component saturates. */
  SCANNER_TYPES_CAP: 3,
  FULL_WEIGHT_DAYS: 7,
  DECAY_TO_ZERO_DAYS: 90,
  /**
   * One fresh external flag alone (Safe Browsing *or* VirusTotal) scores
   * 0.6 × 0.40 + 0.10 recency = 0.34 / 0.90 ≈ 0.38 — so it clears this bar,
   * while a decayed or half-hearted external signal does not. Community-
   * and scanner-only domains can never reach MALICIOUS regardless: that
   * requires an external or ADMIN indicator.
   */
  MALICIOUS_MIN_CONFIDENCE: 0.35,
  SUSPICIOUS_MIN_CONFIDENCE: 0.25,
} as const;

export interface IndicatorForScoring {
  type: IndicatorType;
  source: IndicatorSource;
  lastDetectedAt: Date;
  suppressed: boolean;
}

export interface ReputationInput {
  indicators: IndicatorForScoring[];
  /** Σ over distinct users with an open FALSE_NEGATIVE report; accounts < 24h old count 0.5 (§22.4). */
  weightedReporters: number;
  confirmedFalsePositives: number;
  confirmedTruePositives: number;
  isAllowlisted: boolean;
  scanCount: number;
  now: Date;
}

export interface ReputationResult {
  reputation: Reputation;
  confidence: number;
  components: { external: number; reporters: number; scanner: number; recency: number; falsePositiveRate: number };
  activeTypes: IndicatorType[];
}

/** Full weight for 7 days, linear decay to zero at 90 days. */
export function decay(lastDetectedAt: Date, now: Date): number {
  const ageDays = (now.getTime() - lastDetectedAt.getTime()) / 86_400_000;
  const { FULL_WEIGHT_DAYS, DECAY_TO_ZERO_DAYS } = REPUTATION_THRESHOLDS;
  if (ageDays <= FULL_WEIGHT_DAYS) return 1;
  if (ageDays >= DECAY_TO_ZERO_DAYS) return 0;
  return 1 - (ageDays - FULL_WEIGHT_DAYS) / (DECAY_TO_ZERO_DAYS - FULL_WEIGHT_DAYS);
}

const round2 = (n: number) => Math.round(n * 100) / 100;

export function computeReputation(input: ReputationInput): ReputationResult {
  const { now } = input;
  // Suppressed indicators never score; allowlisted domains ignore community signals entirely.
  const active = input.indicators
    .filter((i) => !i.suppressed)
    .filter((i) => !(input.isAllowlisted && i.source === 'COMMUNITY'))
    .map((i) => ({ ...i, weight: decay(i.lastDetectedAt, now) }))
    .filter((i) => i.weight > 0);

  const bySource = (source: IndicatorSource) => active.filter((i) => i.source === source);
  const maxWeight = (list: typeof active) => list.reduce((m, i) => Math.max(m, i.weight), 0);

  const safeBrowsing = maxWeight(bySource('SAFE_BROWSING'));
  const virusTotal = maxWeight(bySource('VIRUSTOTAL'));
  const external = safeBrowsing > 0 && virusTotal > 0 ? Math.max(safeBrowsing, virusTotal) : Math.max(safeBrowsing, virusTotal) * 0.6;

  const community = bySource('COMMUNITY');
  const reporterScale = Math.log(1 + REPUTATION_THRESHOLDS.REPORTER_CAP);
  const reporters = input.isAllowlisted
    ? 0
    : Math.min(1, Math.log(1 + Math.max(0, input.weightedReporters)) / reporterScale) * (community.length > 0 ? maxWeight(community) : 1);

  const scannerIndicators = bySource('SCANNER');
  const scannerTypes = new Map<IndicatorType, number>();
  for (const i of scannerIndicators) scannerTypes.set(i.type, Math.max(scannerTypes.get(i.type) ?? 0, i.weight));
  const scannerWeightSum = [...scannerTypes.values()].reduce((a, b) => a + b, 0);
  const scanner = Math.min(1, scannerWeightSum / REPUTATION_THRESHOLDS.SCANNER_TYPES_CAP);

  const recency = maxWeight(active);

  const reviewed = input.confirmedFalsePositives + input.confirmedTruePositives;
  const falsePositiveRate = reviewed > 0 ? input.confirmedFalsePositives / reviewed : 0;

  const w = REPUTATION_WEIGHTS;
  const positive = (w.external * external + w.reporters * reporters + w.scanner * scanner + w.recency * recency) / 0.9;
  const confidence = round2(Math.max(0, Math.min(1, positive - w.falsePositive * falsePositiveRate)));

  const activeTypes = [...new Set(active.map((i) => i.type))];
  const adminForced = bySource('ADMIN').length > 0;
  const hasExternal = safeBrowsing > 0 || virusTotal > 0;

  let reputation: Reputation;
  if (adminForced) {
    reputation = 'MALICIOUS';
  } else if (active.length === 0) {
    reputation = input.scanCount > 0 ? 'CLEAN' : 'UNKNOWN';
  } else if (hasExternal && confidence >= REPUTATION_THRESHOLDS.MALICIOUS_MIN_CONFIDENCE) {
    // "MALICIOUS requires at least one external source or an ADMIN action."
    reputation = 'MALICIOUS';
  } else if (confidence >= REPUTATION_THRESHOLDS.SUSPICIOUS_MIN_CONFIDENCE) {
    // "A COMMUNITY-only indicator can never on its own raise reputation above SUSPICIOUS."
    reputation = 'SUSPICIOUS';
  } else {
    reputation = input.scanCount > 0 ? 'CLEAN' : 'UNKNOWN';
  }

  return {
    reputation,
    confidence: adminForced ? Math.max(confidence, 0.95) : confidence,
    components: {
      external: round2(external),
      reporters: round2(reporters),
      scanner: round2(scanner),
      recency: round2(recency),
      falsePositiveRate: round2(falsePositiveRate),
    },
    activeTypes,
  };
}
