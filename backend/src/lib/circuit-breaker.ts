/**
 * §24.4 "A circuit breaker wraps each external service: five consecutive
 * failures opens it for 60 seconds, during which the check is marked
 * UNAVAILABLE immediately instead of consuming the timeout on every request."
 *
 * After the open window, one trial request is let through (HALF_OPEN): a
 * success closes the breaker, a failure re-opens it for another window.
 */
export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class CircuitOpenError extends Error {
  constructor(readonly service: string) {
    super(`Circuit open for ${service}`);
    this.name = 'CircuitOpenError';
  }
}

export class CircuitBreaker {
  private consecutiveFailures = 0;
  private openedAt: number | null = null;
  private trialInFlight = false;
  private lastLatencyMs: number | null = null;
  private lastError: string | null = null;

  constructor(
    readonly name: string,
    private readonly failureThreshold = 5,
    private readonly openMs = 60_000,
    private readonly now: () => number = Date.now
  ) {}

  get state(): BreakerState {
    if (this.openedAt === null) return 'CLOSED';
    return this.now() - this.openedAt >= this.openMs ? 'HALF_OPEN' : 'OPEN';
  }

  async exec<T>(fn: () => Promise<T>): Promise<T> {
    const state = this.state;
    if (state === 'OPEN' || (state === 'HALF_OPEN' && this.trialInFlight)) throw new CircuitOpenError(this.name);
    if (state === 'HALF_OPEN') this.trialInFlight = true;

    const started = this.now();
    try {
      const result = await fn();
      this.lastLatencyMs = this.now() - started;
      this.onSuccess();
      return result;
    } catch (error) {
      this.lastLatencyMs = this.now() - started;
      this.lastError = error instanceof Error ? error.message.slice(0, 200) : 'unknown';
      this.onFailure();
      throw error;
    } finally {
      this.trialInFlight = false;
    }
  }

  private onSuccess(): void {
    this.consecutiveFailures = 0;
    this.openedAt = null;
  }

  private onFailure(): void {
    this.consecutiveFailures++;
    if (this.openedAt !== null || this.consecutiveFailures >= this.failureThreshold) {
      // A failed HALF_OPEN trial (or crossing the threshold) opens a fresh window.
      this.openedAt = this.now();
    }
  }

  /** For GET /health/dependencies (ADMIN only). */
  snapshot() {
    return {
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      lastLatencyMs: this.lastLatencyMs,
      lastError: this.lastError,
    };
  }

  /** Tests only. */
  reset(): void {
    this.consecutiveFailures = 0;
    this.openedAt = null;
    this.trialInFlight = false;
  }
}

export const breakers = {
  safeBrowsing: new CircuitBreaker('safeBrowsing'),
  virusTotal: new CircuitBreaker('virusTotal'),
  whois: new CircuitBreaker('whois'),
  claude: new CircuitBreaker('claude'),
};
export type BreakerName = keyof typeof breakers;
