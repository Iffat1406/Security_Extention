/**
 * Collects per-dependency timings for the §28.1 structured log line:
 *   deps: { safeBrowsing: 310, virusTotal: 490, claude: 720, db: 43 }
 */
export class DepTimer {
  private readonly timings: Record<string, number> = {};

  async time<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const started = performance.now();
    try {
      return await fn();
    } finally {
      this.timings[name] = (this.timings[name] ?? 0) + Math.round(performance.now() - started);
    }
  }

  timeSync<T>(name: string, fn: () => T): T {
    const started = performance.now();
    try {
      return fn();
    } finally {
      this.timings[name] = (this.timings[name] ?? 0) + Math.round(performance.now() - started);
    }
  }

  toJSON(): Record<string, number> {
    return { ...this.timings };
  }
}
