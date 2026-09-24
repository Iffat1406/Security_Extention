import { config as loadEnv } from 'dotenv';
import { defineConfig } from 'vitest/config';

// Tests that exercise the real app need DATABASE_URL etc. `test.env` explicitly
// forwards these into the worker environment — a plain `process.env.X = ...`
// here would not reach the test workers.
const { parsed } = loadEnv();

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      ...parsed,
      // Never inherit `development` from .env: no pino-pretty worker threads,
      // no scheduled jobs, quiet output.
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      // Third-party keys are never used in tests — external services are
      // injected fakes (§26.6 "never a live request").
      SAFE_BROWSING_API_KEY: '',
      VIRUSTOTAL_API_KEY: '',
      ANTHROPIC_API_KEY: '',
    },
    // Several files boot the full app against one Postgres in parallel.
    hookTimeout: 30_000,
    testTimeout: 20_000,
    coverage: {
      provider: 'v8',
      // §26.1 "≥ 85% coverage on those modules" — the pure logic.
      include: [
        'src/risk-engine/**',
        'src/services/url-normalizer.service.ts',
        'src/services/url-safety.service.ts',
        'src/services/reputation-model.ts',
        'src/lib/ip-utils.ts',
        'src/lib/circuit-breaker.ts',
      ],
      thresholds: { lines: 85, functions: 85, statements: 85, branches: 75 },
    },
  },
});
