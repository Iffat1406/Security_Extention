import { config as loadEnv } from 'dotenv';
import { defineConfig } from 'vitest/config';

// Tests that exercise the real app (health.test.ts) need DATABASE_URL etc.
// `test.env` explicitly forwards these into the worker environment — a
// plain `process.env.X = ...` here would not reach the test workers.
const { parsed } = loadEnv();

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: parsed,
  },
});
