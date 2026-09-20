// @ts-check
const tseslint = require('typescript-eslint');

module.exports = tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  ...tseslint.configs.recommended,
  {
    rules: {
      // Intentional: AppError/service functions throw and let the Fastify
      // error handler (app.ts) format the response — not every catch needs
      // to touch the value.
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  }
);
