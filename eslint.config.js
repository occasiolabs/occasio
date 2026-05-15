'use strict';

/**
 * Minimal ESLint config — eslint:recommended plus two extras chosen for
 * audit-trail correctness rather than style:
 *   - no-empty with allowEmptyCatch: false — silent catch blocks are a
 *     documented risk in the roadmap. Forcing a comment or a body keeps
 *     them visible to reviewers.
 *   - no-unused-vars as a warning — useful signal without breaking the
 *     build during incremental cleanup.
 *
 * Scope: src/ only. test-*.js, scripts/, internal/legacy-*, node_modules,
 * and dist artifacts are ignored. Per the roadmap, only src/audit/ and
 * src/attest/ are kept lint-clean today; broader cleanup is queued.
 */

const js = require('@eslint/js');

module.exports = [
  {
    ignores: [
      'node_modules/**',
      'internal/**',
      'dist/**',
      'coverage/**',
      'integrations/**',
      '.git/**',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'bin/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        setImmediate: 'readonly',
        clearImmediate: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        AbortController: 'readonly',
        AbortSignal: 'readonly',
        fetch: 'readonly',
        queueMicrotask: 'readonly',
        global: 'readonly',
        globalThis: 'readonly',
        performance: 'readonly',
      },
    },
    rules: {
      'no-empty': ['error', { allowEmptyCatch: false }],
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
];
