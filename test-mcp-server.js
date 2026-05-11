'use strict';

/**
 * test-mcp-server.js — Regression tests for MCP input normalization.
 *
 * Tests the three normalization shims in mcp-normalize.js:
 *   normalizeReadInput  — path/start_line/end_line → file_path/offset/limit
 *   normalizeFindInput  — pattern/extension/path   → glob pattern/path
 *   normalizeGrepInput  — case_sensitive/file_glob  → -i/glob
 *
 * Run: node test-mcp-server.js
 */

const { normalizeReadInput, normalizeFindInput, normalizeGrepInput } = require('./src/mcp-normalize');

let passed = 0, failed = 0;

function check(label, got, expected) {
  const gs = JSON.stringify(got);
  const es = JSON.stringify(expected);
  if (gs === es) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${label}`);
    console.error(`    got:      ${gs}`);
    console.error(`    expected: ${es}`);
  }
}

// ── normalizeReadInput ─────────────────────────────────────────────────────────

console.log('\nnormalizeReadInput');

check('null input → empty file_path',
  normalizeReadInput(null),
  { file_path: '' });

check('path only',
  normalizeReadInput({ path: '/src/foo.js' }),
  { file_path: '/src/foo.js' });

check('file_path fallback when no path',
  normalizeReadInput({ file_path: '/src/foo.js' }),
  { file_path: '/src/foo.js' });

check('path wins over file_path',
  normalizeReadInput({ path: '/new.js', file_path: '/old.js' }),
  { file_path: '/new.js' });

check('start_line + end_line → offset + limit',
  normalizeReadInput({ path: '/f.js', start_line: 10, end_line: 20 }),
  { file_path: '/f.js', offset: 9, limit: 11 });

check('start_line only → offset only',
  normalizeReadInput({ path: '/f.js', start_line: 5 }),
  { file_path: '/f.js', offset: 4 });

check('start_line=1 → offset=0',
  normalizeReadInput({ path: '/f.js', start_line: 1 }),
  { file_path: '/f.js', offset: 0 });

check('start_line=0 clamped → offset=0',
  normalizeReadInput({ path: '/f.js', start_line: 0 }),
  { file_path: '/f.js', offset: 0 });

check('start_line=null → falls through to offset/limit',
  normalizeReadInput({ path: '/f.js', start_line: null, offset: 3, limit: 10 }),
  { file_path: '/f.js', offset: 3, limit: 10 });

check('legacy offset + limit passthrough',
  normalizeReadInput({ file_path: '/f.js', offset: 5, limit: 20 }),
  { file_path: '/f.js', offset: 5, limit: 20 });

check('end_line < start_line → limit clamped to 1',
  normalizeReadInput({ path: '/f.js', start_line: 10, end_line: 8 }),
  { file_path: '/f.js', offset: 9, limit: 1 });

check('empty object → empty file_path',
  normalizeReadInput({}),
  { file_path: '' });

// ── normalizeFindInput ─────────────────────────────────────────────────────────

console.log('\nnormalizeFindInput');

check('null input → **/*',
  normalizeFindInput(null),
  { pattern: '**/*' });

check('empty args → **/*',
  normalizeFindInput({}),
  { pattern: '**/*' });

check('empty pattern → **/*',
  normalizeFindInput({ pattern: '' }),
  { pattern: '**/*' });

check('glob pattern passthrough',
  normalizeFindInput({ pattern: '**/*.js' }),
  { pattern: '**/*.js' });

check('plain name fragment → wrapped',
  normalizeFindInput({ pattern: 'interceptor' }),
  { pattern: '**/*interceptor*' });

check('extension only (with dot)',
  normalizeFindInput({ pattern: '', extension: '.ts' }),
  { pattern: '**/*.ts' });

check('extension without dot → dot added',
  normalizeFindInput({ pattern: '', extension: 'ts' }),
  { pattern: '**/*.ts' });

check('name fragment + extension',
  normalizeFindInput({ pattern: 'analyzer', extension: '.js' }),
  { pattern: '**/*analyzer*.js' });

check('glob + extension already present → unchanged',
  normalizeFindInput({ pattern: '**/*.ts', extension: '.ts' }),
  { pattern: '**/*.ts' });

check('glob + new extension appended',
  normalizeFindInput({ pattern: 'src/**/*', extension: '.js' }),
  { pattern: 'src/**/*.js' });

check('path included when not dot',
  normalizeFindInput({ pattern: '*.js', path: 'src' }),
  { pattern: '*.js', path: 'src' });

check('path=. excluded from result',
  normalizeFindInput({ pattern: '*.js', path: '.' }),
  { pattern: '*.js' });

check('max_results ignored',
  normalizeFindInput({ pattern: '*.js', max_results: 10 }),
  { pattern: '*.js' });

check('? and * are glob chars → passthrough',
  normalizeFindInput({ pattern: 'src/?oo.js' }),
  { pattern: 'src/?oo.js' });

check('{ } brace expansion → passthrough',
  normalizeFindInput({ pattern: 'src/*.{ts,tsx}' }),
  { pattern: 'src/*.{ts,tsx}' });

// ── normalizeGrepInput ─────────────────────────────────────────────────────────

console.log('\nnormalizeGrepInput');

check('null input → empty pattern + -i=true',
  normalizeGrepInput(null),
  { pattern: '', '-i': true });

check('pattern only → -i=true by default',
  normalizeGrepInput({ pattern: 'foo' }),
  { pattern: 'foo', '-i': true });

check('case_sensitive=false → -i=true',
  normalizeGrepInput({ pattern: 'foo', case_sensitive: false }),
  { pattern: 'foo', '-i': true });

check('case_sensitive=true → -i=false',
  normalizeGrepInput({ pattern: 'foo', case_sensitive: true }),
  { pattern: 'foo', '-i': false });

check('case_sensitive=undefined → -i=true',
  normalizeGrepInput({ pattern: 'foo', case_sensitive: undefined }),
  { pattern: 'foo', '-i': true });

check('file_glob → glob',
  normalizeGrepInput({ pattern: 'foo', file_glob: '*.ts' }),
  { pattern: 'foo', glob: '*.ts', '-i': true });

check('file_glob=null → no glob key',
  normalizeGrepInput({ pattern: 'foo', file_glob: null }),
  { pattern: 'foo', '-i': true });

check('max_results → head_limit',
  normalizeGrepInput({ pattern: 'foo', max_results: 25 }),
  { pattern: 'foo', '-i': true, head_limit: 25 });

check('max_results=0 → not included',
  normalizeGrepInput({ pattern: 'foo', max_results: 0 }),
  { pattern: 'foo', '-i': true });

check('path=. excluded',
  normalizeGrepInput({ pattern: 'foo', path: '.' }),
  { pattern: 'foo', '-i': true });

check('path included when real',
  normalizeGrepInput({ pattern: 'foo', path: 'src' }),
  { pattern: 'foo', path: 'src', '-i': true });

check('output_mode passed through',
  normalizeGrepInput({ pattern: 'foo', output_mode: 'files_with_matches' }),
  { pattern: 'foo', '-i': true, output_mode: 'files_with_matches' });

check('type passed through',
  normalizeGrepInput({ pattern: 'foo', type: 'js' }),
  { pattern: 'foo', type: 'js', '-i': true });

check('empty string pattern',
  normalizeGrepInput({ pattern: '' }),
  { pattern: '', '-i': true });

// ── Summary ────────────────────────────────────────────────────────────────────

const total = passed + failed;
console.log(`\n────────────────────────────────────────`);
if (failed === 0) {
  console.log(`✓ All ${total} normalization tests passed`);
} else {
  console.log(`✗ ${failed} of ${total} tests failed`);
  process.exit(1);
}
