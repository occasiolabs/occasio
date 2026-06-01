#!/usr/bin/env node
'use strict';

/**
 * test-detectors.js — richer, explainable secret detection (Idea #5).
 *
 * Covers:
 *   - src/scanner/detectors.js  detectSecrets / redactWithLedger / shannonEntropy
 *   - opt-in wiring in src/policy/engine.js (default off = unchanged)
 *
 * No network, no deps. analyzer.scanSecrets is intentionally NOT exercised here
 * (it stays frozen; its tests live in test-interceptor.js).
 */

const { detectSecrets, redactWithLedger, shannonEntropy } = require('./src/scanner/detectors');
const engine = require('./src/policy/engine');
const loader = require('./src/policy/loader');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}
const has = (hits, detector, labelRe) => hits.some(h => h.detector === detector && (!labelRe || labelRe.test(h.label)));

// ── 1. known prefixes ────────────────────────────────────────────────────────
console.log('\n1. prefix detectors');
{
  const cases = [
    ['ghp_' + 'a'.repeat(36),                       'github-token'],
    ['AKIA' + 'ABCDEFGHIJKLMNOP',                   'aws-access-key'],
    ['sk-' + 'abcdEFGH1234abcdEFGH1234',            'openai-key'],
    // assembled from parts so the literal token isn't in source (GitHub push protection)
    ['xoxb-' + '123456789012-abcdefghijklmnop',     'slack-token'],
    ['sk_live_' + 'abcd1234abcd1234EF',             'stripe-key'],
    ['github_pat_' + 'A'.repeat(70),                'github-fine-pat'],
    ['sk-ant-api03-' + 'x'.repeat(40),              'anthropic-key'],
  ];
  for (const [tok, label] of cases) {
    const hits = detectSecrets(`value: ${tok}`);
    assert(`prefix ${label}`, hits.some(h => h.detector === 'prefix' && h.label === label), JSON.stringify(hits.map(h => h.label)));
  }
  const h = detectSecrets('ghp_' + 'a'.repeat(36));
  assert('hit carries confidence + reason + sha256 + masked snippet',
    h[0].confidence >= 0.9 && /prefix/.test(h[0].reason) && /^[0-9a-f]{64}$/.test(h[0].value_sha256) && !h[0].snippet.includes('ghp_a'));
}

// ── 2. JWT ───────────────────────────────────────────────────────────────────
console.log('\n2. jwt detector');
{
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: '1234567890', name: 'x' })).toString('base64url');
  const jwt = `${header}.${payload}.c2lnbmF0dXJlc2ln`;
  const hits = detectSecrets(`Authorization: Bearer ${jwt}`);
  assert('JWT detected', has(hits, 'jwt'));
  assert('JWT reason explains structure', hits.find(h => h.detector === 'jwt').reason.includes('JWT'));
  // a non-JWT eyJ-ish string whose header is not JSON must NOT fire
  assert('non-JWT eyJ string does not fire', !has(detectSecrets('eyJabc.def.ghi notvalid'), 'jwt'));
}

// ── 3. high-entropy token ────────────────────────────────────────────────────
console.log('\n3. entropy detector');
{
  const tok = 'Xb7Kp2Qz9LmWn4Rt6Yv8Jc1Ds3Fg5Hk';   // 32 chars, mixed case+digits, not hex
  const hits = detectSecrets(`opaque=${tok}`);
  const e = hits.find(h => h.detector === 'entropy');
  assert('entropy token detected', !!e);
  assert('entropy reason carries length + H', /len \d+/.test(e.reason) && /H≈\d/.test(e.reason));
  assert('shannonEntropy is sane', shannonEntropy(tok) > 3.5 && shannonEntropy('aaaaaaaa') < 0.1);
}

// ── 4. negatives stay quiet ──────────────────────────────────────────────────
console.log('\n4. negatives / allowlist');
{
  assert('UUID → no hit', detectSecrets('id: 550e8400-e29b-41d4-a716-446655440000').length === 0);
  assert('git SHA-1 (40 hex) → no hit', detectSecrets('commit 356a192b7913b04c54574d18c28d46e6395428ab').length === 0);
  assert('SHA-256 (64 hex) → no hit', detectSecrets('digest ' + 'a'.repeat(64)).length === 0);
  assert('English sentence → no hit', detectSecrets('the quick brown fox jumps over the lazy dog').length === 0);
  assert('AKIA…EXAMPLE fixture → allowlisted', detectSecrets('AKIAIOSFODNN7EXAMPLE').length === 0);
  assert('caller allowlist suppresses', detectSecrets('opaque=Xb7Kp2Qz9LmWn4Rt6Yv8Jc1Ds3Fg5Hk', { allowlist: ['Xb7Kp2Qz9LmWn4Rt6Yv8Jc1Ds3Fg5Hk'] }).length === 0);
}

// ── 5. .env secret-like keys ─────────────────────────────────────────────────
console.log('\n5. env-key detector');
{
  assert('SECRET_KEY=… → env-key', has(detectSecrets('SECRET_KEY=abcd1234abcd1234'), 'env-key'));
  assert('DATABASE_PASSWORD=… → env-key', has(detectSecrets('DATABASE_PASSWORD=hunter2hunter2'), 'env-key'));
  assert('API_KEY=changeme placeholder → no hit', detectSecrets('API_KEY=changeme').length === 0);
  assert('PATH=/usr/bin (non-secret key) → no env-key', !has(detectSecrets('PATH=/usr/local/bin'), 'env-key'));
}

// ── 6. redactWithLedger — value replaced, hash-only ledger ───────────────────
console.log('\n6. redactWithLedger');
{
  const secret = 'ghp_' + 'b'.repeat(36);
  const text = `app config\nsee ${secret} in the vault\nend`;   // not KEY=value, so only prefix fires
  const { redacted, ledger } = redactWithLedger(text);
  assert('value removed from redacted output', !redacted.includes(secret) && redacted.includes('[REDACTED:github-token]'));
  assert('ledger entry has detector + reason + sha256', ledger.length === 1 && ledger[0].value_sha256 && ledger[0].reason && ledger[0].detector === 'prefix');
  assert('ledger never stores plaintext', !JSON.stringify(ledger).includes(secret));
  assert('replacement is stable token', ledger[0].replacement === '[REDACTED:github-token]');
}

// ── 7. opt-in engine wiring (default off = unchanged) ────────────────────────
console.log('\n7. engine opt-in');
{
  const entropyTok = 'Zq4Wm8Tb2Nx6Pr0Lk5Hj3Vc9Df1Gs7Ya';   // scanSecrets misses this; detectors catch it
  const toolResults = [{ tool_use_id: 't1', content: `blob=${entropyTok}` }];

  loader._setOverrideForTests({ version: 1, entropy_secret_detection: false });
  const off = engine.evaluateToolResults(toolResults, { mode: 'intercept' });
  assert('flag OFF → scanSecrets path unchanged (no entropy hit)', off.secrets.length === 0);

  loader._setOverrideForTests({ version: 1, entropy_secret_detection: true });
  const on = engine.evaluateToolResults(toolResults, { mode: 'intercept' });
  assert('flag ON → entropy token detected', on.secrets.some(s => s.detector === 'entropy'));

  loader._setOverrideForTests(null);
  loader._resetCache();
}

console.log(`\n${failed === 0 ? '✓' : '✗'} detectors: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
