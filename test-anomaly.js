'use strict';

/**
 * test-anomaly.js — focused tests for the EDR layer.
 *
 *   1. False-positive smoke: low-activity synthetic profile → 0 HIGH alerts
 *      from any built-in detector.
 *   2. threshold-multiplier plumbing: increasing the multiplier suppresses
 *      a deny-rate alert that fires at multiplier=1.
 *
 * Uses scripts/edr-synthetic.js as the canonical chain generator. Keeps the
 * coverage independent of the user's real ~/.occasio chain.
 */

const { runDetectors } = require('./src/anomaly');
const { generate }     = require('./scripts/edr-synthetic');

let passed = 0;
let failed = 0;
function assert(name, cond) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else      { console.log(`  ✗ ${name}`); failed++; }
}

function parseRows(jsonl) {
  const out = [];
  for (const line of jsonl.split('\n')) {
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch { /* skip */ }
  }
  return out;
}

console.log('\nEDR. anomaly detector regression suite\n');

// ── 1. FP smoke on low-activity profile ───────────────────────────────────
{
  console.log('1. low-activity → no HIGH alerts');
  const now    = Date.parse('2026-05-15T12:00:00Z');
  const jsonl  = generate({ profile: 'low-activity', rows: 600, endMs: now, seed: 17 });
  const rows   = parseRows(jsonl);
  const result = runDetectors({ rows, windowMs: 15 * 60 * 1000, now });

  const highs = result.alerts.filter(a => a.severity === 'high');
  assert(`chain parses (${rows.length} rows)`, rows.length === 600);
  assert(`zero HIGH alerts on low-activity profile (got ${highs.length})`, highs.length === 0);
  assert('zero detector crashes', (result.errors || []).length === 0);
}

// ── 2. denied-heavy profile triggers deny-rate ────────────────────────────
{
  console.log('\n2. denied-heavy → deny-rate fires at multiplier=1');
  const now    = Date.parse('2026-05-15T12:00:00Z');
  const jsonl  = generate({ profile: 'denied-heavy', rows: 600, endMs: now, seed: 42 });
  const rows   = parseRows(jsonl);
  const result = runDetectors({ rows, windowMs: 15 * 60 * 1000, now });

  const deny = result.alerts.find(a => a.detector_id === 'deny-rate');
  assert('deny-rate alert present', !!deny);
}

// ── 3. threshold-multiplier suppresses a marginal deny-rate alert ─────────
// We need historical BLOCKs to exercise the rate-path (not the categorical
// "no baseline" path which is intentionally always-fires). Build rows by
// hand: 400 historical rows including 8 BLOCKs spread over 4 hours, then
// 5 BLOCKs in the current 15-min window — a marginal ratio.
{
  console.log('\n3. threshold-multiplier=10 suppresses marginal deny-rate');
  const now    = Date.parse('2026-05-15T12:00:00Z');
  const rows   = [];
  const histBlockCount  = 12;
  const histTotal       = 400;
  const histStartMs     = now - 4 * 3600 * 1000;
  const histStepMs      = (now - 30 * 60 * 1000 - histStartMs) / histTotal;
  for (let i = 0; i < histTotal; i++) {
    const ts = new Date(histStartMs + i * histStepMs).toISOString();
    const action = i % Math.floor(histTotal / histBlockCount) === 0 ? 'BLOCK' : 'LOCAL';
    rows.push({ ts, hash: 'h' + i, action, tool_name: 'Bash', kind: 'tool_call' });
  }
  const winStart = now - 14 * 60 * 1000;
  for (let i = 0; i < 5; i++) {
    rows.push({ ts: new Date(winStart + i * 60000).toISOString(),
                hash: 'w' + i, action: 'BLOCK', tool_name: 'Bash', kind: 'tool_call' });
  }

  const r1  = runDetectors({ rows, windowMs: 15 * 60 * 1000, now, thresholdMultiplier: 1 });
  const r10 = runDetectors({ rows, windowMs: 15 * 60 * 1000, now, thresholdMultiplier: 10 });
  const has1  = r1.alerts.some(a => a.detector_id === 'deny-rate');
  const has10 = r10.alerts.some(a => a.detector_id === 'deny-rate');
  assert('multiplier=1 fires deny-rate (marginal ratio)',  has1);
  assert('multiplier=10 suppresses deny-rate',            !has10);
}

console.log('\n────────────────────────────────────────');
if (failed === 0) {
  console.log(`✓ All ${passed} anomaly tests passed\n`);
  process.exit(0);
} else {
  console.log(`✗ ${failed}/${passed + failed} anomaly tests failed\n`);
  process.exit(1);
}
