#!/usr/bin/env node
'use strict';

/**
 * test-explain.js — explain → rule-line + alternatives (Idea #9).
 *
 * Covers:
 *   - src/policy/explain-rule.js  resolveBlockedRule + line locators (pure)
 *   - src/cli/explain.js          explainToolCall rendering (reads a temp policy)
 *
 * No network. Temp policy.yml in os.tmpdir(); events are hand-built audit rows.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { resolveBlockedRule, findListEntryLine, findKeyLine } = require('./src/policy/explain-rule');
const { explainToolCall } = require('./src/cli/explain');
const loader = require('./src/policy/loader');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

const tmps = [];
function mkTmp(p) { const d = fs.mkdtempSync(path.join(os.tmpdir(), p)); tmps.push(d); return d; }

const POLICY = [
  'version: 1',          // line 1
  'deny_paths:',         // line 2
  '  - ~/.ssh',          // line 3
  '  - /etc/secret',     // line 4
  'allow_paths:',        // line 5
  '  - /work',           // line 6
  'limits:',             // line 7
  '  max_tool_calls_per_round: 50',  // line 8
  '',
].join('\n');

const dir = mkTmp('lf-explain-');
const polFile = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-exp-pol-')) + '/policy.yml';
fs.mkdirSync(path.dirname(polFile), { recursive: true });
fs.writeFileSync(polFile, POLICY);
tmps.push(path.dirname(polFile));

const ctx = { rawText: POLICY, parsed: loader.parse(POLICY), policyPath: polFile,
              currentHash: 'a'.repeat(64), eventHash: 'a'.repeat(64) };

const denyEvent = {
  kind: 'tool_call', tool_name: 'read_file', action: 'BLOCK', reason: 'path-denied',
  event_id: 'deny0001', run_id: 'R', ts: '2026-06-01T10:00:01.000Z',
  tool_inputs: { path: '~/.ssh/id_rsa' },
};

// ── 1. deny_path → section + index + matched value ───────────────────────────
console.log('\n1. resolveBlockedRule — path-denied');
{
  const r = resolveBlockedRule(denyEvent, ctx);
  assert('section = deny_paths', r && r.section === 'deny_paths');
  assert('index 0 (first deny entry)', r.index === 0);
  assert('matched_value = ~/.ssh', r.matched_value === '~/.ssh');
  assert('rule_id = deny_paths[0]', r.rule_id === 'deny_paths[0]');
  assert('alternatives present', Array.isArray(r.alternatives) && r.alternatives.length >= 1);
}

// ── 2. policy.yml line located ───────────────────────────────────────────────
console.log('\n2. line located');
{
  const r = resolveBlockedRule(denyEvent, ctx);
  assert('deny_paths[0] is line 3', r.line === 3, `got ${r && r.line}`);
  assert('findKeyLine(limits.max_tool_calls_per_round) = line 8', findKeyLine(POLICY, 'limits', 'max_tool_calls_per_round') === 8);
  assert('findListEntryLine(/etc/secret) = line 4', findListEntryLine(POLICY, 'deny_paths', '/etc/secret') === 4);
}

// ── 3. line-unavailable fallback ─────────────────────────────────────────────
console.log('\n3. fallback when line/policy unavailable');
{
  const r = resolveBlockedRule(denyEvent, { rawText: '', parsed: {}, currentHash: null, eventHash: null });
  assert('section still deny_paths', r && r.section === 'deny_paths');
  assert('line is null', r.line === null);
  assert('matched_value falls back to input path', r.matched_value === '~/.ssh/id_rsa');
  assert('no throw, alternatives present', Array.isArray(r.alternatives) && r.alternatives.length >= 1);
}

// ── 4. limit_exceeded → name, max, actual + limits line ──────────────────────
console.log('\n4. resolveBlockedRule — limit_exceeded');
{
  const limEvent = {
    kind: 'limit_exceeded', action: 'BLOCK', reason: 'limit-exceeded',
    event_id: 'lim00001', run_id: 'R', ts: '2026-06-01T10:00:02.000Z',
    tool_inputs: { limit: 'max_tool_calls_per_round', max: 50, actual: 120, decision: 'block' },
  };
  const r = resolveBlockedRule(limEvent, ctx);
  assert('section = limits', r && r.section === 'limits');
  assert('rule_id names the limit', r.rule_id === 'limits.max_tool_calls_per_round');
  assert('matched_value carries max + actual', /max 50/.test(r.matched_value) && /actual 120/.test(r.matched_value));
  assert('limits line located (line 8)', r.line === 8);
  assert('alternative suggests raising the cap', r.alternatives.some(a => /Raise/.test(a) && /max_tool_calls_per_round/.test(a)));
}

// ── 5. stability — non-block / unknown events → null, no throw ───────────────
console.log('\n5. stability');
{
  assert('policy_loaded → null', resolveBlockedRule({ kind: 'policy_loaded', reason: 'policy-loaded', tool_inputs: {} }, ctx) === null);
  assert('LOCAL tool_call → null', resolveBlockedRule({ kind: 'tool_call', action: 'LOCAL', reason: 'native-handleable', tool_inputs: { path: '/x' } }, ctx) === null);
  assert('unknown reason → null', resolveBlockedRule({ kind: 'tool_call', action: 'BLOCK', reason: 'something-weird', tool_inputs: {} }, ctx) === null);
  // explainToolCall must not throw on any of these
  let threw = false;
  try {
    explainToolCall({ kind: 'tool_call', action: 'LOCAL', reason: 'native-handleable', event_id: 'x', tool_inputs: { path: '/x' } }, []);
    explainToolCall({ kind: 'policy_loaded', event_id: 'y', tool_inputs: {} }, []);
  } catch { threw = true; }
  assert('explainToolCall stable on non-block events', threw === false);
}

// ── 6. drift flag when current hash ≠ event hash ─────────────────────────────
console.log('\n6. drift provenance');
{
  const r = resolveBlockedRule(denyEvent, { ...ctx, currentHash: 'a'.repeat(64), eventHash: 'b'.repeat(64) });
  assert('provenance = policy-changed', r.provenance === 'policy-changed');
}

// ── 7. explainToolCall render (string-contains) ──────────────────────────────
console.log('\n7. explainToolCall — rendered output');
{
  const polHash = loader.computePolicyHash(polFile);
  const all = [
    { kind: 'policy_loaded', run_id: 'R', ts: '2026-06-01T10:00:00.000Z', event_id: 'pl0001',
      tool_inputs: { policy_path: polFile, policy_hash: polHash, version: 1 } },
    denyEvent,
  ];
  const out = explainToolCall(denyEvent, all);
  assert('output names the rule deny_paths[0]', out.includes('deny_paths[0]'));
  assert('output shows policy.yml location with line', out.includes(`${polFile}:3`));
  assert('output has Suggested next actions', out.includes('Suggested next actions'));
  assert('output suggests narrowing the deny entry', /Remove or narrow/.test(out));
  assert('no drift note when hashes match', !out.includes('changed since this decision'));
}

for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
console.log(`\n${failed === 0 ? '✓' : '✗'} explain: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
