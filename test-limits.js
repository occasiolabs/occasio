#!/usr/bin/env node
'use strict';

/**
 * test-limits.js — per-round volume limits (Idea #4).
 *
 * Covers:
 *   - src/limits.js                checkRoundLimits / normalizeLimits (pure)
 *   - src/audit/jsonl-auditor.js   recordLimitExceeded → tamper-evident row
 *   - src/policy/loader.js         limits parsing + default-off
 *   - src/adapters/claude-code.js  enforcement in runToolLoop (no network:
 *                                  the round-0 count check precedes forwardToCloud)
 *
 * No network, no API keys: the integration test sets a policy override and
 * feeds a crafted SSE batch; the limit halt returns before any cloud call.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const { checkRoundLimits, normalizeLimits, LIMIT_KEYS } = require('./src/limits');
const { createAuditor } = require('./src/audit/jsonl-auditor');
const { verifyFile }    = require('./src/audit/verifier');
const loader   = require('./src/policy/loader');
const _adapter = require('./src/adapters/claude-code');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

const tmps = [];
function mkTmp(p) { const d = fs.mkdtempSync(path.join(os.tmpdir(), p)); tmps.push(d); return d; }

// SSE batch builder (mirrors the fixture pattern in test-interceptor.js §28).
function makeBatchSSE(blocks) {
  const lines = ['data: {"type":"message_start","message":{"id":"msg_lim","usage":{"input_tokens":100,"output_tokens":5}}}'];
  blocks.forEach((b, idx) => {
    lines.push(`data: {"type":"content_block_start","index":${idx},"content_block":{"type":"tool_use","id":"${b.id}","name":"${b.name}","input":{}}}`);
    lines.push(`data: {"type":"content_block_delta","index":${idx},"delta":{"type":"input_json_delta","partial_json":${JSON.stringify(JSON.stringify(b.input))}}}`);
    lines.push(`data: {"type":"content_block_stop","index":${idx}}`);
  });
  lines.push('data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}');
  lines.push('data: {"type":"message_stop"}');
  return Buffer.from(lines.join('\n'));
}

// ── 1. helper — under all limits → no block (test 1) ─────────────────────────
console.log('\n1. checkRoundLimits — under limits');
{
  const limits = { max_tool_calls_per_round: 50, max_bash_calls_per_round: 10, max_bytes_to_model_per_round: 2000000 };
  const r = checkRoundLimits(limits, { toolCalls: 5, bashCalls: 1, bytesToModel: 1000 });
  assert('under all limits → not exceeded', r.exceeded === false);
}

// ── 2. helper — tool-call cap exceeded (test 2) ──────────────────────────────
console.log('\n2. checkRoundLimits — max_tool_calls_per_round');
{
  const r = checkRoundLimits({ max_tool_calls_per_round: 3 }, { toolCalls: 4, bashCalls: 0, bytesToModel: 0 });
  assert('tool calls over → exceeded', r.exceeded === true);
  assert('kind = max_tool_calls_per_round', r.kind === 'max_tool_calls_per_round');
  assert('max=3 actual=4', r.max === 3 && r.actual === 4);
  const eq = checkRoundLimits({ max_tool_calls_per_round: 3 }, { toolCalls: 3 });
  assert('exactly at limit → not exceeded (> not >=)', eq.exceeded === false);
}

// ── 3. helper — bash cap exceeded (test 3) ───────────────────────────────────
console.log('\n3. checkRoundLimits — max_bash_calls_per_round');
{
  const r = checkRoundLimits({ max_tool_calls_per_round: 100, max_bash_calls_per_round: 2 },
    { toolCalls: 5, bashCalls: 3, bytesToModel: 0 });
  assert('bash over → exceeded', r.exceeded === true && r.kind === 'max_bash_calls_per_round');
  assert('max=2 actual=3', r.max === 2 && r.actual === 3);
}

// ── 4. helper — bytes-to-model cap exceeded (test 4) ─────────────────────────
console.log('\n4. checkRoundLimits — max_bytes_to_model_per_round');
{
  const r = checkRoundLimits({ max_bytes_to_model_per_round: 1000 },
    { toolCalls: 1, bashCalls: 0, bytesToModel: 5000 });
  assert('bytes over → exceeded', r.exceeded === true && r.kind === 'max_bytes_to_model_per_round');
  assert('max=1000 actual=5000', r.max === 1000 && r.actual === 5000);
}

// ── 5. helper — default-off + normalizeLimits hygiene ────────────────────────
console.log('\n5. default-off + normalizeLimits');
{
  assert('empty limits never block', checkRoundLimits({}, { toolCalls: 9999, bashCalls: 9999, bytesToModel: 9e9 }).exceeded === false);
  assert('null limits never block', checkRoundLimits(null, { toolCalls: 9999 }).exceeded === false);
  const n = normalizeLimits({ max_tool_calls_per_round: 50, max_bash_calls_per_round: 0, max_bytes_to_model_per_round: -5, max_tool_calls_per_round_typo: 3, foo: 1 });
  assert('normalize keeps valid positive int', n.max_tool_calls_per_round === 50);
  assert('normalize drops 0', !('max_bash_calls_per_round' in n));
  assert('normalize drops negative', !('max_bytes_to_model_per_round' in n));
  assert('normalize drops unknown keys', !('foo' in n) && !('max_tool_calls_per_round_typo' in n));
  assert('normalize drops non-integer', !('x' in normalizeLimits({ max_tool_calls_per_round: 1.5 })) && normalizeLimits({ max_tool_calls_per_round: 1.5 }).max_tool_calls_per_round === undefined);
  assert('LIMIT_KEYS has 3 keys', LIMIT_KEYS.length === 3);
}

// ── 6. recordLimitExceeded — tamper-evident chain row (test 5) ───────────────
console.log('\n6. recordLimitExceeded — chain row');
{
  const dir = mkTmp('lf-limits-chain-');
  const f = path.join(dir, 'pipeline-events.jsonl');
  const auditor = createAuditor(f, { lock: false });
  const st = auditor.recordLimitExceeded({ runId: 'R1', sessionId: 'R1', kind: 'max_tool_calls_per_round', max: 3, actual: 7, round: 0 });
  assert('recordLimitExceeded ok', st.ok === true);
  const rows = fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert('row kind = limit_exceeded', rows[0].kind === 'limit_exceeded' && rows[0].action === 'BLOCK');
  assert('tool_inputs carries limit/max/actual/decision',
    rows[0].tool_inputs.limit === 'max_tool_calls_per_round' &&
    rows[0].tool_inputs.max === 3 && rows[0].tool_inputs.actual === 7 &&
    rows[0].tool_inputs.decision === 'block');
  assert('chain verifies', verifyFile(f).ok === true);

  // tamper: change actual without recomputing hash → verify fails
  const r0 = JSON.parse(fs.readFileSync(f, 'utf8').split('\n').filter(Boolean)[0]);
  r0.tool_inputs.actual = 1;
  fs.writeFileSync(f, JSON.stringify(r0) + '\n');
  assert('tampered row fails verification', verifyFile(f).ok === false);
}

// ── 7. loader — parses limits block; absent → {} (test 6: default-off) ───────
console.log('\n7. loader — limits parsing');
{
  const dir = mkTmp('lf-limits-policy-');
  const withLimits = path.join(dir, 'with.yml');
  fs.writeFileSync(withLimits, 'version: 1\nlimits:\n  max_tool_calls_per_round: 25\n  max_bash_calls_per_round: 4\n');
  loader._resetCache();
  const p1 = loader.load(withLimits);
  assert('limits parsed from yaml', p1.limits.max_tool_calls_per_round === 25 && p1.limits.max_bash_calls_per_round === 4);

  const noLimits = path.join(dir, 'none.yml');
  fs.writeFileSync(noLimits, 'version: 1\nblock_secrets_in_tool_results: true\n');
  loader._resetCache();
  const p2 = loader.load(noLimits);
  assert('absent limits → empty object (default-off)', p2.limits && Object.keys(p2.limits).length === 0);
  loader._resetCache();
}

// ── 8. integration — runToolLoop halts on count limits (no network) ──────────
console.log('\n8. integration — runToolLoop enforcement');
(async () => {
  const dir = mkTmp('lf-limits-int-');
  const reqBody = { model: 'claude-sonnet-4-6', messages: [{ role: 'user', content: 'hi' }] };

  // (a) tool-call cap: 3 blocks, limit 2 → halt at round 0, before any cloud call
  {
    loader._setOverrideForTests({ version: 1, limits: { max_tool_calls_per_round: 2 } });
    const chain = path.join(dir, 'a.jsonl');
    const auditor = createAuditor(chain, { lock: false });
    const sse = makeBatchSSE([
      { id: 'b1', name: 'Bash', input: { command: 'ls' } },
      { id: 'b2', name: 'Bash', input: { command: 'pwd' } },
      { id: 'b3', name: 'Bash', input: { command: 'whoami' } },
    ]);
    const res = await _adapter.runToolLoop({
      initialSse: sse, reqBody, reqHeaders: {}, auditor,
      sessionId: 'S', runId: 'S', verbose: false, mode: 'intercept', todoStore: [],
    });
    assert('(a) intercepted=true (halted)', res.intercepted === true);
    assert('(a) limitExceeded kind = max_tool_calls_per_round', res.limitExceeded && res.limitExceeded.kind === 'max_tool_calls_per_round');
    assert('(a) actual=3 max=2', res.limitExceeded.actual === 3 && res.limitExceeded.max === 2);
    assert('(a) synthetic response stop_reason end_turn', res.response && res.response.stop_reason === 'end_turn');
    assert('(a) synthetic text explains the halt', /limit exceeded/i.test(res.response.content[0].text) && /max_tool_calls_per_round/.test(res.response.content[0].text));
    assert('(a) response model echoed', res.response.model === 'claude-sonnet-4-6');
    const rows = fs.readFileSync(chain, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    assert('(a) limit_exceeded row in chain', rows.some(r => r.kind === 'limit_exceeded' && r.tool_inputs.limit === 'max_tool_calls_per_round'));
    assert('(a) chain verifies', verifyFile(chain).ok === true);
  }

  // (b) bash cap: 3 Bash blocks, tool-call limit high, bash limit 1 → halt
  {
    loader._setOverrideForTests({ version: 1, limits: { max_tool_calls_per_round: 100, max_bash_calls_per_round: 1 } });
    const chain = path.join(dir, 'b.jsonl');
    const auditor = createAuditor(chain, { lock: false });
    const sse = makeBatchSSE([
      { id: 'b1', name: 'Bash', input: { command: 'ls' } },
      { id: 'b2', name: 'PowerShell', input: { command: 'Get-ChildItem' } },
      { id: 'b3', name: 'Bash', input: { command: 'pwd' } },
    ]);
    const res = await _adapter.runToolLoop({
      initialSse: sse, reqBody, reqHeaders: {}, auditor,
      sessionId: 'S', runId: 'S', verbose: false, mode: 'intercept', todoStore: [],
    });
    assert('(b) limitExceeded kind = max_bash_calls_per_round', res.limitExceeded && res.limitExceeded.kind === 'max_bash_calls_per_round');
    assert('(b) bash actual=3 max=1', res.limitExceeded.actual === 3 && res.limitExceeded.max === 1);
  }

  // (c) under limit → NOT halted by limits (falls through normally; here the
  //     batch is non-interceptable Bash so it passes through to cloud, i.e. no
  //     limitExceeded and intercepted=false — proving limits did not fire).
  {
    loader._setOverrideForTests({ version: 1, limits: { max_tool_calls_per_round: 10 } });
    const sse = makeBatchSSE([{ id: 'b1', name: 'Bash', input: { command: 'ls' } }]);
    const res = await _adapter.runToolLoop({
      initialSse: sse, reqBody, reqHeaders: {},
      sessionId: 'S', runId: 'S', verbose: false, mode: 'intercept', todoStore: [],
    });
    assert('(c) under limit → no limitExceeded', !res.limitExceeded);
  }

  loader._setOverrideForTests(null);
  loader._resetCache();

  for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
  console.log(`\n${failed === 0 ? '✓' : '✗'} limits: ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
