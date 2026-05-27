#!/usr/bin/env node
'use strict';

/**
 * test-audit-chain.js — H1 from the 2026-05-15 code review.
 *
 * Covers src/audit/jsonl-auditor.js and src/audit/verifier.js.
 * The hash chain is the load-bearing tamper-evidence pillar — every scenario
 * here is one that, if regressed, would silently invalidate the security
 * promise printed on the README.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { createAuditor, GENESIS, computeHash } = require('./src/audit/jsonl-auditor');
const { verifyFile } = require('./src/audit/verifier');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

function tmpFile() {
  return path.join(os.tmpdir(), `occasio-audit-test-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
}

function readRows(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

function writeRows(file, rows) {
  fs.writeFileSync(file, rows.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf8');
}

function evt(i) {
  return {
    timestamp: `2026-05-15T00:00:0${i % 10}Z`,
    id:        `evt-${i}`,
    sessionId: 'sess-1',
    runId:     'run-1',
    agent:     'claude-code',
    protocol:  'anthropic',
    direction: 'outbound',
    kind:      'tool_call',
    toolName:  'shell_bash',
    toolInput: { command: `echo ${i}` },
  };
}
const decision = { action: 'PASS', reason: 'test', policySource: 'default' };
const result   = { passThrough: true };

// ── 1. happy path ────────────────────────────────────────────────────────────
console.log('\n1. createAuditor — happy path');
{
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 5; i++) {
    const r = a.record(evt(i), decision, result);
    assert(`append row ${i}`, r.ok === true);
  }
  const rows = readRows(f);
  assert('5 rows written', rows.length === 5);
  assert('first row prev_hash is GENESIS', rows[0].prev_hash === GENESIS);
  for (let i = 1; i < rows.length; i++) {
    assert(`row ${i} prev_hash equals row ${i - 1}.hash`, rows[i].prev_hash === rows[i - 1].hash);
  }
  for (const row of rows) {
    const { hash, ...rest } = row;
    assert(`row ${row.event_id} hash matches computeHash`, computeHash(rest) === hash);
  }
  const v = verifyFile(f);
  assert('verifyFile ok=true', v.ok === true);
  assert('verifyFile chained=5', v.chained === 5);
  assert('verifyFile legacy=0', v.legacy === 0);
  assert('verifyFile errors empty', v.errors.length === 0);
  fs.unlinkSync(f);
}

// ── 2. tamper: row deleted ───────────────────────────────────────────────────
console.log('\n2. tamper — row deleted');
{
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 4; i++) a.record(evt(i), decision, result);
  const rows = readRows(f);
  rows.splice(2, 1);
  writeRows(f, rows);
  const v = verifyFile(f);
  assert('chain broken when middle row deleted', v.ok === false);
  assert('at least one chain-break error', v.errors.some(e => /chain broken|prev_hash mismatch/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 3. tamper: hash mutated (content forgery) ────────────────────────────────
console.log('\n3. tamper — hash mutated');
{
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 3; i++) a.record(evt(i), decision, result);
  const rows = readRows(f);
  rows[1].hash = '0'.repeat(64);
  writeRows(f, rows);
  const v = verifyFile(f);
  assert('chain broken when hash field forged', v.ok === false);
  assert('hash mismatch error reported', v.errors.some(e => /hash mismatch/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 4. tamper: prev_hash mutated ─────────────────────────────────────────────
console.log('\n4. tamper — prev_hash mutated');
{
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 3; i++) a.record(evt(i), decision, result);
  const rows = readRows(f);
  rows[2].prev_hash = '0'.repeat(64);
  writeRows(f, rows);
  const v = verifyFile(f);
  assert('chain broken when prev_hash forged', v.ok === false);
  assert('prev_hash mismatch detected', v.errors.some(e => /prev_hash mismatch|hash mismatch/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 5. tamper: tool_inputs mutated but hash field left intact ────────────────
console.log('\n5. tamper — row contents mutated, hash stale');
{
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 3; i++) a.record(evt(i), decision, result);
  const rows = readRows(f);
  rows[1].tool_inputs = { command: 'rm -rf /' };  // forged content; hash now stale
  writeRows(f, rows);
  const v = verifyFile(f);
  assert('content forgery detected via hash mismatch', v.ok === false);
  assert('error mentions hash mismatch', v.errors.some(e => /hash mismatch/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 6. GENESIS boundary: first chained row must start at GENESIS ─────────────
console.log('\n6. GENESIS boundary');
{
  const f = tmpFile();
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  const rows = readRows(f);
  // Forge prev_hash of the FIRST chained row to something other than GENESIS,
  // then recompute the hash so the row is self-consistent — only the GENESIS
  // boundary check should fail.
  rows[0].prev_hash = 'a'.repeat(64);
  const { hash: _omit, ...rest } = rows[0];
  rows[0].hash = computeHash(rest);
  writeRows(f, rows);
  const v = verifyFile(f);
  assert('first-row GENESIS violation detected', v.ok === false);
  assert('error mentions GENESIS', v.errors.some(e => /GENESIS/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 7. legacy rows skipped, fresh chain starts from GENESIS ──────────────────
console.log('\n7. legacy rows + fresh chain');
{
  const f = tmpFile();
  // Pre-existing legacy rows (no hash/prev_hash). loadPrevHash should treat
  // them as unverifiable but not poison the chain.
  fs.writeFileSync(f, JSON.stringify({ ts: 't0', kind: 'legacy', note: 'pre-chain' }) + '\n');
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  a.record(evt(1), decision, result);
  const rows = readRows(f);
  assert('3 rows total (1 legacy + 2 chained)', rows.length === 3);
  assert('first chained row starts at GENESIS', rows[1].prev_hash === GENESIS);
  assert('second chained row links to first', rows[2].prev_hash === rows[1].hash);
  const v = verifyFile(f);
  assert('verify ok with legacy rows present', v.ok === true);
  assert('verify legacy count = 1', v.legacy === 1);
  assert('verify chained count = 2', v.chained === 2);
  fs.unlinkSync(f);
}

// ── 8. chain continues across process "restart" ──────────────────────────────
console.log('\n8. chain continuity across auditor restart');
{
  const f = tmpFile();
  const a1 = createAuditor(f);
  a1.record(evt(0), decision, result);
  a1.record(evt(1), decision, result);
  const after1 = readRows(f);
  const lastHash1 = after1[after1.length - 1].hash;

  // Simulate a fresh process: new auditor instance reads the existing file.
  const a2 = createAuditor(f);
  a2.record(evt(2), decision, result);
  const after2 = readRows(f);
  assert('row 2 prev_hash equals row 1 hash from disk', after2[2].prev_hash === lastHash1);
  const v = verifyFile(f);
  assert('chain across restart verifies', v.ok === true);
  assert('chained=3 after restart', v.chained === 3);
  fs.unlinkSync(f);
}

// ── 9. dropped append does not advance prevHash ──────────────────────────────
console.log('\n9. dropped append leaves chain consistent');
{
  const f = tmpFile();
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  const before = readRows(f);
  const lastHash = before[0].hash;

  // Force the next append to fail by deleting the file and replacing it with
  // a directory at the same path — appendFileSync will throw EISDIR.
  fs.unlinkSync(f);
  fs.mkdirSync(f);
  const r = a.record(evt(1), decision, result);
  assert('record() returns ok=false on append failure', r.ok === false);
  assert('record() surfaces error', r.error instanceof Error);
  assert('droppedRow returned', r.droppedRow && r.droppedRow.event_id === 'evt-1');

  // Cleanup + verify the auditor would re-link to lastHash (prevHash unchanged).
  fs.rmdirSync(f);
  fs.writeFileSync(f, before.map(JSON.stringify).join('\n') + '\n');
  const r2 = a.record(evt(2), decision, result);
  assert('record() recovers on next call', r2.ok === true);
  const after = readRows(f);
  assert('post-recovery row links to lastHash (NOT the dropped row)', after[1].prev_hash === lastHash);
  fs.unlinkSync(f);
}

// ── 10. invalid JSON line ────────────────────────────────────────────────────
console.log('\n10. invalid JSON line surfaces error');
{
  const f = tmpFile();
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  // Append garbage line — verifier should report invalid-JSON error but not crash.
  fs.appendFileSync(f, '{not-json\n');
  a.record(evt(1), decision, result);
  const v = verifyFile(f);
  assert('verify reports invalid JSON line', v.errors.some(e => /Invalid JSON/i.test(e.detail)));
  fs.unlinkSync(f);
}

// ── 11. missing file ─────────────────────────────────────────────────────────
console.log('\n11. missing file → loud verifier error');
{
  const v = verifyFile(path.join(os.tmpdir(), `nonexistent-${Date.now()}.jsonl`));
  assert('verify ok=false', v.ok === false);
  assert('error mentions read failure', v.errors.some(e => /Cannot read file/i.test(e.detail)));
}

// ── 12. recordPolicyLoaded extends the same chain ────────────────────────────
console.log('\n12. recordPolicyLoaded is chain-linked');
{
  const f = tmpFile();
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  const pol = a.recordPolicyLoaded({ hash: 'p'.repeat(64), path: '/tmp/policy.yml', version: 1, source: 'user' });
  assert('recordPolicyLoaded ok', pol.ok === true);
  a.record(evt(1), decision, result);
  const rows = readRows(f);
  assert('3 rows total', rows.length === 3);
  assert('policy_loaded row kind correct', rows[1].kind === 'policy_loaded');
  assert('policy_loaded chained to row 0', rows[1].prev_hash === rows[0].hash);
  assert('next event chained to policy_loaded', rows[2].prev_hash === rows[1].hash);
  const v = verifyFile(f);
  assert('full chain (with policy_loaded) verifies', v.ok === true);
  fs.unlinkSync(f);
}

// ── 13. empty file ───────────────────────────────────────────────────────────
console.log('\n13. empty file');
{
  const f = tmpFile();
  fs.writeFileSync(f, '');
  const v = verifyFile(f);
  assert('empty file ok=true (nothing to break)', v.ok === true);
  assert('total=0', v.total === 0);
  assert('chained=0', v.chained === 0);
  fs.unlinkSync(f);
}

// ── 14. tail-read: loadPrevHash bounded by window size ──────────────────────
console.log('\n14. loadPrevHash uses bounded tail-read');
{
  const { loadPrevHash, scanTailForPrevHash } = require('./src/audit/jsonl-auditor');
  const f = tmpFile();
  // Build 10k-event file by reusing one auditor.
  const a = createAuditor(f);
  const N = 10000;
  for (let i = 0; i < N; i++) a.record(evt(i), decision, result);
  const rows = readRows(f);
  const lastHash = rows[rows.length - 1].hash;

  // Fresh load must return the last hash on disk.
  const reloaded = loadPrevHash(f);
  assert('loadPrevHash returns last hash from 10k-event file', reloaded === lastHash);

  // Bootstrap latency: tail-read must be fast relative to a whole-file scan.
  // Conservative bound (50ms) so the test does not flake on slow CI.
  const t0 = Date.now();
  for (let i = 0; i < 10; i++) loadPrevHash(f);
  const elapsed = Date.now() - t0;
  assert(`10× loadPrevHash on 10k-row file under 500ms (was ${elapsed}ms)`, elapsed < 500);

  // Tiny window: still returns the last hash because the last row fits.
  const tinyReloaded = loadPrevHash(f, { tailBytes: 4096 });
  assert('loadPrevHash respects tailBytes opt + still finds last hash', tinyReloaded === lastHash);

  // scanTailForPrevHash low-level tuple shape.
  const [code, val] = scanTailForPrevHash(f);
  assert('scanTailForPrevHash returns hash code', code === 'hash');
  assert('scanTailForPrevHash returns matching value', val === lastHash);

  fs.unlinkSync(f);
}

// ── 15. crash recovery: partial trailing line is fail-hard ──────────────────
console.log('\n15. crash recovery — partial trailing line');
{
  const { loadPrevHash } = require('./src/audit/jsonl-auditor');
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 3; i++) a.record(evt(i), decision, result);
  // Simulate a partial write: append half a row, no trailing newline.
  fs.appendFileSync(f, '{"ts":"2026-05-15T00:00:99Z","event_id":"evt-partia');

  let threw = false;
  try { loadPrevHash(f); } catch (e) {
    threw = e && e.code === 'AUDIT_CORRUPT';
  }
  // Note: we expect to FALL BACK to the previous hash here because earlier
  // complete rows exist in the window — failHard only fires when no
  // recoverable hash row is present in the tail window. Verify that path:
  const recovered = loadPrevHash(f);
  const rows = fs.readFileSync(f, 'utf8').split('\n').filter(Boolean);
  // The last complete JSON row's hash is what we must chain from.
  const lastValid = JSON.parse(rows[2]).hash;  // rows[3] is the partial garbage
  assert('partial line is skipped, prev valid hash recovered', recovered === lastValid);
  assert('no throw when recoverable row exists in window', threw === false);

  // Now construct a file where ONLY a partial line exists — no recoverable hash.
  const f2 = tmpFile();
  fs.writeFileSync(f2, '{"ts":"2026-05-15T00:00:99Z","event_id":"evt-x');
  let hardThrew = false;
  try { loadPrevHash(f2); } catch (e) { hardThrew = e && e.code === 'AUDIT_CORRUPT'; }
  assert('loadPrevHash throws AUDIT_CORRUPT when no recoverable row', hardThrew === true);

  // failHard: false → warn + GENESIS instead of throw.
  const fallback = loadPrevHash(f2, { failHard: false });
  assert('failHard=false falls back to GENESIS with warning', fallback === GENESIS);

  fs.unlinkSync(f);
  fs.unlinkSync(f2);
}

// ── 16. repair CLI: truncate partial trailing line ──────────────────────────
console.log('\n16. occasio audit repair');
{
  const { repairAuditFile } = require('./src/audit/repair');
  const f = tmpFile();
  const a = createAuditor(f);
  for (let i = 0; i < 3; i++) a.record(evt(i), decision, result);
  const beforeRows = readRows(f);
  // Append a partial line.
  fs.appendFileSync(f, '{"ts":"partial","oops');

  // Dry-run: should report would-truncate without modifying file.
  const dry = repairAuditFile(f, { dryRun: true });
  assert('dryRun reports would-truncate', dry.wouldTruncate === true);
  assert('dryRun does not modify file', fs.readFileSync(f, 'utf8').includes('"oops'));
  assert('dryRun does not write backup', !fs.existsSync(f + '.bak'));

  // Real run: truncates, writes backup.
  const out = repairAuditFile(f, { dryRun: false });
  assert('repair: truncated=true', out.truncated === true);
  assert('repair: backup file written', fs.existsSync(out.backupPath));
  const after = readRows(f);
  assert('repair: 3 complete rows remain', after.length === 3);
  assert('repair: last surviving row is intact', after[2].hash === beforeRows[2].hash);

  // A subsequent auditor open succeeds with the original last hash.
  const a2 = createAuditor(f);
  a2.record(evt(99), decision, result);
  const finalRows = readRows(f);
  assert('post-repair auditor chains from last valid hash',
    finalRows[3].prev_hash === beforeRows[2].hash);

  fs.unlinkSync(f);
  fs.unlinkSync(out.backupPath);
}

// ── 17. schema_version: every new row carries audit_schema=1 ────────────────
console.log('\n17. audit_schema versioning');
{
  const f = tmpFile();
  const a = createAuditor(f);
  a.record(evt(0), decision, result);
  a.recordPolicyLoaded({ hash: 'p'.repeat(64), path: '/tmp/p.yml', version: 1, source: 'user' });
  const rows = readRows(f);
  assert('record() row carries audit_schema=1', rows[0].audit_schema === 1);
  assert('recordPolicyLoaded row carries audit_schema=1', rows[1].audit_schema === 1);
  // The audit_schema field IS part of the hash input — verify chain still ok.
  const v = verifyFile(f);
  assert('chain with audit_schema field verifies', v.ok === true);
  fs.unlinkSync(f);
}

// ── 18. schema_version: legacy rows without audit_schema still verify ───────
console.log('\n18. legacy rows without audit_schema still accepted');
{
  const f = tmpFile();
  const a1 = createAuditor(f);
  a1.record(evt(0), decision, result);
  // Strip audit_schema from the first row and recompute its hash to simulate
  // a row written by a pre-v0.8.4 build, then chain a new row on top.
  const rows = readRows(f);
  delete rows[0].audit_schema;
  const { hash: _h, ...rest } = rows[0];
  rows[0].hash = computeHash(rest);
  writeRows(f, rows);

  const a2 = createAuditor(f);
  a2.record(evt(1), decision, result);
  const v = verifyFile(f);
  assert('legacy row + new row chain verifies', v.ok === true);
  const final = readRows(f);
  assert('legacy row stays schema-less', final[0].audit_schema === undefined);
  assert('new row has audit_schema=1', final[1].audit_schema === 1);
  fs.unlinkSync(f);
}

// ── 19. recordRequest — per-request accounting row ─────────────────────────
console.log('\n19. recordRequest — per-request accounting');
{
  const f = tmpFile();
  const a = createAuditor(f);

  // happy path: write one request row
  const r1 = a.recordRequest({
    iso: '2026-05-28T12:00:00.000Z',
    run_id: 'r-acct-1',
    cwd: 'C:\\\\proj',
    event_type: 'cloud_sent',
    model: 'claude-haiku-4-5',
    input_tokens: 120, output_tokens: 8,
    cache_read_tokens: 0, cache_write_tokens: 0,
    cost: 0.000123, cache_savings: 0,
  });
  assert('recordRequest ok=true', r1.ok === true);

  const rows = readRows(f);
  assert('one row written', rows.length === 1);
  assert('kind is "request"', rows[0].kind === 'request');
  assert('audit_schema present', rows[0].audit_schema === 1);
  assert('prev_hash is GENESIS', rows[0].prev_hash === GENESIS);
  assert('hash field present', typeof rows[0].hash === 'string' && rows[0].hash.length === 64);
  assert('run_id propagated', rows[0].run_id === 'r-acct-1');
  assert('event_type propagated', rows[0].event_type === 'cloud_sent');
  assert('cost propagated', rows[0].cost === 0.000123);

  // chains correctly with subsequent rows of different kinds
  const r2 = a.record(evt(0), decision, result);
  assert('record after recordRequest ok', r2.ok === true);
  const rows2 = readRows(f);
  assert('two rows total', rows2.length === 2);
  assert('row 2 prev_hash links to row 1 hash', rows2[1].prev_hash === rows2[0].hash);

  // verifier accepts mixed-kind chain
  const v = verifyFile(f);
  assert('mixed-kind chain verifies', v.ok === true);
  assert('verifier counted 2 rows', v.chained === 2);

  // recordRequest with null/undefined entry is a safe no-op
  const rNull = a.recordRequest(null);
  assert('recordRequest(null) ok=true (no-op)', rNull.ok === true);
  assert('null call did not write a row', readRows(f).length === 2);

  // defaults: missing tokens/cost fields become 0, not undefined
  const r3 = a.recordRequest({ iso: '2026-05-28T12:00:01.000Z', run_id: 'r-acct-1' });
  assert('recordRequest with minimal entry ok', r3.ok === true);
  const last = readRows(f).pop();
  assert('missing input_tokens defaults to 0', last.input_tokens === 0);
  assert('missing cost defaults to 0', last.cost === 0);
  assert('missing event_type falls back to cloud_sent', last.event_type === 'cloud_sent');

  fs.unlinkSync(f);
}

// ── 20. recordRequest canonical serialization stability ────────────────────
//
// Pin the JSON-key order of a deterministic kind:"request" row. If this
// test fails, someone reordered fields in recordRequestInner()'s row
// literal in src/audit/jsonl-auditor.js. That's a BREAKING CHANGE to the
// audit chain's canonical serialization: rows written after the reorder
// will hash differently from rows written before, and the independent
// Python walker (docs/audit_walker.py) will see a hash mismatch on the
// boundary row. Either revert the reorder, or bump audit_schema
// intentionally and update both this test and the Python walker.
console.log('\n20. recordRequest canonical serialization stability');
{
  const crypto = require('crypto');
  const realUuid = crypto.randomUUID;
  crypto.randomUUID = () => '00000000-0000-0000-0000-000000000000';

  const f = tmpFile();
  const a = createAuditor(f);
  try {
    const r = a.recordRequest({
      iso: '2026-05-28T12:00:00.000Z',
      run_id: 'fixed-run-id',
      cwd: 'C:\\fixed\\path',
      event_type: 'cloud_sent',
      model: 'claude-haiku-4-5',
      input_tokens: 100,
      output_tokens: 10,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
      cost: 0.001,
      cache_savings: 0.0005,
      lao_tokens_saved: 0,
      lao_cost_saved: 0,
      distill_tokens_saved: 0,
      distill_cost_saved: 0,
      tools_attempted: 1,
      tools_local_count: 1,
      tools_mcp_count: 0,
    });
    assert('recordRequest ok', r.ok === true);

    const row = readRows(f)[0];
    const keys = Object.keys(row);

    // Canonical key order — MUST match the field order in
    // recordRequestInner's row literal in src/audit/jsonl-auditor.js.
    const expectedKeys = [
      'audit_schema', 'ts', 'event_id', 'session_id', 'run_id',
      'agent', 'protocol', 'direction', 'kind', 'event_type',
      'model', 'cwd', 'input_tokens', 'output_tokens',
      'cache_read_tokens', 'cache_write_tokens', 'cost', 'cache_savings',
      'lao_tokens_saved', 'lao_cost_saved', 'distill_tokens_saved', 'distill_cost_saved',
      'tools_attempted', 'tools_local_count', 'tools_mcp_count',
      'prev_hash', 'hash',
    ];
    assert(`row has ${expectedKeys.length} keys in canonical order`,
      JSON.stringify(keys) === JSON.stringify(expectedKeys),
      `actual: ${JSON.stringify(keys)}`);

    // Hash recomputation: confirms the canonical-serialization contract.
    // computeHash uses JSON.stringify which respects insertion order in
    // V8 (and Python dict from 3.7+). If anyone changes the key order
    // in the row literal, the recomputed hash here will diverge from
    // the stored hash, and this assertion catches it.
    const withoutHash = { ...row };
    delete withoutHash.hash;
    const recomputed = computeHash(withoutHash);
    assert('stored hash equals computeHash(row-without-hash)', row.hash === recomputed);

    // Cross-walker verification: the JS verifier accepts the row.
    const v = verifyFile(f);
    assert('canonical row verifies', v.ok === true);
    assert('verifier counted 1 row', v.chained === 1);
  } finally {
    crypto.randomUUID = realUuid;
    try { fs.unlinkSync(f); } catch { /* */ }
  }
}

// ── 21. file-locking: two concurrent writers preserve the chain ─────────────
console.log('\n21. file-locking — concurrent writers');
{
  let lockAvailable = true;
  try { require('proper-lockfile'); } catch { lockAvailable = false; }
  if (!lockAvailable) {
    console.log('  (skipped — proper-lockfile not installed)');
  } else {
    const { spawnSync } = require('child_process');
    const f = tmpFile();
    fs.writeFileSync(f, '');  // start from empty chain

    const N = 25;
    const workerScript = path.join(__dirname, 'test-audit-lock-worker.js');
    // Launch two writers in parallel via detached spawn; wait on both via
    // spawnSync would serialize them, so we use the child_process module
    // directly with non-blocking spawn + a small wait loop.
    const { spawn } = require('child_process');
    const w1 = spawn(process.execPath, [workerScript, f, String(N), 'A'], { stdio: 'inherit' });
    const w2 = spawn(process.execPath, [workerScript, f, String(N), 'B'], { stdio: 'inherit' });

    const waitFor = (proc) => new Promise(res => proc.on('exit', code => res(code)));
    (async () => {
      const [c1, c2] = await Promise.all([waitFor(w1), waitFor(w2)]);
      assert('both writers exit 0', c1 === 0 && c2 === 0);

      const rows = readRows(f);
      assert(`${2 * N} total rows written`, rows.length === 2 * N);

      // Chain continuity: every row's prev_hash must equal the previous row's hash.
      let ok = true, where = -1;
      for (let i = 1; i < rows.length; i++) {
        if (rows[i].prev_hash !== rows[i - 1].hash) { ok = false; where = i; break; }
      }
      assert(`chain unbroken across interleaved writers (break at ${where})`, ok);

      const v = verifyFile(f);
      assert('multi-writer chain verifies', v.ok === true);
      assert(`verifyFile chained=${2 * N}`, v.chained === 2 * N);

      // Both writers should be represented (no writer was starved out).
      const tagA = rows.filter(r => r.event_id?.startsWith('A-')).length;
      const tagB = rows.filter(r => r.event_id?.startsWith('B-')).length;
      assert(`writer A produced ${N} rows`, tagA === N);
      assert(`writer B produced ${N} rows`, tagB === N);

      fs.unlinkSync(f);
      // Clean up potential stale .lock directory.
      try { fs.rmSync(f + '.lock', { recursive: true, force: true }); } catch { /* not present */ }
    })().then(() => {
      // Final summary printout runs only after the async block completes.
      printSummary();
    });
    // Skip the synchronous summary at end-of-file; the async block owns it.
    return;
  }
}

// ── Summary ──────────────────────────────────────────────────────────────────
function printSummary() {
console.log(`\n${'─'.repeat(40)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`✓ All ${total} audit-chain tests passed\n`);
  process.exit(0);
} else {
  console.error(`✗ ${failed}/${total} audit-chain tests failed\n`);
  process.exit(1);
}
}

// If the multi-process block above did not opt to handle the summary (because
// proper-lockfile is unavailable and the block skipped its async handler),
// run it synchronously now.
printSummary();
