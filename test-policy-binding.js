#!/usr/bin/env node
'use strict';

/**
 * test-policy-binding.js — the real recordPolicyLoaded writer must bind a
 * policy_loaded row to its run_id, so `occasio verify --strict` can pass policy
 * binding on a real run.
 *
 * Why this test exists: test-bundle.js hand-builds the policy_loaded row WITH a
 * run_id and the verifier passes on it — but no test drove the actual writer,
 * which used to hard-code run_id:undefined. That gap let the run_id never reach
 * the chain, so loadRunSlice excluded every policy_loaded row, every attestation
 * fell back to policy.source='inferred', and the GitHub Action's
 * `occasio verify --strict` self-verify could never go green on a real run.
 *
 * This test drives createAuditor().recordPolicyLoaded directly (the same path
 * the proxy uses), then bundles the run and asserts policy binding holds under
 * --strict. A negative control proves the writer still omits run_id when none is
 * supplied (process-scoped MCP rows stay byte-for-byte unchanged).
 *
 * No network, no API keys: temp files in os.tmpdir(), unsigned bundle.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const { createAuditor } = require('./src/audit/jsonl-auditor');
const { buildBundle }   = require('./src/bundle');
const { verifyBundle }  = require('./src/bundle/verify');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}
function sha256hex(str) { return crypto.createHash('sha256').update(str, 'utf8').digest('hex'); }

const tmps = [];
function mkTmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmps.push(d);
  return d;
}
function readRows(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

const GIT_STATE = {
  is_repo: true, head: 'a'.repeat(40), branch: 'main', dirty: false,
  changed_files: [], untracked_files: [], diff_hash: null,
};

async function main() {
  console.log('test-policy-binding — real recordPolicyLoaded binds run_id\n');

  const dir       = mkTmp('lf-polbind-');
  const chainFile = path.join(dir, 'pipeline-events.jsonl');
  const polFile   = path.join(dir, 'policy.yml');
  const POLICY_TEXT = 'block_secrets_in_tool_results: true\ndeny_paths:\n  - /etc/secret\n';
  fs.writeFileSync(polFile, POLICY_TEXT);
  const POLHASH = sha256hex(POLICY_TEXT);
  const RUN = '77777777-7777-7777-7777-777777777777';

  // lock:false — single writer in-test, no concurrent proxy/MCP process.
  const auditor = createAuditor(chainFile, { lock: false });

  // ── 1. the real writer carries run_id when supplied ──────────────────────
  console.log('1. recordPolicyLoaded writes run_id');
  const r1 = auditor.recordPolicyLoaded({
    hash: POLHASH, path: polFile, version: 1, source: 'user',
    runId: RUN, sessionId: RUN,
  });
  assert('write ok', r1 && r1.ok === true, JSON.stringify(r1));
  auditor.recordGitState({ phase: 'run_start', runId: RUN, sessionId: RUN, cwd: dir, state: GIT_STATE });
  auditor.recordGitState({ phase: 'run_end',   runId: RUN, sessionId: RUN, cwd: dir, state: GIT_STATE });

  const rows = readRows(chainFile);
  const pl = rows.find(r => r.kind === 'policy_loaded');
  assert('policy_loaded row present', !!pl);
  assert('policy_loaded.run_id === RUN', pl && pl.run_id === RUN, pl && JSON.stringify(pl.run_id));
  assert('policy_loaded.session_id === RUN', pl && pl.session_id === RUN);
  assert('policy_loaded.policy_source = user', pl && pl.policy_source === 'user');

  // ── 2. bundle over the run binds policy (source=user) ────────────────────
  console.log('\n2. bundle binds policy.source = user');
  const bundle = buildBundle({ runId: RUN, logFile: chainFile, policyFile: polFile });
  assert('bundle built', !!bundle);
  assert('attestation.policy.source = user (not inferred)',
    bundle && bundle.attestation.policy.source === 'user',
    bundle && bundle.attestation.policy.source);
  assert('attestation.policy.file_hash = sha256(policy bytes)',
    bundle && bundle.attestation.policy.file_hash === POLHASH);

  // ── 3. occasio verify --strict passes policy binding + git state ─────────
  console.log('\n3. verify --strict (requirePolicyBinding + requireGitState)');
  const bundleFile = path.join(dir, 'run.occasio.json');
  fs.writeFileSync(bundleFile, JSON.stringify(bundle, null, 2));
  const v = await verifyBundle(bundleFile, { requirePolicyBinding: true, requireGitState: true });
  const polCheck = v.checks.find(c => c.name === 'policy binding');
  const gitCheck = v.checks.find(c => c.name === 'git state matches chain');
  assert('policy binding check passed', !!polCheck && polCheck.ok === true,
    polCheck && polCheck.detail);
  assert('git state check passed', !!gitCheck && gitCheck.ok === true,
    gitCheck && gitCheck.detail);
  // Unsigned bundle: the strict-signature requirement is NOT set here, so the
  // overall result is ok (signature check passes as "unsigned, not required").
  assert('overall ok (unsigned, signature not required)', v.ok === true,
    JSON.stringify(v.checks.filter(c => !c.ok)));

  // ── 4. negative control: no runId → row omits run_id, bundle stays inferred
  console.log('\n4. negative control — no runId keeps the old inferred behavior');
  const dir2       = mkTmp('lf-polbind-neg-');
  const chainFile2 = path.join(dir2, 'pipeline-events.jsonl');
  fs.writeFileSync(path.join(dir2, 'policy.yml'), POLICY_TEXT);
  const polFile2   = path.join(dir2, 'policy.yml');
  const RUN2 = '88888888-8888-8888-8888-888888888888';
  const aud2 = createAuditor(chainFile2, { lock: false });
  // policy_loaded WITHOUT runId (the process-scoped MCP shape) …
  aud2.recordPolicyLoaded({ hash: sha256hex(POLICY_TEXT), path: polFile2, version: 1, source: 'user' });
  // … and a git_state row that DOES carry the run, so the slice is non-empty.
  aud2.recordGitState({ phase: 'run_start', runId: RUN2, sessionId: RUN2, cwd: dir2, state: GIT_STATE });
  const plNeg = readRows(chainFile2).find(r => r.kind === 'policy_loaded');
  assert('policy_loaded without runId omits run_id', plNeg && plNeg.run_id === undefined,
    plNeg && JSON.stringify(plNeg.run_id));
  const bundle2 = buildBundle({ runId: RUN2, logFile: chainFile2, policyFile: polFile2 });
  assert('bundle without bound policy_loaded → source=inferred',
    bundle2 && bundle2.attestation.policy.source === 'inferred',
    bundle2 && bundle2.attestation.policy.source);
  const bundleFile2 = path.join(dir2, 'run.occasio.json');
  fs.writeFileSync(bundleFile2, JSON.stringify(bundle2, null, 2));
  const v2 = await verifyBundle(bundleFile2, { requirePolicyBinding: true });
  assert('inferred policy fails --require-policy-binding', v2.ok === false,
    JSON.stringify(v2.checks));

  // ── done ─────────────────────────────────────────────────────────────────
  for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
  console.log(`\n${failed === 0 ? '✓' : '✗'} policy-binding: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
