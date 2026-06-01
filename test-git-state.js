#!/usr/bin/env node
'use strict';

/**
 * test-git-state.js — git-state binding (Idea #1).
 *
 * Covers:
 *   - src/git/state.js            captureGitState / gitStateDigest
 *   - src/audit/jsonl-auditor.js  recordGitState → tamper-evident git_state row
 *   - src/attest/index.js         buildAttestation pulls git_state from chain
 *   - src/attest/verify.js        check #4 predicate: claimed git_state must
 *                                 byte-match what is re-derived from the chain
 *
 * No network, no real API keys, no machine-specific paths: every git repo is
 * created in a fresh os.tmpdir() and removed at the end. If `git` is not on
 * PATH, the git-dependent assertions are skipped (not failed) and the
 * chain/attestation paths are still exercised with hand-built state objects.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const { captureGitState, gitStateDigest } = require('./src/git/state');
const { createAuditor }                   = require('./src/audit/jsonl-auditor');
const { verifyFile }                      = require('./src/audit/verifier');
const { buildAttestation, deriveGitState } = require('./src/attest/index');
const { loadRunSlice }                    = require('./src/attest/run-slice');
const { canonicalize }                    = require('./src/attest/canonicalize');

let passed = 0, failed = 0, skipped = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}
function skip(label) { console.log(`  ~ ${label} (skipped)`); skipped++; }

const tmps = [];
function mkTmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmps.push(d);
  return d;
}

// Quiet, isolated git invocation for building test fixtures.
function rawGit(args, cwd) {
  return spawnSync('git', args, {
    cwd, encoding: 'utf8', timeout: 8000, windowsHide: true,
    env: Object.assign({}, process.env, {
      GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
      GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.dev',
      GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.dev',
    }),
  });
}
function gitAvailable() {
  try { const r = rawGit(['--version'], os.tmpdir()); return r.status === 0; }
  catch { return false; }
}
function initRepo(dir) {
  rawGit(['init'], dir);
  rawGit(['config', 'commit.gpgsign', 'false'], dir);
  rawGit(['config', 'user.email', 't@t.dev'], dir);
  rawGit(['config', 'user.name', 't'], dir);
}

const HAS_GIT = gitAvailable();

// ── 1. captureGitState — clean repo ──────────────────────────────────────────
console.log('\n1. captureGitState — clean repo with one commit');
if (HAS_GIT) {
  const dir = mkTmp('lf-git-clean-');
  initRepo(dir);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello\n');
  rawGit(['add', 'a.txt'], dir);
  rawGit(['commit', '-m', 'init'], dir);

  const s = captureGitState(dir);
  assert('is_repo true', s.is_repo === true);
  assert('head is 40-hex sha', /^[0-9a-f]{40}$/.test(s.head || ''));
  assert('branch is a non-empty string', typeof s.branch === 'string' && s.branch.length > 0);
  assert('clean → dirty false', s.dirty === false);
  assert('clean → no changed files', s.changed_files.length === 0);
  assert('clean → no untracked files', s.untracked_files.length === 0);
  assert('clean → diff_hash null', s.diff_hash === null);
} else {
  skip('captureGitState clean-repo asserts — git not on PATH');
}

// ── 2. captureGitState — dirty (modified tracked file) ───────────────────────
console.log('\n2. captureGitState — dirty tracked file');
if (HAS_GIT) {
  const dir = mkTmp('lf-git-dirty-');
  initRepo(dir);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello\n');
  rawGit(['add', 'a.txt'], dir);
  rawGit(['commit', '-m', 'init'], dir);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello\nworld\n');   // modify

  const s = captureGitState(dir);
  assert('dirty true', s.dirty === true);
  assert('changed_files includes a.txt', s.changed_files.includes('a.txt'));
  assert('diff_hash is 64-hex', /^[0-9a-f]{64}$/.test(s.diff_hash || ''));
} else {
  skip('captureGitState dirty asserts — git not on PATH');
}

// ── 3. captureGitState — untracked file ──────────────────────────────────────
console.log('\n3. captureGitState — untracked file');
if (HAS_GIT) {
  const dir = mkTmp('lf-git-untracked-');
  initRepo(dir);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello\n');
  rawGit(['add', 'a.txt'], dir);
  rawGit(['commit', '-m', 'init'], dir);
  fs.writeFileSync(path.join(dir, 'new.txt'), 'untracked\n');

  const s = captureGitState(dir);
  assert('untracked_files includes new.txt', s.untracked_files.includes('new.txt'));
  assert('untracked → dirty true', s.dirty === true);
} else {
  skip('captureGitState untracked asserts — git not on PATH');
}

// ── 4. captureGitState — non-git directory (edge) ────────────────────────────
console.log('\n4. captureGitState — non-git directory');
{
  const dir = mkTmp('lf-git-none-');
  fs.writeFileSync(path.join(dir, 'a.txt'), 'plain\n');
  const s = captureGitState(dir);
  assert('non-git → is_repo false', s.is_repo === false);
  assert('non-git → head null', s.head === null);
  assert('non-git → dirty false', s.dirty === false);
  assert('non-git → empty changed/untracked',
    s.changed_files.length === 0 && s.untracked_files.length === 0);
}

// ── 5. gitStateDigest — deterministic + order-insensitive ────────────────────
console.log('\n5. gitStateDigest — determinism');
{
  const a = { is_repo: true, head: 'a'.repeat(40), branch: 'main', dirty: true,
    changed_files: ['b.txt', 'a.txt'], untracked_files: ['z.txt'], diff_hash: 'd'.repeat(64) };
  const b = { is_repo: true, head: 'a'.repeat(40), branch: 'main', dirty: true,
    changed_files: ['a.txt', 'b.txt'], untracked_files: ['z.txt'], diff_hash: 'd'.repeat(64) };
  assert('digest is 64-hex', /^[0-9a-f]{64}$/.test(gitStateDigest(a)));
  assert('digest stable across file ordering', gitStateDigest(a) === gitStateDigest(b));
  const c = Object.assign({}, a, { diff_hash: 'e'.repeat(64) });
  assert('digest changes when diff_hash changes', gitStateDigest(a) !== gitStateDigest(c));
}

// Shared synthetic states for chain/attestation tests (no git needed).
const START_STATE = {
  is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: false,
  changed_files: [], untracked_files: [], diff_hash: null,
};
const END_STATE = {
  is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: true,
  changed_files: ['src/app.js'], untracked_files: ['notes.md'], diff_hash: '2'.repeat(64),
};

// ── 6. recordGitState — tamper-evident row, chain verifies ───────────────────
console.log('\n6. recordGitState — chain integrity');
const RUN = '99999999-9999-9999-9999-999999999999';
let chainFile;
{
  const dir = mkTmp('lf-git-chain-');
  chainFile = path.join(dir, 'pipeline-events.jsonl');
  const auditor = createAuditor(chainFile, { lock: false });

  const r1 = auditor.recordGitState({ phase: 'run_start', runId: RUN, sessionId: RUN, cwd: dir, state: START_STATE });
  const r2 = auditor.recordGitState({ phase: 'run_end',   runId: RUN, sessionId: RUN, cwd: dir, state: END_STATE });
  assert('recordGitState run_start ok', r1.ok === true);
  assert('recordGitState run_end ok',   r2.ok === true);

  const rows = fs.readFileSync(chainFile, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert('two git_state rows written', rows.length === 2 && rows.every(r => r.kind === 'git_state'));
  assert('row carries digest', /^[0-9a-f]{64}$/.test(rows[0].tool_inputs.digest));

  const v = verifyFile(chainFile);
  assert('chain verifies intact', v.ok === true);
  assert('both rows chained', v.chained === 2);
}

// ── 7. recordGitState — tampering a row breaks the chain (failure path) ──────
console.log('\n7. tamper detection — modified git_state row fails verify');
{
  const dir = mkTmp('lf-git-tamper-');
  const f = path.join(dir, 'pipeline-events.jsonl');
  const auditor = createAuditor(f, { lock: false });
  auditor.recordGitState({ phase: 'run_start', runId: RUN, sessionId: RUN, cwd: dir, state: START_STATE });
  auditor.recordGitState({ phase: 'run_end',   runId: RUN, sessionId: RUN, cwd: dir, state: END_STATE });

  // Flip the recorded HEAD on the first row WITHOUT recomputing its hash.
  const lines = fs.readFileSync(f, 'utf8').split('\n').filter(Boolean);
  const row0 = JSON.parse(lines[0]);
  row0.tool_inputs.head = '0'.repeat(40);          // lie about the commit
  lines[0] = JSON.stringify(row0);
  fs.writeFileSync(f, lines.join('\n') + '\n');

  const v = verifyFile(f);
  assert('tampered chain fails verification', v.ok === false);
  assert('verifier reports an error', (v.errors || []).length > 0);
}

// ── 8. buildAttestation — pulls chain-sourced git_state ──────────────────────
console.log('\n8. buildAttestation — subject.git_state from chain');
let attestation;
{
  const dir = mkTmp('lf-git-attest-');
  const polFile = path.join(dir, 'policy.yml');
  fs.writeFileSync(polFile, 'block_secrets_in_tool_results: true\n');

  attestation = buildAttestation({ runId: RUN, logFile: chainFile, policyFile: polFile });
  assert('attestation built', !!attestation);
  assert('subject.git_state present', !!attestation.subject.git_state);
  assert('git_state provenance = chain', attestation.subject.git_state.provenance === 'chain');
  assert('git_state.run_start.head from chain',
    attestation.subject.git_state.run_start.head === '1'.repeat(40));
  assert('git_state.run_end captured dirty state',
    attestation.subject.git_state.run_end.dirty === true &&
    attestation.subject.git_state.run_end.changed_files[0] === 'src/app.js');
  assert('subject.git_commit defaults to run_start head',
    attestation.subject.git_commit === '1'.repeat(40));
}

// ── 9. verifier check #4 predicate — claimed git_state must match chain ──────
console.log('\n9. cross-check predicate — git_state vs chain');
{
  // Honest: re-derive straight from the chain → byte-equal to what the
  // attestation claims (this is exactly verify.js check #4).
  const slice = loadRunSlice(chainFile, RUN);
  const rederived = deriveGitState(slice.events);
  assert('honest attestation matches chain',
    canonicalize(rederived) === canonicalize(attestation.subject.git_state));

  // Tampered: edit the attestation's claimed run_end head after the fact →
  // no longer matches the chain-derived object.
  const forged = JSON.parse(JSON.stringify(attestation.subject.git_state));
  forged.run_end.head = 'f'.repeat(40);
  assert('forged git_state diverges from chain',
    canonicalize(rederived) !== canonicalize(forged));
}

// ── 10. backward-compat — no git_state rows → no subject.git_state ───────────
console.log('\n10. backward-compat — flag-only / no git rows');
{
  const dir = mkTmp('lf-git-compat-');
  const f = path.join(dir, 'pipeline-events.jsonl');
  const polFile = path.join(dir, 'policy.yml');
  fs.writeFileSync(polFile, 'block_secrets_in_tool_results: true\n');
  // A chain with a single tool_call row, no git_state.
  const auditor = createAuditor(f, { lock: false });
  auditor.record(
    { timestamp: '2026-05-12T10:00:00.000Z', id: crypto.randomUUID(), sessionId: RUN, runId: RUN,
      agent: 'claude-code', protocol: 'anthropic-http', direction: 'outbound', kind: 'tool_call',
      toolName: 'read_file', toolInput: { path: '/tmp/x' } },
    { action: 'LOCAL', reason: 'native-handleable', policySource: 'default' },
    { exitCode: 0 });
  const att = buildAttestation({ runId: RUN, logFile: f, policyFile: polFile });
  assert('no git_state key when chain has no git_state rows',
    !Object.prototype.hasOwnProperty.call(att.subject, 'git_state'));
  assert('no git_commit when neither flag nor chain provides one',
    !Object.prototype.hasOwnProperty.call(att.subject, 'git_commit'));
}

// ── cleanup ───────────────────────────────────────────────────────────────────
for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }

console.log(`\n${failed === 0 ? '✓' : '✗'} git-state: ${passed} passed, ${failed} failed, ${skipped} skipped\n`);
process.exit(failed === 0 ? 0 : 1);
