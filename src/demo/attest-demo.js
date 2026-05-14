'use strict';

/**
 * demo/attest-demo.js — `localfirst demo attest`
 *
 * End-to-end demo of the attestation pipeline, locally, without GitHub
 * Actions or external services. Runs against a synthetic audit chain so
 * it never touches the user's real ~/.localfirst/pipeline-events.jsonl.
 *
 * Flow demonstrated:
 *   1. Build a hash-chained scratch audit chain (3 PASS + 1 BLOCK + 1
 *      TRANSFORM with redacted secret + 1 policy_loaded row)
 *   2. Verify the chain integrity (mirrors `localfirst audit verify`)
 *   3. Build an unsigned attestation for the synthetic run_id
 *   4. Verify the predicate ↔ attestation byte-equivalence (canonical
 *      JSON round-trip) without invoking Sigstore — the test harness
 *      validates the cryptographic path elsewhere
 *   5. Print what the GitHub Check Run summary WOULD look like
 *   6. Render the same data as the View-Evidence page would render it
 *
 * Used by:
 *   - First-time demo / "show me what this does end-to-end"
 *   - Smoke test in CI for the full predicate happy path
 *   - Reference Pipeline doc (docs/reference-pipeline.md)
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const { buildAttestation }      = require('../attest');
const { verifyFile }            = require('../audit/verifier');
const { canonicalize }          = require('../attest/canonicalize');
const { buildSummary }          = require('../../integrations/attest-action/scripts/post-check');

const C = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

const GENESIS = '0'.repeat(64);

function appendRow(file, prevHash, row) {
  const withPrev = { ...row, prev_hash: prevHash };
  const hash = crypto.createHash('sha256').update(JSON.stringify(withPrev), 'utf8').digest('hex');
  const full = { ...withPrev, hash };
  fs.appendFileSync(file, JSON.stringify(full) + '\n');
  return { hash, full };
}

function buildSyntheticChain(chainFile, policyFile) {
  // Reset the chain file fresh.
  fs.writeFileSync(chainFile, '');
  fs.writeFileSync(policyFile, [
    'version: 1',
    'deny_paths:',
    '  - "**/.env"',
    '  - "**/.ssh/**"',
    'deny_patterns:',
    '  api_key: "(?i)api[_-]?key\\\\s*[:=]\\\\s*\\\\S+"',
    'block_secrets_in_tool_results: true',
    '',
  ].join('\n'));

  const RUN = crypto.randomBytes(16).toString('hex');
  const RUN_ID = `${RUN.slice(0,8)}-${RUN.slice(8,12)}-${RUN.slice(12,16)}-${RUN.slice(16,20)}-${RUN.slice(20,32)}`;
  const policyHash = crypto.createHash('sha256').update(fs.readFileSync(policyFile)).digest('hex');

  let prev = GENESIS;
  const ts = (s) => new Date(Date.UTC(2026, 0, 1, 12, 0, s)).toISOString();

  // policy_loaded
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(0), event_id: crypto.randomUUID(),
    run_id: RUN_ID, agent: 'localfirst',
    kind: 'policy_loaded', tool_name: 'policy_loaded', action: 'INFO',
    tool_inputs: { policy_hash: policyHash, policy_path: policyFile, version: 1 },
    policy_source: 'user', reason: 'policy-loaded',
  }));
  // PASS read
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(5), event_id: crypto.randomUUID(),
    run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Read', action: 'PASS',
    tool_inputs: { path: 'src/index.js' },
  }));
  // BLOCK on denied path
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(10), event_id: crypto.randomUUID(),
    run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Read', action: 'BLOCK',
    tool_inputs: { path: '/home/user/.ssh/id_rsa' },
    reason: 'path-denied',
  }));
  // TRANSFORM with redacted secret in result
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(15), event_id: crypto.randomUUID(),
    run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Grep', action: 'TRANSFORM',
    tool_inputs: { pattern: 'TODO', path: 'src/' },
    secrets_redacted: 1,
  }));
  // LOCAL Glob
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(20), event_id: crypto.randomUUID(),
    run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Glob', action: 'LOCAL',
    tool_inputs: { pattern: '**/*.js' },
  }));

  return RUN_ID;
}

async function runAttestDemoCli(_args = []) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-demo-attest-'));
  const chainFile  = path.join(tmpDir, 'pipeline-events.jsonl');
  const policyFile = path.join(tmpDir, 'policy.yml');
  const outFile    = path.join(tmpDir, 'localfirst-attestation.json');

  process.stdout.write(`${C.b('localfirst demo attest')}\n`);
  process.stdout.write(`${C.d('  scratch dir: ' + tmpDir)}\n\n`);

  // ── Step 1 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('1.')} Building synthetic audit chain  ${C.d('(5 rows: policy_loaded + Read PASS + Read BLOCK + Grep TRANSFORM/redacted + Glob LOCAL)')}\n`);
  const runId = buildSyntheticChain(chainFile, policyFile);
  process.stdout.write(`   ${C.g('✓')} run_id: ${C.c(runId)}\n\n`);

  // ── Step 2 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('2.')} Verifying audit-chain integrity  ${C.d('(SHA-256-walk every prev_hash → hash link)')}\n`);
  const ver = verifyFile(chainFile);
  if (!ver.ok) {
    process.stderr.write(`   ${C.r('✗')} chain broken — this should not happen on a synthetic chain\n`);
    return 1;
  }
  process.stdout.write(`   ${C.g('✓')} chain integrity OK  ${C.d('(' + ver.chained + ' rows)')}\n\n`);

  // ── Step 3 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('3.')} Building behavioral attestation  ${C.d('(unsigned — signing requires Sigstore + GitHub OIDC)')}\n`);
  const att = buildAttestation({ runId, logFile: chainFile, policyFile });
  if (!att) {
    process.stderr.write(`   ${C.r('✗')} buildAttestation returned null\n`);
    return 1;
  }
  fs.writeFileSync(outFile, JSON.stringify(att, null, 2));
  process.stdout.write(`   ${C.g('✓')} ${C.d(outFile)}\n`);
  process.stdout.write(`     ${C.d('tool_calls: ' + att.execution_summary.tool_calls +
    '  blocked: ' + att.execution_summary.blocked +
    '  transformed: ' + att.execution_summary.transformed +
    '  secrets_redacted: ' + att.execution_summary.secrets_redacted)}\n`);
  process.stdout.write(`     ${C.d('chain: ' + att.audit_chain.first_hash.slice(0,12) + '…' +
    att.audit_chain.last_hash.slice(0,12) + '  (' + att.audit_chain.event_count + ' events)')}\n`);
  process.stdout.write(`     ${C.d('policy: ' + att.policy.source + '  hash=' +
    att.policy.file_hash.slice(0,16) + '…')}\n\n`);

  // ── Step 4 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('4.')} Canonical-JSON byte-equivalence  ${C.d('(predicate parsed back from disk vs in-memory attestation)')}\n`);
  const reparsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  const { signature: _omit1, ...expected } = att;
  const { signature: _omit2, ...observed } = reparsed;
  if (canonicalize(expected) !== canonicalize(observed)) {
    process.stderr.write(`   ${C.r('✗')} canonical bytes diverged — this is a bug\n`);
    return 1;
  }
  process.stdout.write(`   ${C.g('✓')} canonical round-trip stable\n\n`);

  // ── Step 5 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('5.')} GitHub Check Run preview  ${C.d('(this is what reviewers see on the PR)')}\n`);
  const { title, summary } = buildSummary(att, '');
  process.stdout.write(`\n   ${C.b('Title:')} ${title}\n\n`);
  for (const line of summary.split('\n').slice(0, 12)) {
    process.stdout.write(`   ${line}\n`);
  }
  process.stdout.write(`   ${C.d('… (table truncated; full body in the live Check Run)')}\n\n`);

  // ── Step 6 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('6.')} Next steps for a live deployment\n`);
  process.stdout.write(`   - Add ${C.c('.github/workflows/attest-on-pr.yml')} from ${C.d('docs/reference-pipeline.md')}\n`);
  process.stdout.write(`   - Grant the workflow ${C.c('id-token: write')} + ${C.c('checks: write')} permissions\n`);
  process.stdout.write(`   - Push a PR; the Action will sign via Sigstore keyless and post a Check Run\n`);
  process.stdout.write(`   - Auditors verify offline: ${C.c('localfirst attest verify <file>')}\n\n`);
  process.stdout.write(`${C.d('Scratch artifacts kept at ' + tmpDir + ' for inspection.')}\n`);

  return 0;
}

module.exports = { runAttestDemoCli, buildSyntheticChain };
