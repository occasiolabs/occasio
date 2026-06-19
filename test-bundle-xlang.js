#!/usr/bin/env node
'use strict';

/**
 * test-bundle-xlang.js — the Node↔Python guarantee for the evidence bundle.
 *
 * src/bundle/verify.js (Node) and docs/verify_bundle.py (Python) must agree
 * check-for-check on the SAME bundle file, including the manifest hashes that
 * reproduce V8's JSON.stringify byte-for-byte (via docs/audit_walker._v8_json).
 * This pins it: honest bundles pass in both; each single-point tamper fails the
 * SAME check in both; and the strict requirements (--require-*) fail closed
 * identically.
 *
 * Node side runs in-process (verifyBundle). Python side is spawned with --json.
 * No network, no ~/.occasio: a synthetic chain is built in os.tmpdir().
 */

const fs = require('fs'), os = require('os'), path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { buildBundle } = require('./src/bundle');
const { verifyBundle } = require('./src/bundle/verify');

const sha = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
let pass = 0, fail = 0;
const ok = (l, c, d = '') => { if (c) { console.log('  ✓ ' + l); pass++; } else { console.error('  ✗ ' + l + (d ? ' — ' + d : '')); fail++; } };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-xlang-'));
const chainFile = path.join(dir, 'pipeline-events.jsonl');
const polFile = path.join(dir, 'policy.yml');
const POLICY = 'block_secrets_in_tool_results: true\ndeny_paths:\n  - /etc/secret\n';
fs.writeFileSync(polFile, POLICY);
const POLHASH = sha(POLICY);
const RUN = '55555555-5555-5555-5555-555555555555';

let prev = '0'.repeat(64);
const row = r => { const wp = { ...r, prev_hash: prev }; const h = sha(JSON.stringify(wp)); fs.appendFileSync(chainFile, JSON.stringify({ ...wp, hash: h }) + '\n'); prev = h; };
const START = { is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: false, changed_files: [], untracked_files: [], diff_hash: null, digest: 'a'.repeat(40) };
const END = { is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: true, changed_files: ['src/app.js'], untracked_files: ['notes.md'], diff_hash: '2'.repeat(40), digest: 'b'.repeat(40) };
row({ audit_schema: 1, ts: '2026-05-12T10:00:00.000Z', run_id: RUN, agent: 'occasio', protocol: 'internal', direction: 'inbound', kind: 'policy_loaded', tool_name: 'policy_loaded', tool_inputs: { policy_hash: POLHASH, policy_path: polFile, version: 1 }, action: 'INFO', reason: 'policy-loaded', policy_source: 'user' });
row({ audit_schema: 1, ts: '2026-05-12T10:00:01.000Z', run_id: RUN, agent: 'occasio', protocol: 'internal', direction: 'inbound', kind: 'git_state', tool_name: 'git_state', tool_inputs: { phase: 'run_start', cwd: '/tmp', ...START }, action: 'INFO', reason: 'git-state' });
row({ audit_schema: 1, ts: '2026-05-12T10:00:05.000Z', run_id: RUN, agent: 'claude-code', protocol: 'anthropic-http', direction: 'outbound', kind: 'tool_call', tool_name: 'read_file', tool_inputs: { path: '/tmp/x' }, action: 'LOCAL', reason: 'native-handleable' });
row({ audit_schema: 1, ts: '2026-05-12T10:00:09.000Z', run_id: RUN, agent: 'occasio', protocol: 'internal', direction: 'inbound', kind: 'git_state', tool_name: 'git_state', tool_inputs: { phase: 'run_end', cwd: '/tmp', ...END }, action: 'INFO', reason: 'git-state' });

const base = buildBundle({ runId: RUN, logFile: chainFile, policyFile: polFile });

function recompute(b) {
  const a = sha(JSON.stringify(b.attestation)), s = sha(JSON.stringify(b.chain_slice));
  const t = b.policy_snapshot.text, p = (t == null) ? null : sha(t);
  b.manifest = { attestation_sha256: a, chain_slice_sha256: s, policy_sha256: p, bundle_digest: sha(JSON.stringify({ schema: 'occasio-bundle/v1', run_id: b.run_id, attestation_sha256: a, chain_slice_sha256: s, policy_sha256: p })) };
  return b;
}
const clone = () => JSON.parse(JSON.stringify(base));

// Each case: a bundle + the strict flags + the check expected to fail (or null).
const cases = [];
cases.push({ label: 'honest (lenient)', bundle: base, flags: [], expectFail: null });
cases.push({ label: 'honest --strict', bundle: base, flags: ['--strict'], expectFail: 'signature' });
{ const b = clone(); b.chain_slice[1].tool_inputs.head = '0'.repeat(40); recompute(b); cases.push({ label: 'tamper chain row', bundle: b, flags: [], expectFail: 'chain slice integrity' }); }
{ const b = clone(); b.policy_snapshot.text = 'block_secrets_in_tool_results: false\n'; recompute(b); cases.push({ label: 'swapped policy', bundle: b, flags: [], expectFail: 'policy binding' }); }
{ const b = clone(); b.attestation.subject.git_state.run_end.head = 'f'.repeat(40); recompute(b); cases.push({ label: 'forged git_state', bundle: b, flags: [], expectFail: 'git state matches chain' }); }
{ const b = clone(); b.manifest.attestation_sha256 = 'd'.repeat(64); cases.push({ label: 'edited manifest bytes', bundle: b, flags: [], expectFail: 'manifest integrity' }); }
{ const b = clone(); b.attestation.policy.source = 'inferred'; recompute(b); cases.push({ label: 'inferred --require-policy-binding', bundle: b, flags: ['--require-policy-binding'], expectFail: 'policy binding' }); }
{ const b = clone(); b.attestation.policy.source = 'inferred'; recompute(b); cases.push({ label: 'inferred (lenient)', bundle: b, flags: [], expectFail: null }); }

function ctxFromFlags(flags) {
  const has = f => flags.includes('--strict') || flags.includes(f);
  return {
    requireSignature:     has('--require-signature'),
    requirePolicyBinding: has('--require-policy-binding'),
    requireGitState:      has('--require-git-state'),
  };
}
function pyVerify(file, flags) {
  const r = spawnSync('python', ['docs/verify_bundle.py', '--json', ...flags, file], { encoding: 'utf8' });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* leave null */ }
  return { status: r.status, result: parsed, raw: (r.stdout + r.stderr).trim() };
}

(async () => {
  console.log('\nNode ↔ Python — evidence bundle verifier agreement');
  for (const c of cases) {
    const file = path.join(dir, c.label.replace(/[^a-z0-9]+/gi, '_') + '.json');
    fs.writeFileSync(file, JSON.stringify(c.bundle, null, 2));

    const nodeRes = await verifyBundle(file, ctxFromFlags(c.flags));
    const py = pyVerify(file, c.flags);

    if (!py.result) { ok(`${c.label}: python produced JSON`, false, py.raw); continue; }

    // 1. overall agreement
    ok(`${c.label}: overall ok agrees (node=${nodeRes.ok} python=${py.result.ok})`,
      nodeRes.ok === py.result.ok);

    // 2. expected outcome
    if (c.expectFail === null) {
      ok(`${c.label}: both pass`, nodeRes.ok === true && py.result.ok === true);
    } else {
      const nodeBad = nodeRes.checks.find(x => x.ok === false);
      const pyBad = py.result.checks.find(x => x.ok === false);
      ok(`${c.label}: both fail at "${c.expectFail}"`,
        nodeBad && pyBad && nodeBad.name === c.expectFail && pyBad.name === c.expectFail,
        `node=${nodeBad && nodeBad.name} python=${pyBad && pyBad.name}`);
    }

    // 3. the passing-check prefix is identical (same names, same order)
    const nNames = nodeRes.checks.map(x => x.name + ':' + (x.ok ? 1 : 0)).join(',');
    const pNames = py.result.checks.map(x => x.name + ':' + (x.ok ? 1 : 0)).join(',');
    ok(`${c.label}: check sequence is byte-identical`, nNames === pNames, `\n      node:   ${nNames}\n      python: ${pNames}`);
  }

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  console.log(`\n${fail === 0 ? '✓' : '✗'} bundle-xlang: ${pass} passed, ${fail} failed\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
