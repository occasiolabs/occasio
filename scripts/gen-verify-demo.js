#!/usr/bin/env node
'use strict';

/**
 * gen-verify-demo.js — generate the SYNTHETIC demo fixture for web/verify/.
 *
 * Not shipped (scripts/ is excluded from package files[]). Rows are hand-built
 * with the REAL hashing primitive (computeHash) so the hashes are genuine and
 * the browser / Node / Python verifiers all agree — but every value is
 * fabricated and POSIX-clean: no real $HOME, OS user, git identity, hostname,
 * or live secret. Paths are /home/dev/demo-project/…; the only "secret" is a
 * denied path, never a live credential.
 *
 * Output:
 *   - web/verify/demo.js   window.OCCASIO_DEMO = { attestation, chainLines, sigstore }
 *   - prints a temp chain path for cross-verification.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const REPO = path.resolve(__dirname, '..');
const { computeHash, GENESIS } = require(path.join(REPO, 'src/audit/jsonl-auditor'));
const { gitStateDigest }       = require(path.join(REPO, 'src/git/state'));
const { buildAttestation }     = require(path.join(REPO, 'src/attest'));
const { buildInTotoStatement } = require(path.join(REPO, 'src/attest/sign'));
const { canonicalize }         = require(path.join(REPO, 'src/attest/canonicalize'));

const RUN  = '11111111-2222-4333-8444-555555555555';      // fabricated
const HEAD = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0';  // fabricated 40-hex
const CWD  = '/home/dev/demo-project';                     // synthetic, POSIX, no real $HOME

// Hand-build a GENESIS-rooted chain with genuine computeHash hashes + POSIX paths.
let prev = GENESIS;
const lines = [];
function append(row) {
  const full = { ...row, prev_hash: prev };
  full.hash = computeHash(full);                            // sha256(JSON.stringify(full-without-hash))
  lines.push(JSON.stringify(full));
  prev = full.hash;
}
function gitState(phase, state, ts, id) {
  append({ audit_schema: 1, ts, event_id: id, session_id: RUN, run_id: RUN, agent: 'occasio',
    protocol: 'internal', direction: 'inbound', kind: 'git_state', tool_name: 'git_state',
    tool_inputs: { phase, cwd: CWD, is_repo: true, head: state.head, branch: 'main', dirty: state.dirty,
      changed_files: state.changed_files, untracked_files: [], diff_hash: state.diff_hash, digest: gitStateDigest({ is_repo: true, ...state }) },
    action: 'INFO', reason: 'git-state' });
}
function toolCall(toolName, toolInput, action, reason, ts, id, resultKind) {
  append({ audit_schema: 1, ts, event_id: id, session_id: RUN, run_id: RUN, agent: 'claude-code',
    protocol: 'anthropic-http', direction: 'outbound', kind: 'tool_call', tool_name: toolName,
    tool_inputs: toolInput, action, reason, policy_source: action === 'BLOCK' ? 'user' : 'default',
    result_kind: resultKind });
}

const START = { head: HEAD, branch: 'main', dirty: false, changed_files: [], untracked_files: [], diff_hash: null };
const END   = { head: HEAD, branch: 'main', dirty: true, changed_files: ['src/app.js'], untracked_files: [], diff_hash: 'f00dcafe'.repeat(8) };
gitState('run_start', START, '2026-01-15T09:00:00.000Z', '0a000000-0000-4000-8000-000000000001');
toolCall('read_file', { path: '/home/dev/demo-project/src/app.js' }, 'LOCAL', 'native-handleable', '2026-01-15T09:00:01.000Z', '0a000000-0000-4000-8000-000000000002', 'local');
toolCall('read_file', { path: '/home/dev/demo-project/.env' },       'BLOCK', 'path-denied',       '2026-01-15T09:00:03.000Z', '0a000000-0000-4000-8000-000000000003', 'block');
gitState('run_end', END, '2026-01-15T09:00:05.000Z', '0a000000-0000-4000-8000-000000000004');

// Write the chain to a temp file, build the attestation from it, then sanitize
// the two metadata fields that buildAttestation fills with the real local path.
const dir   = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-verify-demo-'));
const chain = path.join(dir, 'pipeline-events.jsonl');
const pol   = path.join(dir, 'policy.yml');
fs.writeFileSync(chain, lines.join('\n') + '\n');
fs.writeFileSync(pol, 'version: 1\nblock_secrets_in_tool_results: true\ndeny_paths:\n  - /home/dev/demo-project/.env\n');

const attestation = buildAttestation({ runId: RUN, logFile: chain, policyFile: pol });
attestation.audit_chain.chain_file = '/home/dev/demo-project/.occasio/pipeline-events.jsonl';   // sanitize real path
attestation.policy.file_path        = '/home/dev/demo-project/.occasio/policy.yml';              // sanitize real path
attestation.signature = {
  type: 'sigstore-cosign-keyless',
  identity: 'repo:occasiolabs/occasio-demo:ref:refs/heads/main  (synthetic demo — not a real signature)',
  rekor_entry: null,
  signed_at: '2026-01-15T09:00:05.000Z',
  envelope_sha256: '0'.repeat(64),
};

// Sidecar whose DSSE payload IS this attestation's in-toto statement → the
// browser's predicate-equivalence check passes for real.
const statement  = buildInTotoStatement(attestation);
const payloadB64 = Buffer.from(canonicalize(statement), 'utf8').toString('base64');
const sigstore = {
  mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
  verificationMaterial: { tlogEntries: [{ logIndex: '0' }] },
  dsseEnvelope: { payload: payloadB64, payloadType: 'application/vnd.in-toto+json' },
};

const out = path.join(REPO, 'web', 'verify', 'demo.js');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out,
  '/* AUTO-GENERATED by scripts/gen-verify-demo.js — synthetic, POSIX-clean demo data:\n' +
  '   no real paths, identities, or secrets. Hashes are genuine (real computeHash) so the\n' +
  '   browser, `occasio audit verify`, and docs/audit_walker.py all agree.\n' +
  '   Regenerate: node scripts/gen-verify-demo.js */\n' +
  'window.OCCASIO_DEMO = ' + JSON.stringify({ attestation, chainLines: lines, sigstore }, null, 2) + ';\n',
  'utf8');

console.log('wrote ' + out);
console.log('demo chain (for cross-verify): ' + chain);
