#!/usr/bin/env node
'use strict';

/**
 * scripts/demo-release.js — runnable proof of the v0.11.0 evidence + policy +
 * scanner/preflight workflow. Builds a throwaway policy + fixture chain, then
 * drives the real `occasio` CLI and ASSERTS the exit codes, including the
 * headline beat: a tampered evidence bundle fails verification.
 *
 * Not shipped (lives in scripts/, excluded from package files[]). Run with:
 *   node scripts/demo-release.js   →   exit 0 iff every step behaves as claimed.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.resolve(__dirname, '..');
const BIN  = path.join(REPO, 'bin', 'occasio.js');
const { createAuditor }     = require('../src/audit/jsonl-auditor');
const { computePolicyHash } = require('../src/policy/loader');

const c = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };

let pass = 0, fail = 0;
function check(label, ok, detail = '') {
  if (ok) { console.log(`  ${c.g('✓')} ${label}`); pass++; }
  else { console.log(`  ${c.r('✗')} ${label}${detail ? c.d('  ' + detail) : ''}`); fail++; }
}

function occ(args, extraEnv) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    cwd: REPO, encoding: 'utf8', timeout: 60000,
    env: Object.assign({}, process.env, extraEnv || {}),
  });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-demo-'));
try {
  const pol    = path.join(dir, 'policy.yml');
  const pol2   = path.join(dir, 'policy-edited.yml');
  const lock   = path.join(dir, 'policy.lock.json');
  const bundle = path.join(dir, 'run.occasio.json');
  const leak   = path.join(dir, 'leak.txt');
  const chain  = path.join(dir, 'pipeline-events.jsonl');
  const RUN    = 'aaaaaaaa-1111-2222-3333-444444444444';

  // Cross-feature policy: deny_paths + limits + entropy_secret_detection together.
  fs.writeFileSync(pol,
    'version: 1\n' +
    'block_secrets_in_tool_results: true\n' +
    'entropy_secret_detection: true\n' +
    'deny_paths:\n  - ~/.ssh\n' +
    'limits:\n  max_tool_calls_per_round: 50\n');

  // Fixture chain: git_state(run_start) → read_file BLOCK(path-denied) → limit_exceeded → git_state(run_end)
  const a = createAuditor(chain, { lock: false });
  a.recordGitState({ phase: 'run_start', runId: RUN, sessionId: RUN, cwd: dir,
    state: { is_repo: true, head: 'a'.repeat(40), branch: 'main', dirty: false, changed_files: [], untracked_files: [], diff_hash: null } });
  const denyId = crypto.randomUUID();
  a.record(
    { timestamp: '2026-06-01T10:00:01.000Z', id: denyId, sessionId: RUN, runId: RUN, agent: 'claude-code',
      protocol: 'anthropic-http', direction: 'outbound', kind: 'tool_call', toolName: 'read_file', toolInput: { file_path: '~/.ssh/id_rsa' } },
    { action: 'BLOCK', reason: 'path-denied', policySource: 'user' }, { blocked: true });
  a.recordLimitExceeded({ runId: RUN, sessionId: RUN, kind: 'max_tool_calls_per_round', max: 50, actual: 120, round: 1 });
  a.recordGitState({ phase: 'run_end', runId: RUN, sessionId: RUN, cwd: dir,
    state: { is_repo: true, head: 'a'.repeat(40), branch: 'main', dirty: true, changed_files: ['src/x.js'], untracked_files: [], diff_hash: 'b'.repeat(64) } });
  const limitId = fs.readFileSync(chain, 'utf8').split('\n').filter(Boolean).map(JSON.parse).find(r => r.kind === 'limit_exceeded').event_id;

  const polEnv = { OCCASIO_POLICY_FILE: pol };
  const chainEnv = { OCCASIO_AUDIT_FILE: chain, OCCASIO_POLICY_FILE: pol };

  console.log(c.b('\n⚡ Occasio v0.11.0 — evidence + policy + scanner/preflight demo\n'));

  console.log(c.b('Policy: lock + drift'));
  check('audit verify (chain w/ git_state + limit_exceeded) → intact', occ(['audit', 'verify', '--file', chain]).code === 0);
  check('policy validate (deny_paths + limits + entropy) → 0', occ(['policy', 'validate', '--file', pol]).code === 0);
  check('policy lock --out → 0', occ(['policy', 'lock', '--file', pol, '--out', lock]).code === 0);
  check('policy diff (unchanged) → 0', occ(['policy', 'diff', '--file', pol, '--since', lock]).code === 0);

  console.log(c.b('\nScanner + preflight'));
  const ghp = 'ghp_' + 'd'.repeat(36);
  fs.writeFileSync(leak, 'token ' + ghp + '\n');
  const scan = occ(['scan', '--file', leak]);
  check('scan (secret present) → exit 1', scan.code === 1);
  check('scan never prints the plaintext secret', !scan.out.includes(ghp));
  check('preflight simulate --strict (blocked read) → exit 1', occ(['preflight', 'simulate', '--read', '~/.ssh/id_rsa', '--read', '/tmp/ok', '--strict'], polEnv).code === 1);

  console.log(c.b('\nEvidence: bundle + verify + tamper'));
  check('bundle --run → 0', occ(['bundle', '--run', RUN, '--log', chain, '--policy', pol, '--out', bundle]).code === 0);
  check('verify (honest bundle) → 0', occ(['verify', bundle]).code === 0);
  fs.writeFileSync(bundle, fs.readFileSync(bundle, 'utf8').replace('src/x.js', 'src/EVIL.js'));
  check('verify (tampered bundle) → exit ≠ 0', occ(['verify', bundle]).code !== 0);

  console.log(c.b('\nDrift gates'));
  fs.writeFileSync(pol2,
    'version: 1\nblock_secrets_in_tool_results: false\ndeny_paths:\n  - ~/.ssh\n  - /etc/secret\nlimits:\n  max_tool_calls_per_round: 10\n');
  check('policy diff (drifted policy) → exit 1', occ(['policy', 'diff', '--file', pol2, '--since', lock]).code === 1);
  check('policy lock --verify --against (drifted) → exit 1', occ(['policy', 'lock', '--verify', lock, '--against', pol2]).code === 1);

  console.log(c.b('\nExplain'));
  const exD = occ(['explain', denyId], chainEnv);
  check('explain deny_paths block → names deny_paths[0]', exD.code === 0 && exD.out.includes('deny_paths[0]'));
  const exL = occ(['explain', limitId], chainEnv);
  check('explain limit_exceeded → names the limit + max/actual', exL.code === 0 && exL.out.includes('limits.max_tool_calls_per_round') && /max 50/.test(exL.out) && /actual 120/.test(exL.out));

  console.log('\n' + (fail === 0 ? c.g(`✓ demo: ${pass} steps passed`) : c.r(`✗ demo: ${pass} passed, ${fail} failed`)) + '\n');
} finally {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

process.exit(fail === 0 ? 0 : 1);
