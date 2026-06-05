#!/usr/bin/env node
'use strict';

/**
 * test-identity-hook.js — the PreToolUse hook (second enforcement point).
 *
 * Covers: the proxy≡gate PARITY guard, `gate --enforce` (consume + audit), the
 * hook's fail-closed contract (verified-token no-op, forged-token → enforce,
 * any-error → deny), the full lifecycle through the hook, and merge-safe install.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'idhook-'));
process.env.OCCASIO_APPROVALS_FILE    = path.join(TMP, 'approvals.jsonl');
process.env.OCCASIO_APPROVAL_KEY_FILE = path.join(TMP, 'approval-key');
process.env.OCCASIO_IDENTITY_FILE     = path.join(TMP, 'identity.json');
process.env.OCCASIO_AUDIT_FILE        = path.join(TMP, 'pipeline-events.jsonl');

require('./src/adapters/claude-code');
const loader = require('./src/policy/loader');
const engine = require('./src/policy/engine');
const gate   = require('./src/cli/gate');
const hookInstall = require('./src/cli/hook-install');
const { getStore, commandHash } = require('./src/policy/identity-store');
const { makeBoundaryEvent } = require('./src/core/boundary-event');
const { verifyFile } = require('./src/audit/verifier');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') { if (cond) { console.log(`  ✓ ${label}`); passed++; } else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; } }
function quiet(fn) { const o = process.stdout.write, e = process.stderr.write; process.stdout.write = () => true; process.stderr.write = () => true; try { return fn(); } finally { process.stdout.write = o; process.stderr.write = e; } }

const strictParsed = loader.parse(fs.readFileSync(path.join(__dirname, 'policy-templates', 'strict-identity-gate.yml'), 'utf8'));
loader._setOverrideForTests(strictParsed);
const ev = (c) => makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code', protocol: 'anthropic-http', toolName: 'shell_bash', toolInput: { command: c } });

// spawn `occasio hook` with stdin JSON + env (the real PreToolUse path)
const HOOK_ENV = { ...process.env, OCCASIO_POLICY_FILE: path.join(__dirname, 'policy-templates', 'strict-identity-gate.yml'), OCCASIO_SESSION_FILE: path.join(TMP, 'session.json') };
function hook(input, extra) { return spawnSync('node', [path.join(__dirname, 'bin', 'occasio.js'), 'hook'], { input: JSON.stringify(input), env: { ...HOOK_ENV, ...extra }, encoding: 'utf8' }); }
function bash(cmd) { return { tool_name: 'Bash', tool_input: { command: cmd } }; }
function rows() { try { return fs.readFileSync(process.env.OCCASIO_AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); } catch { return []; } }

// ── 1. PARITY guard: proxy (evaluate) ≡ gate (gateShellCommand) ──────────────
console.log('\n1. proxy ≡ gate parity');
{
  const pol = loader.load();
  const battery = ['ssh azureuser@h', 'az vm run', 'sudo systemctl restart x', 'printenv', 'cat .env',
    'occasio approvals approve apr_x --once', 'python -m pytest', 'grep -ri secret /home', 'less .env'];
  for (const c of battery) {
    const a = engine.evaluate(ev(c));
    const b = engine.gateShellCommand(c, pol);
    const aBlocked = a.action === 'BLOCK', bBlocked = b.action === 'BLOCK';
    const sameVerdict = aBlocked === bBlocked && (!aBlocked || a.reason === b.reason);
    assert(`parity: ${c}`, sameVerdict, `evaluate=${a.action}/${a.reason} gate=${b.action}/${b.reason}`);
  }
}

// ── 2. gate --enforce ───────────────────────────────────────────────────────
console.log('\n2. gate --enforce');
{
  const store = getStore();
  assert('ssh --enforce no token → exit 3', quiet(() => gate.run(['ssh azureuser@e', '--enforce'])) === 3);
  assert('  identity_borrow_request enforcement_point=hook', rows().some(r => r.event_type === 'identity_borrow_request' && r.enforcement_point === 'hook'));
  const pend = store.list({ state: 'pending' }).find(r => r.command_hash === commandHash('ssh azureuser@e'));
  store.approve(pend.id, { approved_by: 'alice', identity_source: 'explicit' });
  assert('after approve, ssh --enforce → exit 0', quiet(() => gate.run(['ssh azureuser@e', '--enforce'])) === 0);
  assert('  token consumed', store.get(pend.id).state === 'consumed');
  assert('  identity_borrow_consumed enforcement_point=hook coverage=authorized', rows().some(r => r.event_type === 'identity_borrow_consumed' && r.enforcement_point === 'hook' && r.coverage === 'authorized'));
  assert('second ssh --enforce → exit 3 (single-use)', quiet(() => gate.run(['ssh azureuser@e', '--enforce'])) === 3);
  assert('printenv --enforce → exit 2', quiet(() => gate.run(['printenv', '--enforce'])) === 2);
  assert('occasio approvals approve --enforce → exit 2 (control_plane)', quiet(() => gate.run(['occasio approvals approve apr_x', '--enforce'])) === 2);
  assert('pytest --enforce → exit 0', quiet(() => gate.run(['python -m pytest', '--enforce'])) === 0);
  // preview unchanged: no consume, exit 3
  assert('preview ssh (no --enforce) → exit 3', quiet(() => gate.run(['ssh azureuser@preview'])) === 3);
}

// ── 3. hook contract (real stdin) ───────────────────────────────────────────
console.log('\n3. occasio hook contract');
{
  assert('Read tool → exit 0 (not ours)', hook({ tool_name: 'Read', tool_input: { file_path: 'x' } }).status === 0);
  const r = hook(bash('ssh azureuser@h'));
  assert('borrow, no proxy → exit 2 (block)', r.status === 2);
  assert('  approval message on stderr', /approv/i.test(r.stderr));
  assert('printenv → exit 2', hook(bash('printenv')).status === 2);
  assert('control-plane via hook → exit 2', hook(bash('occasio approvals approve apr_x')).status === 2);
  assert('benign pytest → exit 0', hook(bash('python -m pytest')).status === 0);
}

// ── 4. fail-closed: verified-token no-op vs forged token ────────────────────
console.log('\n4. proxy-detection (the security boundary)');
{
  fs.writeFileSync(path.join(TMP, 'session.json'), JSON.stringify({ proxy_session: 'REAL' }));
  assert('valid token (env==session) → exit 0 (no-op)', hook(bash('ssh azureuser@h'), { OCCASIO_PROXY_SESSION: 'REAL' }).status === 0);
  assert('forged env token (mismatch) → ENFORCE exit 2', hook(bash('ssh azureuser@h'), { OCCASIO_PROXY_SESSION: 'FORGED' }).status === 2);
  assert('env token, no session file → ENFORCE exit 2', hook(bash('ssh azureuser@h'), { OCCASIO_PROXY_SESSION: 'X', OCCASIO_SESSION_FILE: path.join(TMP, 'nope.json') }).status === 2);
  // any-error → deny: point the audit file at a directory so the audit append throws
  const auditDir = path.join(TMP, 'auditdir'); fs.mkdirSync(auditDir, { recursive: true });
  assert('hook internal error → exit 2 (fail-closed, never pass-through)', hook(bash('ssh azureuser@h'), { OCCASIO_AUDIT_FILE: auditDir }).status === 2);
}

// ── 5. lifecycle through the hook + chain ───────────────────────────────────
console.log('\n5. lifecycle through the hook');
{
  const store = getStore();
  const SSH = 'ssh lifecycle@host';
  hook(bash(SSH)); // block → pending
  const pend = store.list({ state: 'pending' }).find(r => r.command_hash === commandHash(SSH));
  assert('hook borrow created a pending', !!pend);
  store.approve(pend.id, { approved_by: 'alice', identity_source: 'explicit' }); // out-of-band human
  assert('after approve, hook ssh → exit 0', hook(bash(SSH)).status === 0);
  assert('token consumed', store.get(pend.id).state === 'consumed');
  assert('2nd hook ssh → exit 2 (single-use)', hook(bash(SSH)).status === 2);
  assert('chain verifies (Node)', verifyFile(process.env.OCCASIO_AUDIT_FILE).ok === true);
}

// ── 6. install merge-safe + idempotent ──────────────────────────────────────
console.log('\n6. hook install');
{
  const set = path.join(TMP, 'settings.json');
  fs.writeFileSync(set, JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'other' }] }] } }));
  process.env.OCCASIO_CLAUDE_SETTINGS = set;
  quiet(() => hookInstall.run());
  const j = JSON.parse(fs.readFileSync(set, 'utf8'));
  assert('install preserves existing key', j.model === 'x');
  assert('install preserves the existing hook + adds occasio', j.hooks.PreToolUse.length === 2 && j.hooks.PreToolUse.some(g => g.hooks.some(h => h.command === 'occasio hook')));
  assert('install is idempotent', hookInstall.hasOccasioHook(j) && (quiet(() => hookInstall.run()), JSON.parse(fs.readFileSync(set, 'utf8')).hooks.PreToolUse.length === 2));
  delete process.env.OCCASIO_CLAUDE_SETTINGS;
}

loader._setOverrideForTests(null);
console.log('\n' + '─'.repeat(40));
if (failed === 0) {
  console.log(`✓ All ${passed} identity-hook tests passed`);
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ }
} else {
  console.error(`✗ ${failed}/${passed + failed} identity-hook tests failed (artifacts: ${TMP})`);
}
process.exit(failed === 0 ? 0 : 1);
