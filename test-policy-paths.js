#!/usr/bin/env node
'use strict';

/**
 * test-policy-paths.js — H4 from the 2026-05-15 code review.
 *
 * Covers path enforcement in src/policy/engine.js and the shell-mediated read
 * detector in src/policy/shell-path.js:
 *   - deny_paths / allow_paths against typed Read / Glob / Grep tools
 *   - Windows-vs-Linux case normalization
 *   - Symlink resolution via realpath
 *   - Compound shell chains: `cd … && cat …`, `Set-Location …; Get-Content …`
 *   - Prefix-match safety (denying ~/.aws must not also deny ~/.awskeys)
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { makeBoundaryEvent } = require('./src/core/boundary-event');
const policy                = require('./src/policy/engine');
const loader                = require('./src/policy/loader');
const { extractShellReadPaths } = require('./src/policy/shell-path');
require('./src/adapters/claude-code');   // ensure agent → canonical tool map is registered

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

const IS_WIN = process.platform === 'win32';

function mkTmpDir() {
  const d = path.join(os.tmpdir(), `occasio-policy-paths-${process.pid}-${Math.random().toString(36).slice(2)}`);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function readEv(filePath) {
  return makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http',
    toolName: 'read_file', toolInput: { file_path: filePath },
  });
}

function bashEv(command) {
  return makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http',
    toolName: 'shell_bash', toolInput: { command },
  });
}

function psEv(command) {
  return makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http',
    toolName: 'shell_powershell', toolInput: { command },
  });
}

function withPolicy(p, fn) {
  loader._setOverrideForTests(p);
  try { fn(); } finally { loader._resetCache(); }
}

// ── 1. deny_paths against typed read_file ────────────────────────────────────
console.log('\n1. deny_paths blocks read_file');
{
  const dir   = mkTmpDir();
  const secret = path.join(dir, 'secret.txt');
  fs.writeFileSync(secret, 'shhh');
  withPolicy({ deny_paths: [dir], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
    const d = policy.evaluate(readEv(secret));
    assert('exact deny_paths match → BLOCK',         d.action === 'BLOCK');
    assert('reason is path-denied',                  d.reason === 'path-denied');
  });
  withPolicy({ deny_paths: [dir + path.sep + 'sub'], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
    const d = policy.evaluate(readEv(secret));
    assert('non-matching deny_paths → LOCAL',        d.action === 'LOCAL');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 2. prefix safety: deny ~/.aws does not deny ~/.awskeys ───────────────────
console.log('\n2. prefix-match safety');
{
  const base = mkTmpDir();
  const a = path.join(base, '.aws');
  const b = path.join(base, '.awskeys');
  fs.mkdirSync(a); fs.mkdirSync(b);
  fs.writeFileSync(path.join(a, 'credentials'), 'x');
  fs.writeFileSync(path.join(b, 'data'),        'y');
  withPolicy({ deny_paths: [a], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
    assert('inside ~/.aws → BLOCK',
      policy.evaluate(readEv(path.join(a, 'credentials'))).action === 'BLOCK');
    assert('sibling ~/.awskeys NOT blocked by ~/.aws',
      policy.evaluate(readEv(path.join(b, 'data'))).action !== 'BLOCK');
  });
  fs.rmSync(base, { recursive: true, force: true });
}

// ── 3. allow_paths is a positive list ────────────────────────────────────────
console.log('\n3. allow_paths whitelist');
{
  const base   = mkTmpDir();
  const sub    = path.join(base, 'ok');
  const sneaky = path.join(base, 'nope');
  fs.mkdirSync(sub); fs.mkdirSync(sneaky);
  fs.writeFileSync(path.join(sub, 'a.txt'), 'a');
  fs.writeFileSync(path.join(sneaky, 'b.txt'), 'b');
  withPolicy({ allow_paths: [sub], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
    assert('inside allow_paths → LOCAL',
      policy.evaluate(readEv(path.join(sub, 'a.txt'))).action === 'LOCAL');
    const d = policy.evaluate(readEv(path.join(sneaky, 'b.txt')));
    assert('outside allow_paths → BLOCK',                d.action === 'BLOCK');
    assert('reason path-not-allowed',                    d.reason === 'path-not-allowed');
  });
  fs.rmSync(base, { recursive: true, force: true });
}

// ── 4. Windows case-insensitivity (only on win32) ────────────────────────────
console.log('\n4. case sensitivity matches platform');
{
  const base = mkTmpDir();
  const real = path.join(base, 'Secrets');
  fs.mkdirSync(real);
  const file = path.join(real, 'pw.txt');
  fs.writeFileSync(file, 'x');
  withPolicy({ deny_paths: [real.toLowerCase()], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
    const d = policy.evaluate(readEv(file));
    if (IS_WIN) {
      assert('Windows: case-insensitive deny match → BLOCK', d.action === 'BLOCK');
    } else {
      assert('POSIX: case-sensitive deny mismatch → LOCAL',  d.action !== 'BLOCK');
    }
  });
  fs.rmSync(base, { recursive: true, force: true });
}

// ── 5. realpath / symlink resolution ─────────────────────────────────────────
console.log('\n5. symlink resolves to real path');
{
  const base = mkTmpDir();
  const real = path.join(base, 'real');
  const link = path.join(base, 'shortcut');
  fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, 's.txt'), 'x');
  let linkOk = true;
  try { fs.symlinkSync(real, link, 'dir'); }
  catch (e) {
    // On Windows, symlinkSync needs Developer Mode or admin. Skip gracefully.
    if (IS_WIN && /EPERM|UNKNOWN/.test(e.message)) { linkOk = false; }
    else throw e;
  }
  if (linkOk) {
    withPolicy({ deny_paths: [real], tools: { read_file: { action: 'LOCAL', executor: 'native' } } }, () => {
      const d = policy.evaluate(readEv(path.join(link, 's.txt')));
      assert('symlinked access still blocked (deny on realpath)', d.action === 'BLOCK');
    });
  } else {
    console.log('  ⊘ symlink test skipped (Windows without Developer Mode)');
  }
  fs.rmSync(base, { recursive: true, force: true });
}

// ── 6. shell-mediated read: `cat <denied>` blocked ───────────────────────────
console.log('\n6. shell-mediated read enforcement');
{
  const dir = mkTmpDir();
  const secret = path.join(dir, 'secret.txt');
  fs.writeFileSync(secret, 'x');
  withPolicy({
    deny_paths: [dir],
    tools: { shell_bash: { action: 'LOCAL', executor: 'native', classifier: 'bash-allowlist' } },
  }, () => {
    const d = policy.evaluate(bashEv(`cat ${secret}`));
    assert('Bash cat <denied> → BLOCK',     d.action === 'BLOCK');
    assert('reason is path-denied',          d.reason === 'path-denied');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 7. compound chain: `cd <dir> && cat <denied-relative>` ───────────────────
console.log('\n7. compound chain — cd + cat');
{
  const dir = mkTmpDir();
  const secret = path.join(dir, 's.txt');
  fs.writeFileSync(secret, 'x');
  withPolicy({
    deny_paths: [dir],
    tools: { shell_bash: { action: 'LOCAL', executor: 'native', classifier: 'bash-allowlist' } },
  }, () => {
    const d = policy.evaluate(bashEv(`cd ${dir} && cat s.txt`));
    assert('cd <dir> && cat <relative> → BLOCK',  d.action === 'BLOCK');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 8. PowerShell Set-Location + Get-Content ─────────────────────────────────
console.log('\n8. PowerShell Set-Location chain');
{
  const dir = mkTmpDir();
  const secret = path.join(dir, 's.txt');
  fs.writeFileSync(secret, 'x');
  withPolicy({
    deny_paths: [dir],
    tools: { shell_powershell: { action: 'LOCAL', executor: 'native', classifier: 'powershell-allowlist' } },
  }, () => {
    const d = policy.evaluate(psEv(`Set-Location ${dir}; Get-Content s.txt`));
    assert('Set-Location <dir>; Get-Content <relative> → BLOCK', d.action === 'BLOCK');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 9. extractShellReadPaths — direct unit tests ─────────────────────────────
console.log('\n9. extractShellReadPaths direct tests');
{
  const dir = mkTmpDir();
  const abs = path.resolve(dir, 'x.txt');
  assert('bare cat <abs>', extractShellReadPaths(`cat ${abs}`).includes(abs));
  assert('cd && cat resolves relative to cwd',
    extractShellReadPaths(`cd ${dir} && cat x.txt`).includes(abs));
  assert('Set-Location; Get-Content resolves relative',
    extractShellReadPaths(`Set-Location ${dir}; Get-Content x.txt`).includes(abs));
  assert('Get-Content -Path resolves',
    extractShellReadPaths(`cd ${dir} && Get-Content -Path x.txt`).includes(abs));
  assert('head -n 5 file resolves',
    extractShellReadPaths(`cd ${dir} && head -n 5 x.txt`).includes(abs));
  assert('unknown command returns empty',
    extractShellReadPaths(`some-random-command ${abs}`).length === 0);
  assert('non-string returns empty',
    extractShellReadPaths(null).length === 0);
  // Deduplication: same path read twice yields one entry.
  const dups = extractShellReadPaths(`cat ${abs} && cat ${abs}`);
  assert('duplicate paths deduplicated', dups.length === 1);
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 10. shell read where no deny_paths exist → no extra block ────────────────
console.log('\n10. no deny_paths/allow_paths → shell read passes path check');
{
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'a.txt'), 'x');
  withPolicy({
    tools: { shell_bash: { action: 'LOCAL', executor: 'native', classifier: 'bash-allowlist' } },
  }, () => {
    const d = policy.evaluate(bashEv(`cat ${path.join(dir, 'a.txt')}`));
    assert('no path policy → LOCAL', d.action === 'LOCAL');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 11. tilde expansion in input path ────────────────────────────────────────
console.log('\n11. tilde-prefixed paths expand to homedir');
{
  // We can't safely write into the user's homedir, so use a fake homedir-relative
  // path that won't exist; the resolver still expands and we can check the policy
  // decision against an absolute path inside homedir.
  const homeRelative = '~/.occasio-test-imaginary/x';
  const expanded = path.resolve(os.homedir() + '/.occasio-test-imaginary/x');
  withPolicy({
    deny_paths: [os.homedir() + path.sep + '.occasio-test-imaginary'],
    tools: { read_file: { action: 'LOCAL', executor: 'native' } },
  }, () => {
    const d = policy.evaluate(readEv(homeRelative));
    assert('~-prefixed path expands and matches deny_paths', d.action === 'BLOCK',
      `expanded=${expanded}, got action=${d.action}`);
  });
}

// ── 12. find_files / grep path enforcement ───────────────────────────────────
console.log('\n12. find_files + grep path enforcement');
{
  const dir = mkTmpDir();
  withPolicy({ deny_paths: [dir], tools: {
    find_files: { action: 'LOCAL', executor: 'native' },
    grep:       { action: 'LOCAL', executor: 'native' },
  } }, () => {
    const findEv = makeBoundaryEvent({
      direction: 'inbound', kind: 'tool_call', agent: 'claude-code', protocol: 'anthropic-http',
      toolName: 'find_files', toolInput: { path: dir, pattern: '*.txt' },
    });
    assert('find_files inside deny_paths → BLOCK', policy.evaluate(findEv).action === 'BLOCK');
    const grepEv = makeBoundaryEvent({
      direction: 'inbound', kind: 'tool_call', agent: 'claude-code', protocol: 'anthropic-http',
      toolName: 'grep', toolInput: { path: dir, pattern: 'TODO' },
    });
    assert('grep inside deny_paths → BLOCK', policy.evaluate(grepEv).action === 'BLOCK');
  });
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(40)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`✓ All ${total} policy-path tests passed\n`);
  process.exit(0);
} else {
  console.error(`✗ ${failed}/${total} policy-path tests failed\n`);
  process.exit(1);
}
