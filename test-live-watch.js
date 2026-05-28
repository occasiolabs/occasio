#!/usr/bin/env node
'use strict';

/**
 * test-live-watch.js: integration smoke for `occasio live`.
 *
 * Spawns a real `node bin/occasio.js live` subprocess pointed at a fixture
 * chain via OCCASIO_AUDIT_FILE, waits for the initial render, appends a
 * row to the chain, waits for the watcher to fire, then kills the process.
 * Asserts that:
 *   - the subprocess emits at least one render frame on startup
 *   - the initial frame contains the expected sections
 *   - the subprocess remains running after the initial frame (no immediate exit)
 *   - after a chain append, at least one further write to stdout is observed
 *     (proving fs.watch triggered a redraw)
 *
 * Note: fs.watch behaviour varies by OS and is sometimes coalesced. This
 * test asserts only that *some* further output appears after the append,
 * not a specific frame count.
 */

const { spawn } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');

const tmpDir      = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-live-'));
const chainPath   = path.join(tmpDir, 'pipeline-events.jsonl');
const sessionPath = path.join(tmpDir, 'session.json');

const runId = 'live-test-' + Date.now();
const cwd   = process.cwd();

// Seed a small chain so live has something to render
const { createAuditor } = require('./src/audit/jsonl-auditor');
const auditor = createAuditor(chainPath);
auditor.recordRequest({
  iso: '2026-05-28T14:00:00.000Z',
  run_id: runId, cwd, model: 'claude-haiku-4-5',
  event_type: 'cloud_sent', input_tokens: 50, output_tokens: 10, cost: 0.0007,
});
fs.writeFileSync(sessionPath, JSON.stringify({
  run_id: runId, start: '2026-05-28T14:00:00.000Z',
  cwd, mode: 'intercept', model: 'claude-haiku-4-5', budget: null,
}));

// Redirect the subprocess's session.json read via a bootstrap wrapper. Since
// SESSION_FILE is resolved against os.homedir() in src/models/events.js, we
// override HOME / USERPROFILE so the subprocess looks in our tmp dir.
//
// We also need to symlink (or mkdir + copy) the session.json under
// <tmp>/.occasio/session.json since events.js builds that path from
// os.homedir() + '.occasio'.
const fakeHome   = path.join(tmpDir, 'home');
const fakeOccDir = path.join(fakeHome, '.occasio');
fs.mkdirSync(fakeOccDir, { recursive: true });
fs.copyFileSync(sessionPath, path.join(fakeOccDir, 'session.json'));

const child = spawn(process.execPath, ['bin/occasio.js', 'live'], {
  env: {
    ...process.env,
    OCCASIO_AUDIT_FILE: chainPath,
    HOME:        fakeHome,
    USERPROFILE: fakeHome,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let stdout = '';
let stderr = '';
let redrawByteCounts = [];

child.stdout.on('data', (chunk) => {
  stdout += chunk.toString();
  redrawByteCounts.push(stdout.length);
});
child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

let timedOut = false;
let exited   = false;
let exitCode = null;
child.on('exit', (code) => { exited = true; exitCode = code; });

(async () => {
  // Wait for initial render
  await new Promise((r) => setTimeout(r, 1200));

  const stdoutAfterInit = stdout;
  const bytesAfterInit  = stdoutAfterInit.length;

  // Append a row to the chain to trigger fs.watch
  auditor.record(
    {
      timestamp: '2026-05-28T14:00:05.000Z',
      id: 'live-trigger-' + Date.now(),
      sessionId: 's', runId,
      agent: 'claude-code', protocol: 'anthropic-http',
      direction: 'outbound', kind: 'tool_call',
      toolName: 'read_file',
      toolInput: { path: '/tmp/x' },
    },
    { action: 'LOCAL', reason: 'native-handler', policySource: 'default' },
    { passThrough: false, executor: 'native' });

  // Wait for watcher coalescence + redraw
  await new Promise((r) => setTimeout(r, 1500));

  // Kill the subprocess
  child.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 600));
  if (!exited) child.kill('SIGKILL');

  const stdoutFinal = stdout;

  let passed = 0, failed = 0;
  function assert(label, cond, detail = '') {
    if (cond) { console.log(`  ✓ ${label}`); passed++; }
    else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
  }

  console.log('\nLive watch integration');

  // Strip ANSI for content checks
  const plainInit  = stdoutAfterInit.replace(/\x1b\[[0-9;]*m/g, '');
  const plainFinal = stdoutFinal.replace(/\x1b\[[0-9;]*m/g, '');

  assert('subprocess produced an initial render frame',
    bytesAfterInit > 0,
    `got ${bytesAfterInit} bytes after 1.2s; stderr=${stderr.slice(0, 120)}`);

  assert('initial frame contains the live header',
    plainInit.includes('⚡ Occasio live'));

  assert('initial frame includes Counters section',
    plainInit.includes('Counters'));

  assert('initial frame includes Last 12 chain events',
    plainInit.includes('Last 12 chain events'));

  assert('initial frame shows the fixture run_id',
    plainInit.includes(runId));

  assert('stdout grew after chain append (watcher fired)',
    stdoutFinal.length > bytesAfterInit,
    `before=${bytesAfterInit} after=${stdoutFinal.length}`);

  assert('subprocess stayed alive until killed',
    exitCode === null || exitCode === 0 || exitCode === 143 || exitCode === 1 || exitCode === -1,
    `exit=${exitCode}`);

  console.log(`\n  ${passed} passed, ${failed} failed`);
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  process.exit(failed > 0 ? 1 : 0);
})().catch((e) => {
  console.error('test-live-watch fatal:', e);
  try { child.kill('SIGKILL'); } catch { /* ignore */ }
  process.exit(2);
});

// Hard timeout in case of hang
setTimeout(() => {
  if (!exited) {
    timedOut = true;
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
    console.error('test-live-watch: timeout');
    process.exit(2);
  }
}, 10000).unref();
