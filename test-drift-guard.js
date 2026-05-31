#!/usr/bin/env node
'use strict';

/**
 * test-drift-guard.js — locks in the truth-source invariant.
 *
 * Phase-4 of the architecture refactor unified status/ledger/replay/report
 * to read from the hash-chained audit log via src/models/events.js. This
 * test ensures the unification stays unified.
 *
 * What it does:
 *   1. Builds a deterministic fixture chain with 5 kind:"request" rows.
 *   2. Points the active session at it via session.json.
 *   3. Invokes status / ledger --summary / replay CLIs in-process.
 *   4. Scrapes counters out of their stdout.
 *   5. Asserts equality across surfaces AND match against the fixture.
 *
 * If this test fails, the most likely cause is that someone re-introduced
 * a second source of truth (logs/*.jsonl or session.json counters) for
 * cost/tokens, which is the exact drift this refactor eliminated. Fix the
 * regression, don't fix the test.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

// ── Scratch wiring (must happen before any occasio module is required) ──────
//
// CHAIN_FILE in src/models/events.js resolves at module-load via
// OCCASIO_AUDIT_FILE env var, so setting it here points all readers at our
// fixture. SESSION_FILE has no equivalent env hook (today) — we redirect it
// via a narrow monkey-patch on fs.readFileSync below.

const tmpDir       = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-drift-'));
const chainPath    = path.join(tmpDir, 'pipeline-events.jsonl');
const sessionPath  = path.join(tmpDir, 'session.json');
process.env.OCCASIO_AUDIT_FILE = chainPath;

// Narrow redirect: any read whose path ends in "session.json" goes to our
// scratch session file. Real reads (chain, package.json, etc.) pass through.
const realRead = fs.readFileSync;
fs.readFileSync = function(p, ...rest) {
  if (typeof p === 'string' && p.endsWith('session.json')) {
    return realRead(sessionPath, ...rest);
  }
  return realRead(p, ...rest);
};

// ── Build the fixture ─────────────────────────────────────────────────────

const { createAuditor } = require('./src/audit/jsonl-auditor');
const auditor = createAuditor(chainPath);

const runId = 'drift-guard-run-' + Date.now();
const cwd   = process.cwd();

// Fixture rows MUST be dated today: the replay surface defaults to a
// `today: true` view (src/replay.js → loadEvents), so a hardcoded date
// makes this guard fail every day after it. Date the fixture dynamically.
const _d  = new Date();
const ymd = `${_d.getFullYear()}-${String(_d.getMonth() + 1).padStart(2, '0')}-${String(_d.getDate()).padStart(2, '0')}`;

// Five rows: three cloud_sent, one local_only (zero cost), one blocked.
// Costs chosen so the sum is a clean four-decimal number that survives
// status.js's toFixed(4) display.
const fixtures = [
  { event_type: 'cloud_sent', input_tokens: 100, output_tokens: 10, cost: 0.0010, cache_savings: 0.0005 },
  { event_type: 'cloud_sent', input_tokens: 200, output_tokens: 20, cost: 0.0020, cache_savings: 0.0000 },
  { event_type: 'local_only', input_tokens:   0, output_tokens:  0, cost: 0.0000, tools_local_count: 1 },
  { event_type: 'cloud_sent', input_tokens: 300, output_tokens: 30, cost: 0.0030, cache_savings: 0.0000 },
  { event_type: 'blocked',    input_tokens:   0, output_tokens:  0, cost: 0.0000 },
];

for (let i = 0; i < fixtures.length; i++) {
  const f = fixtures[i];
  const r = auditor.recordRequest({
    iso:   `${ymd}T12:0${i}:00.000Z`,
    run_id: runId,
    cwd,
    model:  'claude-haiku-4-5',
    ...f,
  });
  if (!r.ok) { console.error('fixture write failed:', r.error?.message); process.exit(2); }
}

// session.json pointer — what currentRunId() reads
fs.writeFileSync(sessionPath, JSON.stringify({
  run_id: runId,
  start:  `${ymd}T12:00:00.000Z`,
  cwd,
  mode:   'intercept',
  budget: null,
}));

// ── Expected values from the fixture ──────────────────────────────────────

const expected = {
  requests:      fixtures.length,
  cloud_sent:    fixtures.filter(f => f.event_type === 'cloud_sent').length,
  local_only:    fixtures.filter(f => f.event_type === 'local_only').length,
  blocked:       fixtures.filter(f => f.event_type === 'blocked').length,
  cost:          fixtures.reduce((s, f) => s + (f.cost || 0), 0),
  input_tokens:  fixtures.reduce((s, f) => s + (f.input_tokens || 0), 0),
  output_tokens: fixtures.reduce((s, f) => s + (f.output_tokens || 0), 0),
};

// ── Capture each CLI's output ─────────────────────────────────────────────

function captureStdout(fn) {
  const realStdoutWrite = process.stdout.write.bind(process.stdout);
  const realLog         = console.log;
  let buf = '';
  process.stdout.write = (chunk) => { buf += chunk; return true; };
  console.log = (...args) => {
    buf += args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\n';
  };
  try { fn(); }
  finally {
    process.stdout.write = realStdoutWrite;
    console.log = realLog;
  }
  // Strip ANSI escapes for clean regex matching
  return buf.replace(/\x1b\[[0-9;]*m/g, '');
}

const statusOut = captureStdout(() => require('./src/cli/status').run());
const ledgerOut = captureStdout(() => require('./src/ledger').runLedgerCli(['--summary', '--scope', 'session']));
const replayOut = captureStdout(() => require('./src/replay').runReplayCli(['--last', '10']));

// ── Parse counters ────────────────────────────────────────────────────────

function pickInt(text, re) {
  const m = text.match(re);
  return m ? parseInt(m[1], 10) : null;
}
function pickFloat(text, re) {
  const m = text.match(re);
  return m ? parseFloat(m[1]) : null;
}

const status = {
  requests: pickInt(statusOut,   /Requests:\s+(\d+)/),
  cost:     pickFloat(statusOut, /Cost:\s+\$([\d.]+)/),
};
const ledger = {
  requests:  pickInt(ledgerOut,   /Requests\s+(\d+)/),
  cloud:     pickInt(ledgerOut,   /cloud_sent\s+(\d+)/),
  localOnly: pickInt(ledgerOut,   /local_only\s+(\d+)/),
  blocked:   pickInt(ledgerOut,   /blocked\s+(\d+)/),
  cost:      pickFloat(ledgerOut, /Cost\s+\$([\d.]+)/),
};

// Replay (no --summary mode) shows a per-run header. For our single-run
// fixture the header line contains "5 events: 3 cloud  ·  1 local  ·  1 blocked"
// followed by "$0.0060". We grep the total cost off the cost line.
const replay = {
  cost:      pickFloat(replayOut, /\$([\d.]+)/),
  cloudHits: pickInt(replayOut,   /(\d+)\s+cloud/),
};

// ── Assertions ────────────────────────────────────────────────────────────

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

console.log('\nDrift-guard fixture');
console.log(`  expected:  ${expected.requests} req · $${expected.cost.toFixed(4)} · cloud_sent=${expected.cloud_sent} local_only=${expected.local_only} blocked=${expected.blocked}`);
console.log(`  status:    ${status.requests} req · $${status.cost?.toFixed(4)}`);
console.log(`  ledger:    ${ledger.requests} req · $${ledger.cost?.toFixed(4)} · cloud=${ledger.cloud} local=${ledger.localOnly} blocked=${ledger.blocked}`);
console.log(`  replay:    $${replay.cost?.toFixed(4)} · cloud=${replay.cloudHits}`);

console.log('\nMatch against fixture:');
assert('status.requests matches fixture',     status.requests === expected.requests,
       `${status.requests} vs ${expected.requests}`);
assert('status.cost matches fixture',         Math.abs((status.cost || 0) - expected.cost) < 1e-4,
       `${status.cost} vs ${expected.cost}`);
assert('ledger.requests matches fixture',     ledger.requests === expected.requests,
       `${ledger.requests} vs ${expected.requests}`);
assert('ledger.cost matches fixture',         Math.abs((ledger.cost || 0) - expected.cost) < 1e-4,
       `${ledger.cost} vs ${expected.cost}`);
assert('ledger.cloud_sent matches fixture',   ledger.cloud === expected.cloud_sent,
       `${ledger.cloud} vs ${expected.cloud_sent}`);
assert('ledger.local_only matches fixture',   ledger.localOnly === expected.local_only,
       `${ledger.localOnly} vs ${expected.local_only}`);
assert('ledger.blocked matches fixture',      ledger.blocked === expected.blocked,
       `${ledger.blocked} vs ${expected.blocked}`);

console.log('\nCross-surface equality (the actual drift guard):');
assert('status.requests === ledger.requests', status.requests === ledger.requests,
       `${status.requests} vs ${ledger.requests}`);
assert('status.cost === ledger.cost',         Math.abs((status.cost || 0) - (ledger.cost || 0)) < 1e-4,
       `${status.cost} vs ${ledger.cost}`);
assert('replay total cost === ledger.cost',   Math.abs((replay.cost || 0) - (ledger.cost || 0)) < 1e-4,
       `replay ${replay.cost} vs ledger ${ledger.cost}`);

// ── Cleanup ───────────────────────────────────────────────────────────────

fs.readFileSync = realRead;
try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

console.log(`\n${'─'.repeat(40)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`✓ All ${total} drift-guard checks passed\n`);
  process.exit(0);
} else {
  console.error(`✗ ${failed} of ${total} drift-guard checks failed\n`);
  console.error('NOTE: This test is the lock-in for the truth-source unification.');
  console.error('A failure here means a second source of truth was reintroduced.');
  console.error('Investigate which read path bypasses src/models/events.js.\n');
  process.exit(1);
}
