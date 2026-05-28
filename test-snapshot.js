#!/usr/bin/env node
'use strict';

/**
 * test-snapshot.js: smoke test for `occasio` (no args) unified snapshot.
 *
 * Builds a tiny fixture chain via the same redirect pattern as
 * test-drift-guard.js, then renders the snapshot and asserts that the
 * expected section headers and counters appear.
 *
 * If this test fails, the renderer at src/cli/snapshot.js has drifted away
 * from the events.js facade or its public layout has changed.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const tmpDir      = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-snapshot-'));
const chainPath   = path.join(tmpDir, 'pipeline-events.jsonl');
const sessionPath = path.join(tmpDir, 'session.json');
process.env.OCCASIO_AUDIT_FILE = chainPath;

const realRead = fs.readFileSync;
fs.readFileSync = function (p, ...rest) {
  if (typeof p === 'string' && p.endsWith('session.json')) {
    return realRead(sessionPath, ...rest);
  }
  return realRead(p, ...rest);
};

const { createAuditor } = require('./src/audit/jsonl-auditor');
const auditor = createAuditor(chainPath);
const runId = 'snapshot-test-' + Date.now();
const cwd   = process.cwd();

const fixtures = [
  { event_type: 'cloud_sent', input_tokens: 100, output_tokens: 10, cost: 0.0012, model: 'claude-haiku-4-5' },
  { event_type: 'cloud_sent', input_tokens: 200, output_tokens: 20, cost: 0.0024, model: 'claude-haiku-4-5' },
  { event_type: 'local_only', input_tokens:   0, output_tokens:  0, cost: 0.0000, tools_local_count: 1 },
];

for (let i = 0; i < fixtures.length; i++) {
  const r = auditor.recordRequest({
    iso: `2026-05-28T13:0${i}:00.000Z`,
    run_id: runId, cwd, ...fixtures[i],
  });
  if (!r.ok) { console.error('fixture failed:', r.error?.message); process.exit(2); }
}

// Also record one tool_call so the "Last 5 chain events" block has variety.
{
  const event = {
    timestamp: '2026-05-28T13:03:00.000Z',
    id:        'tool-' + Date.now(),
    sessionId: 'snap-session',
    runId,
    agent:     'claude-code',
    protocol:  'anthropic-http',
    direction: 'outbound',
    kind:      'tool_call',
    toolName:  'read_file',
    toolInput: { file_path: 'README.md' },
  };
  auditor.record(event,
    { action: 'LOCAL', reason: 'native-handler', policySource: 'default' },
    { passThrough: false, executor: 'native' });
}

fs.writeFileSync(sessionPath, JSON.stringify({
  run_id: runId,
  start:  '2026-05-28T13:00:00.000Z',
  cwd,
  mode:   'intercept',
  model:  'claude-haiku-4-5',
  budget: 1.0,
}));

const { render } = require('./src/cli/snapshot');
const raw   = render();
const plain = raw.replace(/\x1b\[[0-9;]*m/g, '');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
}

console.log('\nSnapshot render');

assert('renders Occasio header',           plain.includes('Occasio'));
assert('has Active run section',           plain.includes('Active run'));
assert('shows the fixture run_id',         plain.includes(runId));
assert('has Accounting section',           plain.includes('Accounting'));
assert('shows total cost from fixture',    /\$0\.0036/.test(plain));
assert('shows requests count from fixture', /requests\s+3/.test(plain));
assert('has Tools section',                plain.includes('Tools'));
assert('has Last 5 chain events section',  plain.includes('Last 5 chain events'));
assert('lists the tool_call row',          plain.includes('read_file'));
assert('has Anomalies section',            plain.includes('Anomalies'));
assert('shows footer hints',               plain.includes('occasio claude'));
assert('every line ends without trailing colour state',
  plain.split('\n').every(line => !/\x1b\[[0-9;]*m\s*$/.test(line)));

console.log(`\n  ${passed} passed, ${failed} failed`);

// Cleanup
try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

if (failed > 0) process.exit(1);
process.exit(0);
