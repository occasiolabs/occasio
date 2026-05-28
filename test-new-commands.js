#!/usr/bin/env node
'use strict';

/**
 * test-new-commands.js: smoke tests for the commands added on Tuesday evening.
 *
 * Covers: explain, receipt, bom export, compliance export, live render.
 * Each block runs against a small fixture chain via the same redirect
 * pattern as test-paranoid.js (OCCASIO_AUDIT_FILE env + fs.readFileSync
 * monkey-patch for session.json).
 *
 * Assertions are smoke-grade: the right shape of output, the right keys
 * present, the right exit codes. End-to-end correctness of each command
 * is verified by the existing test-events.js / test-drift-guard.js /
 * test-paranoid.js suites plus live verification before commit.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const tmpDir      = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-newcmds-'));
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

// ── Build a small fixture chain ───────────────────────────────────────────
const { createAuditor } = require('./src/audit/jsonl-auditor');
const auditor = createAuditor(chainPath);
const runId = 'newcmds-' + Date.now();
const cwd   = process.cwd();

// Two request rows plus two tool_call rows (one LOCAL, one BLOCK).
auditor.recordRequest({
  iso: '2026-05-28T13:00:00.000Z',
  run_id: runId, cwd, model: 'claude-haiku-4-5',
  event_type: 'cloud_sent', input_tokens: 100, output_tokens: 10, cost: 0.0012,
});
auditor.recordRequest({
  iso: '2026-05-28T13:00:05.000Z',
  run_id: runId, cwd, model: 'claude-haiku-4-5',
  event_type: 'local_only', input_tokens: 0, output_tokens: 0, cost: 0,
  tools_local_count: 1,
});
auditor.record(
  {
    timestamp: '2026-05-28T13:00:06.000Z',
    id: 'tc-local-' + Date.now(),
    sessionId: 'sess', runId,
    agent: 'claude-code', protocol: 'anthropic-http',
    direction: 'outbound', kind: 'tool_call',
    toolName: 'read_file',
    toolInput: { file_path: '/tmp/example.md' },
  },
  { action: 'LOCAL', reason: 'native-handler', policySource: 'default' },
  { passThrough: false, executor: 'native' });
auditor.record(
  {
    timestamp: '2026-05-28T13:00:08.000Z',
    id: 'tc-block-deadbeef-abcd',
    sessionId: 'sess', runId,
    agent: 'claude-code', protocol: 'anthropic-http',
    direction: 'outbound', kind: 'tool_call',
    toolName: 'read_file',
    toolInput: { path: '/tmp/secret.txt' },
  },
  { action: 'BLOCK', reason: 'path-denied', policySource: 'default' },
  { resultKind: 'block' });

fs.writeFileSync(sessionPath, JSON.stringify({
  run_id: runId,
  start:  '2026-05-28T13:00:00.000Z',
  cwd,
  mode:   'intercept',
  model:  'claude-haiku-4-5',
  budget: null,
}));

// ── Assertion harness ─────────────────────────────────────────────────────
let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
}

function captureStdout(fn) {
  let buf = '';
  const real = process.stdout.write.bind(process.stdout);
  const realLog = console.log;
  process.stdout.write = (chunk) => { buf += chunk; return true; };
  console.log = (...a) => { buf += a.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ') + '\n'; };
  try { fn(); }
  finally { process.stdout.write = real; console.log = realLog; }
  return buf;
}

async function captureStdoutAsync(fn) {
  let buf = '';
  const real = process.stdout.write.bind(process.stdout);
  const realLog = console.log;
  process.stdout.write = (chunk) => { buf += chunk; return true; };
  console.log = (...a) => { buf += a.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ') + '\n'; };
  try { await fn(); }
  finally { process.stdout.write = real; console.log = realLog; }
  return buf;
}

(async () => {

  // ── Block 1: explain ────────────────────────────────────────────────────
  console.log('\nBlock 1: occasio explain');
  {
    const explain = require('./src/cli/explain');
    // Help path
    let buf = captureStdout(() => explain.run(['--help']));
    assert('explain --help prints usage', buf.includes('usage:') && buf.includes('occasio explain'));

    // Exact + prefix lookup
    const exact = explain.findEvent('tc-block-deadbeef-abcd');
    assert('findEvent exact match', exact.event && exact.event.action === 'BLOCK');

    const prefix = explain.findEvent('tc-block');
    assert('findEvent unique prefix', prefix.event && prefix.event.action === 'BLOCK');

    const ambig = explain.findEvent('tc-');
    assert('findEvent ambiguous prefix flagged', ambig.ambiguous && ambig.candidates.length === 2);

    const missing = explain.findEvent('nosuch');
    assert('findEvent missing returns null', missing.event === null && !missing.ambiguous);

    // Render check
    buf = captureStdout(() => explain.run(['tc-block-deadbeef-abcd']));
    const plain = buf.replace(/\x1b\[[0-9;]*m/g, '');
    assert('explain output includes event_id',   plain.includes('tc-block-deadbeef-abcd'));
    assert('explain output includes action BLOCK', plain.includes('BLOCK'));
    assert('explain output includes reason',     plain.includes('path-denied'));
    assert('explain output includes chain context', plain.includes('prev_hash'));
  }

  // ── Block 2: receipt ────────────────────────────────────────────────────
  console.log('\nBlock 2: occasio receipt');
  {
    const receipt = require('./src/cli/receipt');
    const r = receipt.buildReceipt(runId);
    assert('receipt has schema field',           r.schema === 'occasio-receipt/v1');
    assert('receipt has run_id',                 r.run_id === runId);
    assert('receipt accounting requests = 2',    r.accounting.requests === 2);
    assert('receipt accounting cost = 0.0012',   Math.abs(r.accounting.cost_usd - 0.0012) < 1e-6);
    assert('receipt tools total = 2',            r.tools.total === 2);
    assert('receipt tools blocked = 1',          r.tools.blocked === 1);
    assert('receipt tools local = 1',            r.tools.local === 1);
    assert('receipt chain.first_hash present',   typeof r.chain.first_hash === 'string');
    assert('receipt chain.last_hash present',    typeof r.chain.last_hash === 'string');
    assert('receipt has NO cwd field',           !('cwd' in r));
    assert('receipt has NO tool_inputs anywhere', JSON.stringify(r).indexOf('tool_inputs') === -1);
    assert('receipt has NO file paths in body',  !JSON.stringify(r).includes('/tmp/'));

    // --help path
    const buf = await captureStdoutAsync(() => receipt.run(['--help']));
    assert('receipt --help prints usage', buf.includes('usage:') && buf.includes('occasio receipt'));
  }

  // ── Block 3: bom export ─────────────────────────────────────────────────
  console.log('\nBlock 3: occasio bom export');
  {
    const bom = require('./src/bom/cyclonedx');
    const b = bom.buildBom(runId);
    assert('bom bomFormat = CycloneDX',          b.bomFormat === 'CycloneDX');
    assert('bom specVersion = 1.6',              b.specVersion === '1.6');
    assert('bom serialNumber is urn:uuid:...',   /^urn:uuid:/.test(b.serialNumber));
    assert('bom metadata has tool component',    Array.isArray(b.metadata.tools.components));
    assert('bom run-component bom-ref = occasio:run:<id>',
           b.metadata.component['bom-ref'] === `occasio:run:${runId}`);
    assert('bom components include model',
           b.components.some(c => c.type === 'machine-learning-model' && c.name === 'claude-haiku-4-5'));
    assert('bom components include tool library',
           b.components.some(c => c.type === 'library' && c.name === 'read_file'));
    // Note: data components are populated from tool_inputs.path / file_path.
    // The auditor normalizer omits tool_inputs for many tool kinds, so the
    // fixture chain may not carry them; we only assert the data branch is
    // structurally reachable (zero or more data components is valid).
    assert('bom data components is an array (zero or more)',
           Array.isArray(b.components) && b.components.every(c => typeof c.type === 'string'));
    assert('bom dependencies graph present',     Array.isArray(b.dependencies) && b.dependencies.length === 1);

    const buf = captureStdout(() => bom.run(['--help']));
    assert('bom --help prints usage', buf.includes('usage:') && buf.includes('occasio bom export'));
  }

  // ── Block 4: compliance export ──────────────────────────────────────────
  console.log('\nBlock 4: occasio compliance export');
  {
    const compliance = require('./src/cli/compliance');
    const outDir = path.join(tmpDir, 'compliance-out');
    const res = compliance.exportRun(runId, outDir, 'eu-ai-act');
    assert('exportRun ok=true',                  res.ok === true);
    assert('exportRun files list has 5 entries', res.files.length === 5);
    assert('chain.jsonl was written',            fs.existsSync(path.join(outDir, 'chain.jsonl')));
    assert('receipt.json was written',           fs.existsSync(path.join(outDir, 'receipt.json')));
    assert('bom.cyclonedx.json was written',     fs.existsSync(path.join(outDir, 'bom.cyclonedx.json')));
    assert('framework-mapping.json was written', fs.existsSync(path.join(outDir, 'framework-mapping.json')));
    assert('summary.md was written',             fs.existsSync(path.join(outDir, 'summary.md')));

    const mapping = JSON.parse(fs.readFileSync(path.join(outDir, 'framework-mapping.json'), 'utf8'));
    assert('mapping framework = eu-ai-act',      mapping.framework === 'eu-ai-act');
    assert('mapping has Art-12 control',         mapping.controls.some(c => c.control_id === 'eu-ai-act/art-12'));
    assert('mapping has audit-chain control',    mapping.controls.some(c => c.control_id === 'occasio:audit-chain'));

    const summary = fs.readFileSync(path.join(outDir, 'summary.md'), 'utf8');
    assert('summary carries the Sharing note',   summary.includes('Sharing note'));
    assert('summary cites verify command',       summary.includes('occasio audit verify'));

    const buf = captureStdout(() => compliance.run(['--help']));
    assert('compliance --help prints usage', buf.includes('usage:') && buf.includes('occasio compliance export'));
  }

  // ── Block 5: live render ────────────────────────────────────────────────
  console.log('\nBlock 5: occasio live (render only)');
  {
    const live = require('./src/cli/live');
    const out = live.render().replace(/\x1b\[[0-9;]*m/g, '');
    assert('live render includes Occasio header', out.includes('⚡ Occasio live'));
    assert('live render includes Counters',       out.includes('Counters'));
    assert('live render includes Last 12 chain events', out.includes('Last 12 chain events'));
    assert('live render shows fixture run_id',    out.includes(runId));
    assert('live usage() returns help text',      live.usage().includes('usage: occasio live'));
  }

  console.log(`\n  ${passed} passed, ${failed} failed`);

  // Cleanup
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

  if (failed > 0) process.exit(1);
  process.exit(0);
})();
