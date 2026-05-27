#!/usr/bin/env node
'use strict';

/**
 * test-events.js — unit tests for src/models/events.js.
 *
 * Phase-3 of the truth-source unification: this is the single read facade
 * over the audit chain. If these tests regress, every Inspect command in
 * Phase 4 starts showing wrong numbers.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const {
  loadEvents,
  currentRunId,
  groupByRun,
  pickRecentRuns,
  summarize,
  buildRunStats,
  buildToolStats,
  zeroAccountingStats,
  readChain,
  isToday,
  todayDateString,
} = require('./src/models/events');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

function tmpFile() {
  return path.join(os.tmpdir(), `occasio-events-test-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
}

function writeChain(file, rows) {
  fs.writeFileSync(file, rows.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf8');
}

// Realistic fixture mirroring what audit/jsonl-auditor.js actually writes.
function reqRow({ runId = 'r1', ts = '2026-05-28T12:00:00.000Z', et = 'cloud_sent',
                  cost = 0, inp = 0, out = 0, cwd = 'C:\\proj', model = 'haiku' } = {}) {
  return {
    audit_schema: 1, ts, event_id: `e-${Math.random()}`,
    session_id: runId, run_id: runId, agent: 'occasio',
    protocol: 'anthropic-http', direction: 'outbound',
    kind: 'request', event_type: et, model, cwd,
    input_tokens: inp, output_tokens: out,
    cache_read_tokens: 0, cache_write_tokens: 0,
    cost, cache_savings: 0,
    lao_tokens_saved: 0, lao_cost_saved: 0,
    distill_tokens_saved: 0, distill_cost_saved: 0,
    tools_attempted: 0, tools_local_count: 0, tools_mcp_count: 0,
    prev_hash: '0'.repeat(64), hash: 'x'.repeat(64),
  };
}

function toolRow({ runId = 'r1', ts = '2026-05-28T12:00:00.000Z',
                   tool = 'Read', action = 'LOCAL' } = {}) {
  return {
    audit_schema: 1, ts, event_id: `t-${Math.random()}`,
    session_id: runId, run_id: runId, agent: 'claude-code',
    protocol: 'anthropic-http', direction: 'inbound',
    kind: 'tool_call', tool_name: tool, tool_inputs: {},
    action, reason: 'ok', policy_source: 'default',
    prev_hash: '0'.repeat(64), hash: 'x'.repeat(64),
  };
}

// ── 1. readChain ─────────────────────────────────────────────────────────────
console.log('\n1. readChain');
{
  const f = tmpFile();
  assert('missing file → empty array', readChain(f).length === 0);

  writeChain(f, [reqRow(), toolRow()]);
  const rows = readChain(f);
  assert('reads two rows', rows.length === 2);
  assert('preserves write order', rows[0].kind === 'request' && rows[1].kind === 'tool_call');

  // Malformed line in the middle is skipped silently
  fs.appendFileSync(f, '{this-is-not-json}\n');
  fs.appendFileSync(f, JSON.stringify(reqRow({ runId: 'r2' })) + '\n');
  const rows2 = readChain(f);
  assert('malformed line skipped, valid rows survive', rows2.length === 3);

  fs.unlinkSync(f);
}

// ── 2. loadEvents — filters ──────────────────────────────────────────────────
console.log('\n2. loadEvents — filters');
{
  const f = tmpFile();
  writeChain(f, [
    reqRow({ runId: 'r1', cost: 0.01, cwd: 'C:\\a' }),
    reqRow({ runId: 'r2', cost: 0.02, cwd: 'C:\\b' }),
    toolRow({ runId: 'r1' }),
    toolRow({ runId: 'r2' }),
  ]);

  assert('no filter → all 4 rows', loadEvents({ file: f }).length === 4);

  const onlyReq = loadEvents({ file: f, kind: 'request' });
  assert('kind:"request" filter → 2', onlyReq.length === 2);
  assert('kind:"request" rows are request kind', onlyReq.every(e => e.kind === 'request'));

  const onlyTool = loadEvents({ file: f, kind: 'tool_call' });
  assert('kind:"tool_call" filter → 2', onlyTool.length === 2);

  const multi = loadEvents({ file: f, kind: ['request', 'tool_call'] });
  assert('array kind → all 4', multi.length === 4);

  const r1 = loadEvents({ file: f, runId: 'r1' });
  assert('runId filter → 2', r1.length === 2);
  assert('runId filter actually matched', r1.every(e => e.run_id === 'r1'));

  const cwdA = loadEvents({ file: f, cwd: 'C:\\a' });
  assert('cwd filter → 1 (only request row carries cwd)', cwdA.length === 1);

  const combined = loadEvents({ file: f, kind: 'request', runId: 'r1' });
  assert('combined kind+runId → 1', combined.length === 1);

  fs.unlinkSync(f);
}

// ── 3. loadEvents — time filters ─────────────────────────────────────────────
console.log('\n3. loadEvents — time filters');
{
  const f = tmpFile();
  writeChain(f, [
    reqRow({ ts: '2026-05-26T10:00:00.000Z' }),
    reqRow({ ts: '2026-05-27T10:00:00.000Z' }),
    reqRow({ ts: '2026-05-28T10:00:00.000Z' }),
  ]);

  const since = loadEvents({ file: f, since: '2026-05-27T00:00:00.000Z' });
  assert('since filter → 2', since.length === 2);

  const until = loadEvents({ file: f, until: '2026-05-27T00:00:00.000Z' });
  assert('until filter → 1', until.length === 1);

  const window = loadEvents({
    file: f,
    since: '2026-05-27T00:00:00.000Z',
    until: '2026-05-28T00:00:00.000Z',
  });
  assert('since+until window → 1', window.length === 1);

  fs.unlinkSync(f);
}

// ── 4. today filter ──────────────────────────────────────────────────────────
console.log('\n4. isToday / today filter');
{
  const now = new Date();
  const today = todayDateString(now);
  const todayIso = `${today}T12:00:00.000Z`;
  const yesterdayIso = '2020-01-01T12:00:00.000Z';

  assert('isToday on today\'s ts', isToday(todayIso, now) === true);
  assert('isToday on old ts', isToday(yesterdayIso, now) === false);
  assert('isToday on null', isToday(null, now) === false);

  const f = tmpFile();
  writeChain(f, [
    reqRow({ ts: todayIso }),
    reqRow({ ts: yesterdayIso }),
  ]);
  const onlyToday = loadEvents({ file: f, today: true });
  assert('today filter picks today\'s row only', onlyToday.length === 1);
  assert('row picked is today\'s', onlyToday[0].ts === todayIso);

  fs.unlinkSync(f);
}

// ── 5. groupByRun ────────────────────────────────────────────────────────────
console.log('\n5. groupByRun');
{
  const events = [
    reqRow({ runId: 'r1', ts: '2026-05-28T10:00:00.000Z' }),
    reqRow({ runId: 'r2', ts: '2026-05-28T11:00:00.000Z' }),
    reqRow({ runId: 'r1', ts: '2026-05-28T10:30:00.000Z' }),
  ];
  const groups = groupByRun(events);
  assert('two distinct runs', groups.size === 2);
  assert('r1 has 2 events', groups.get('r1').length === 2);
  assert('r2 has 1 event',  groups.get('r2').length === 1);
  assert('r1 events sorted by ts ascending',
         groups.get('r1')[0].ts < groups.get('r1')[1].ts);

  // events without run_id end up under 'legacy'
  const withLegacy = groupByRun([...events, { kind: 'policy_loaded', ts: '2026-05-28T09:00:00.000Z' }]);
  assert('events without run_id grouped as "legacy"', withLegacy.has('legacy'));
}

// ── 6. pickRecentRuns ────────────────────────────────────────────────────────
console.log('\n6. pickRecentRuns');
{
  const groups = groupByRun([
    reqRow({ runId: 'r-old',    ts: '2026-05-26T10:00:00.000Z' }),
    reqRow({ runId: 'r-mid',    ts: '2026-05-27T10:00:00.000Z' }),
    reqRow({ runId: 'r-recent', ts: '2026-05-28T10:00:00.000Z' }),
  ]);
  const top1 = pickRecentRuns(groups, 1);
  assert('top 1 picks most recent', top1.length === 1 && top1[0].runId === 'r-recent');

  const top2 = pickRecentRuns(groups, 2);
  assert('top 2 in descending end-time', top2[0].runId === 'r-recent' && top2[1].runId === 'r-mid');
}

// ── 7. summarize ─────────────────────────────────────────────────────────────
console.log('\n7. summarize');
{
  assert('empty list → zero stats', summarize([]).requests === 0);
  assert('zero stats has all fields', Object.keys(zeroAccountingStats()).length > 10);

  const stats = summarize([
    reqRow({ et: 'cloud_sent', cost: 0.001, inp: 100, out: 10 }),
    reqRow({ et: 'cloud_sent', cost: 0.002, inp: 200, out: 20 }),
    reqRow({ et: 'local_only', cost: 0,    inp: 0,   out: 0 }),
    reqRow({ et: 'blocked',    cost: 0,    inp: 0,   out: 0 }),
  ]);
  assert('counts 4 requests', stats.requests === 4);
  assert('counts cloud_sent', stats.cloud_sent === 2);
  assert('counts local_only', stats.local_only === 1);
  assert('counts blocked',    stats.blocked === 1);
  assert('sums input_tokens',  stats.input_tokens === 300);
  assert('sums output_tokens', stats.output_tokens === 30);
  assert('sums cost',          Math.abs(stats.cost - 0.003) < 1e-9);

  // tool_call rows mixed in are IGNORED by summarize
  const mixed = summarize([
    reqRow({ cost: 0.01 }),
    toolRow(),
    toolRow(),
  ]);
  assert('summarize ignores tool_call rows', mixed.requests === 1);
  assert('summarize still sums request cost from mix', Math.abs(mixed.cost - 0.01) < 1e-9);
}

// ── 8. buildRunStats (alias for summarize, run-scoped intent) ─────────────────
console.log('\n8. buildRunStats');
{
  const stats = buildRunStats([
    reqRow({ runId: 'r1', cost: 0.01, ts: '2026-05-28T10:00:00.000Z' }),
    reqRow({ runId: 'r1', cost: 0.02, ts: '2026-05-28T10:05:00.000Z' }),
  ]);
  assert('start = earliest ts',  stats.start === '2026-05-28T10:00:00.000Z');
  assert('end = latest ts',      stats.end   === '2026-05-28T10:05:00.000Z');
  assert('durationMs > 0',       stats.durationMs > 0);
  assert('cost summed',          Math.abs(stats.cost - 0.03) < 1e-9);

  assert('empty run → zero stats', buildRunStats([]).requests === 0);
  assert('null input → zero stats', buildRunStats(null).requests === 0);
}

// ── 9. buildToolStats ────────────────────────────────────────────────────────
console.log('\n9. buildToolStats');
{
  const stats = buildToolStats([
    toolRow({ tool: 'Read',  action: 'LOCAL' }),
    toolRow({ tool: 'Read',  action: 'LOCAL' }),
    toolRow({ tool: 'Grep',  action: 'LOCAL' }),
    toolRow({ tool: 'Read',  action: 'BLOCK' }),
    toolRow({ tool: 'Write', action: 'TRANSFORM' }),
    reqRow(),  // should be ignored
  ]);
  assert('counts 5 tool calls (request row ignored)', stats.total === 5);
  assert('Read counted 3 times', stats.by_tool.Read === 3);
  assert('Grep counted once',    stats.by_tool.Grep === 1);
  assert('local action counted', stats.local === 3);
  assert('block action counted', stats.blocked === 1);
  assert('transform action counted', stats.transformed === 1);
}

// ── 10. currentRunId ─────────────────────────────────────────────────────────
console.log('\n10. currentRunId');
{
  const f = tmpFile();
  fs.writeFileSync(f, JSON.stringify({ run_id: 'r-current', other: 'data' }));
  assert('reads run_id from session.json', currentRunId(f) === 'r-current');
  fs.unlinkSync(f);

  assert('missing session.json → null', currentRunId('/no/such/file.json') === null);

  const f2 = tmpFile();
  fs.writeFileSync(f2, '{not valid json');
  assert('malformed session.json → null', currentRunId(f2) === null);
  fs.unlinkSync(f2);

  const f3 = tmpFile();
  fs.writeFileSync(f3, JSON.stringify({ no_run_id: true }));
  assert('session.json without run_id → null', currentRunId(f3) === null);
  fs.unlinkSync(f3);
}

// ── 11. End-to-end: chain → loadEvents → summarize ───────────────────────────
console.log('\n11. End-to-end pipeline');
{
  const f = tmpFile();
  writeChain(f, [
    reqRow({ runId: 'r1', cost: 0.01, et: 'cloud_sent', inp: 100, out: 10 }),
    toolRow({ runId: 'r1', tool: 'Read', action: 'LOCAL' }),
    reqRow({ runId: 'r1', cost: 0.02, et: 'cloud_sent', inp: 200, out: 20 }),
    reqRow({ runId: 'r2', cost: 0.05, et: 'cloud_sent', inp: 500, out: 50 }),
  ]);

  // "Status for current run r1" simulation
  const r1Events = loadEvents({ file: f, runId: 'r1', kind: 'request' });
  const r1Stats  = summarize(r1Events);
  assert('r1: 2 requests', r1Stats.requests === 2);
  assert('r1: cost = 0.03', Math.abs(r1Stats.cost - 0.03) < 1e-9);

  // "Replay all runs" simulation
  const allRequests = loadEvents({ file: f, kind: 'request' });
  const groups = groupByRun(allRequests);
  assert('two distinct runs in chain', groups.size === 2);

  // "Behavioral view for r1" simulation
  const r1Behavior = loadEvents({ file: f, runId: 'r1', kind: 'tool_call' });
  const toolStats  = buildToolStats(r1Behavior);
  assert('r1: 1 tool call', toolStats.total === 1);
  assert('r1: 1 LOCAL action', toolStats.local === 1);

  fs.unlinkSync(f);
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(40)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`✓ All ${total} events.js tests passed\n`);
  process.exit(0);
} else {
  console.error(`✗ ${failed} of ${total} events.js tests failed\n`);
  process.exit(1);
}
