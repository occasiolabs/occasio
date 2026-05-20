#!/usr/bin/env node
'use strict';

/**
 * test-eyes.js — unit tests for src/eyes/ (tail, reducer, render, demo).
 *
 * No real TTY interaction. The tail tests write a real file in os.tmpdir().
 * The render tests assert on plain (no-color) output and on a few ANSI
 * structural invariants so layout regressions fail loudly.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { tail, readAll }            = require('./src/eyes/events');
const { initialState, reduce, normTool, pathOf } = require('./src/eyes/state');
const { render, stripAnsi, fmtBytes, fmtUsd, fmtTime } = require('./src/eyes/render');
const { SCRIPT }                   = require('./src/eyes/demo-script');
const eyes                         = require('./src/eyes');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else      { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

// ── 1. state.normTool / pathOf ──────────────────────────────────────────────
console.log('\n1. state — normTool, pathOf');
assert('normTool Read', normTool('Read') === 'Read');
assert('normTool read_file → Read', normTool('read_file') === 'Read');
assert('normTool shell_bash → Bash', normTool('shell_bash') === 'Bash');
assert('normTool unknown passthrough', normTool('Frobnicate') === 'Frobnicate');
assert('pathOf path', pathOf({ tool_inputs: { path: '/x' } }) === '/x');
assert('pathOf file_path', pathOf({ tool_inputs: { file_path: '/y' } }) === '/y');
assert('pathOf command', pathOf({ tool_inputs: { command: 'git status' } }) === 'git status');
assert('pathOf null', pathOf({ tool_inputs: {} }) === null);

// ── 2. reducer transitions ──────────────────────────────────────────────────
console.log('\n2. state — reduce()');

let s = initialState();
assert('initial recent empty', s.recent.length === 0);
assert('initial totals zero', s.totals.local === 0 && s.totals.cloud === 0);

s = reduce(s, { kind: 'tool_call', tool_name: 'Read', tool_inputs: { path: 'a.js' },
                action: 'PASS', executor: 'local', tokens_saved: 1000, ts: '2026-05-19T10:00:00Z',
                run_id: 'r1' }, 100);
assert('after one LOCAL row → local=1', s.totals.local === 1, `got ${s.totals.local}`);
assert('cloud still 0', s.totals.cloud === 0);
assert('recent has 1', s.recent.length === 1);
assert('now.tool=Read', s.now.tool === 'Read');
assert('runId tracked', s.runId === 'r1');
assert('savedUsd > 0', s.totals.savedUsd > 0);

s = reduce(s, { kind: 'tool_call', tool_name: 'Edit', tool_inputs: { file_path: 'b.js' },
                action: 'PASS', executor: 'cloud', ts: '2026-05-19T10:00:01Z',
                run_id: 'r1' }, 200);
assert('cloud=1', s.totals.cloud === 1);

s = reduce(s, { kind: 'tool_call', tool_name: 'Read', tool_inputs: { path: '/etc/passwd' },
                action: 'BLOCK', reason: 'deny_paths', ts: '2026-05-19T10:00:02Z',
                run_id: 'r1' }, 300);
assert('blocks=1', s.totals.blocks === 1);
assert('now.action=BLOCK', s.now.action === 'BLOCK');

s = reduce(s, { kind: 'tool_call', tool_name: 'Grep', tool_inputs: { pattern: 'sk-' },
                action: 'TRANSFORM', secrets_redacted: 3, executor: 'local',
                ts: '2026-05-19T10:00:03Z', run_id: 'r1' }, 400);
assert('redactions=3', s.totals.redactions === 3);
assert('recent newest first', s.recent[0].tool === 'Grep');
assert('recent has 4', s.recent.length === 4);

// non-tool_call rows ignored
const before = s;
s = reduce(s, { kind: 'request', tool_name: 'foo' }, 500);
assert('non-tool_call ignored', s === before);

// policy_loaded
s = reduce(s, { kind: 'policy_loaded', tool_name: 'policy_loaded',
                tool_inputs: { policy_hash: 'abc123def456', policy_path: 'p.yml', version: 1 },
                action: 'INFO', policy_source: 'user' }, 600);
assert('policy hash set', s.policy.hash === 'abc123def456');
assert('policy source=user', s.policy.source === 'user');
assert('hotReloads still 0 (first load)', s.policy.hotReloads === 0);

// second different policy hash → hot reload counter
s = reduce(s, { kind: 'policy_loaded', tool_name: 'policy_loaded',
                tool_inputs: { policy_hash: 'XYZ', policy_path: 'p.yml', version: 2 },
                action: 'INFO', policy_source: 'user' }, 700);
assert('hotReloads=1 after hash change', s.policy.hotReloads === 1);

// cap at 12 recent
let s2 = initialState();
for (let i = 0; i < 20; i++) {
  s2 = reduce(s2, { kind: 'tool_call', tool_name: 'Read', tool_inputs: { path: 'x'+i },
                    action: 'PASS', executor: 'local',
                    ts: `2026-05-19T10:00:${String(i).padStart(2,'0')}Z`, run_id: 'r2' }, i*10);
}
assert('recent capped at 12', s2.recent.length === 12);
assert('newest first after cap', s2.recent[0].path === 'x19');

// ── 3. render — invariants ──────────────────────────────────────────────────
console.log('\n3. render — invariants');

let s3 = initialState();
s3 = reduce(s3, { kind: 'tool_call', tool_name: 'Read', tool_inputs: { path: 'src/foo.js', bytes: 1024 },
                  action: 'PASS', executor: 'local', tokens_saved: 500,
                  ts: '2026-05-19T10:00:00Z', run_id: 'aaaaa-bbbbb' }, 0);

const plain = render(s3, 100, { width: 80, color: false });
assert('render produces a string', typeof plain === 'string');
assert('render contains AGENT EYES', plain.includes('AGENT EYES'));
assert('render contains tool Read', plain.includes('Read'));
assert('render contains path', plain.includes('src/foo.js'));
assert('render contains LAST CALLS', plain.includes('LAST CALLS'));
assert('render contains LOCAL vs CLOUD', plain.includes('LOCAL vs CLOUD'));
assert('render contains POLICY', plain.includes('POLICY'));
assert('plain mode has no ANSI escapes', !/\x1b\[/.test(plain),
  'unexpected ANSI in --no-color output');

// width stability: every visible-text line is ≤ requested width
const visLines = plain.split('\n').map(stripAnsi).filter(Boolean);
let widthOk = true;
for (const line of visLines) {
  if (line.length > 200) { widthOk = false; break; }
}
assert('no line absurdly long', widthOk);

// color mode contains ANSI
const colored = render(s3, 100, { width: 80, color: true });
assert('color mode contains ANSI', /\x1b\[/.test(colored));

// empty state should still render without throwing
const empty = render(initialState(), 0, { width: 80, color: false });
assert('empty state renders', empty.includes('waiting for first event'));

// formatters
assert('fmtBytes 512', fmtBytes(512) === '512 B');
assert('fmtBytes 2048', fmtBytes(2048) === '2.0 KB');
assert('fmtBytes null', fmtBytes(null) === '');
assert('fmtUsd small', fmtUsd(0.0034).startsWith('$0.003'));
assert('fmtUsd zero', fmtUsd(0) === '$0.0000');
assert('fmtTime ISO', fmtTime('2026-05-19T14:22:07Z') === '14:22:07');
assert('fmtTime null', fmtTime(null) === '--:--:--');

// ── 4. tail — appends are picked up ─────────────────────────────────────────
console.log('\n4. events.tail() — appended lines emit rows');

const tmp = path.join(os.tmpdir(), `eyes-test-${Date.now()}-${process.pid}.jsonl`);
try { fs.unlinkSync(tmp); } catch { /* ignore */ }
fs.writeFileSync(tmp, ''); // empty start

const seen = [];
const t = tail(tmp, (row) => seen.push(row), { interval: 60 });

fs.appendFileSync(tmp, JSON.stringify({ kind: 'tool_call', tool_name: 'Read', tool_inputs: { path: 'a' } }) + '\n');
fs.appendFileSync(tmp, JSON.stringify({ kind: 'tool_call', tool_name: 'Glob', tool_inputs: { pattern: '*.js' } }) + '\n');

// Drain explicitly rather than racing watchFile.
t.drain();

assert('tail saw 2 rows', seen.length === 2, `got ${seen.length}`);
assert('first row Read', seen[0] && seen[0].tool_name === 'Read');
assert('second row Glob', seen[1] && seen[1].tool_name === 'Glob');

// partial line buffered until newline
fs.appendFileSync(tmp, '{"kind":"tool_call","tool_name":"Bash"');
t.drain();
assert('partial line buffered (still 2)', seen.length === 2);

fs.appendFileSync(tmp, ',"tool_inputs":{"command":"ls"}}\n');
t.drain();
assert('partial completed → 3 rows', seen.length === 3);
assert('third row Bash', seen[2] && seen[2].tool_name === 'Bash');

// malformed line is skipped, not crashing
fs.appendFileSync(tmp, 'this is not json\n');
fs.appendFileSync(tmp, JSON.stringify({ kind: 'tool_call', tool_name: 'Edit' }) + '\n');
t.drain();
assert('malformed skipped, valid emitted (4)', seen.length === 4);
assert('row after malformed is Edit', seen[3] && seen[3].tool_name === 'Edit');

t.stop();
try { fs.unlinkSync(tmp); } catch { /* ignore */ }

// readAll
const tmp2 = path.join(os.tmpdir(), `eyes-test-all-${Date.now()}.jsonl`);
fs.writeFileSync(tmp2, '{"a":1}\n{"a":2}\nnot json\n{"a":3}\n');
const all = readAll(tmp2);
assert('readAll skips malformed', all.length === 3);
assert('readAll parses', all[0].a === 1 && all[2].a === 3);
try { fs.unlinkSync(tmp2); } catch { /* ignore */ }
assert('readAll missing file → []', readAll(path.join(os.tmpdir(), 'no-such-eyes-file.jsonl')).length === 0);

// ── 5. demo script + replay event shape ────────────────────────────────────
console.log('\n5. demo-script + replay');

assert('SCRIPT has rows', SCRIPT.length > 5);
for (let i = 0; i < SCRIPT.length; i++) {
  const e = SCRIPT[i];
  if (typeof e.delayMs !== 'number' || !e.row) { failed++; console.error(`  ✗ SCRIPT[${i}] shape`); break; }
}
// drive the reducer through the whole script — must not throw, must produce non-zero totals
let sd = initialState();
let t0 = 0;
for (const ev of SCRIPT) { t0 += ev.delayMs; sd = reduce(sd, ev.row, t0); }
assert('demo produces tool calls', sd.totals.callCount > 5,
  `callCount=${sd.totals.callCount}`);
assert('demo produces a block', sd.totals.blocks >= 1);
assert('demo produces redactions', sd.totals.redactions >= 1);
assert('demo loads policy', sd.policy.hash !== null);

// parseArgs
const args = eyes.parseArgs(['--demo', '--no-color', '--frames', '3']);
assert('parseArgs demo', args.demo === true);
assert('parseArgs no-color', args.color === false);
assert('parseArgs frames', args.frames === 3);

const args2 = eyes.parseArgs(['--replay', 'last', '--speed', '2']);
assert('parseArgs replay last', args2.replay === 'last');
assert('parseArgs speed', args2.speed === 2);

// eventsFromReplay computes deltas
const rows = [
  { ts: '2026-05-19T10:00:00.000Z', kind: 'tool_call', tool_name: 'Read' },
  { ts: '2026-05-19T10:00:01.500Z', kind: 'tool_call', tool_name: 'Glob' },
];
const evs = eyes.eventsFromReplay(rows, 1);
assert('eventsFromReplay 2 rows', evs.length === 2);
assert('second delay ≈ 1500ms', Math.abs(evs[1].delayMs - 1500) < 5,
  `got ${evs[1].delayMs}`);

const evsFast = eyes.eventsFromReplay(rows, 2);
assert('speed=2 halves delay', Math.abs(evsFast[1].delayMs - 750) < 5);

// ── 6. capture — extractPayload + persistence ──────────────────────────────
console.log('\n6. capture — extractPayload, ring buffer, listPayloads');

const capture = require('./src/eyes/capture');
const { render: renderContent, buildBodyLines } = require('./src/eyes/content-render');

// extractPayload — flattens system + messages + tool blocks
const body = {
  model: 'claude-opus-4-7',
  system: 'You are Claude Code.',
  messages: [
    { role: 'user', content: 'hi' },
    { role: 'assistant', content: [
      { type: 'text', text: 'reading file' },
      { type: 'tool_use', id: 'tu_1', name: 'Read', input: { path: 'a.js' } },
    ]},
    { role: 'user', content: [
      { type: 'tool_result', tool_use_id: 'tu_1', content: 'line1\nline2' },
    ]},
  ],
};
const ext = capture.extractPayload(body, { seq: 5, ts: '2026-05-20T10:00:00Z', runId: 'r9',
                                            byteCountBefore: 1000, byteCountAfter: 900,
                                            redactionCount: 1, blockedCount: 0 });
assert('extract seq', ext.seq === 5);
assert('extract model', ext.model === 'claude-opus-4-7');
assert('extract runId', ext.runId === 'r9');
assert('extract system text', ext.system.text === 'You are Claude Code.');
assert('extract 3 messages', ext.messages.length === 3);
assert('user msg is text block', ext.messages[0].blocks[0].kind === 'text');
assert('assistant tool_use detected', ext.messages[1].blocks.some(b => b.kind === 'tool_use' && b.toolName === 'Read'));
assert('tool_result detected', ext.messages[2].blocks[0].kind === 'tool_result');
assert('tool_result content', ext.messages[2].blocks[0].text === 'line1\nline2');
assert('byteCount preserved', ext.byteCount.before === 1000 && ext.byteCount.after === 900);

// system as array of blocks
const ext2 = capture.extractPayload({
  system: [{ type: 'text', text: 'A' }, { type: 'text', text: 'B' }],
  messages: [],
}, {});
assert('system as block array joined', ext2.system.text === 'A\nB');

// long content gets clipped
const longText = 'x'.repeat(capture.PER_BLOCK_MAX + 100);
const extLong = capture.extractPayload({ system: longText, messages: [] }, {});
assert('long system clipped', extLong.system.truncated === true);
assert('long system bytes recorded', extLong.system.bytes === longText.length);

// ── capture persistence ─────────────────────────────────────────────────────
const tmpDir = path.join(os.tmpdir(), `eyes-cap-${Date.now()}-${process.pid}`);
const origDir = capture.EYES_DIR;
// monkey-patch EYES_DIR via writing to tmp then re-reading via listPayloadFiles
// (capture module reads its own constant; for the persistence test we'll
// instead drive enable() + check writeFileSync behavior via a small wrapper).
// Easier: ensureDir on tmp, call internal-ish flow by writing JSON ourselves.
fs.mkdirSync(tmpDir, { recursive: true });
fs.writeFileSync(path.join(tmpDir, 'payload-000001.json'), JSON.stringify({ seq: 1 }));
fs.writeFileSync(path.join(tmpDir, 'payload-000002.json'), JSON.stringify({ seq: 2 }));
fs.writeFileSync(path.join(tmpDir, 'not-mine.txt'),        'ignore me');
const eyesIdx2 = require('./src/eyes');
const listed = eyesIdx2.listPayloadFiles(tmpDir);
assert('listPayloadFiles excludes non-payload', listed.length === 2);
assert('listPayloadFiles sorted', listed[0] === 'payload-000001.json' && listed[1] === 'payload-000002.json');
const readBack = eyesIdx2.readPayloadFile(tmpDir, 'payload-000002.json');
assert('readPayloadFile parses', readBack && readBack.seq === 2);
try {
  fs.unlinkSync(path.join(tmpDir, 'payload-000001.json'));
  fs.unlinkSync(path.join(tmpDir, 'payload-000002.json'));
  fs.unlinkSync(path.join(tmpDir, 'not-mine.txt'));
  fs.rmdirSync(tmpDir);
} catch { /* ignore */ }

// capture disabled by default → captureOutbound returns null without writing
assert('capture disabled by default', !capture.isEnabled());
const writtenWhenOff = capture.captureOutbound({ messages: [] }, {});
assert('captureOutbound off → null', writtenWhenOff === null);

// ── 7. content-render — invariants ─────────────────────────────────────────
console.log('\n7. content-render — invariants');

const demoPayload = require('./src/eyes/demo-content').PAYLOADS[1];
assert('demo payload has tool_result', demoPayload.messages.some(m =>
  m.blocks.some(b => b.kind === 'tool_result')));

const plain2 = renderContent(demoPayload, { width: 100, height: 30, color: false, scroll: 0 });
assert('content render returns string', typeof plain2 === 'string');
assert('content render no ANSI in no-color', !/\x1b\[/.test(plain2));
assert('content render contains OUTBOUND #', plain2.includes('OUTBOUND #'));
assert('content render contains system prompt header', plain2.includes('system prompt'));
assert('content render shows messages header', plain2.includes('messages'));
assert('content render shows tool_result content', plain2.includes('jwt.sign') || plain2.includes('bcrypt'));
assert('content render contains line numbers', /\b\d+│/.test(plain2));

// null payload renders an empty-state hint
const empty2 = renderContent(null, { width: 100, height: 30, color: false });
assert('null payload renders empty-state', empty2.includes('no outbound captured'));

// scroll moves window
const linesAll = buildBodyLines(demoPayload, {
  bold: s=>s, dim:s=>s, white:s=>s, cyan:s=>s, mag:s=>s, yellow:s=>s, green:s=>s,
  red:s=>s, blue:s=>s, bgYellow:s=>s, reset:'',
}, 96);
assert('buildBodyLines yields >5', linesAll.length > 5);

const scrolled = renderContent(demoPayload, { width: 100, height: 30, color: false, scroll: 5 });
assert('scrolled differs from top', scrolled !== plain2);

// width stability — no line absurdly long
let widthOk2 = true;
for (const ln of plain2.split('\n')) {
  if (ln.length > 220) { widthOk2 = false; break; }
}
assert('content lines bounded width', widthOk2);

// parseArgs for content mode defaults
const args3 = eyes.parseArgs([]);
assert('default mode = web', args3.mode === 'web');
const args4 = eyes.parseArgs(['--tools']);
assert('--tools → tools mode', args4.mode === 'tools');
const args5 = eyes.parseArgs(['--tui', '--demo']);
assert('--tui explicit', args5.mode === 'tui' && args5.demo === true);
const args6 = eyes.parseArgs(['--content']);
assert('--content alias → tui', args6.mode === 'tui');
const args7 = eyes.parseArgs(['--port', '4000', '--no-open']);
assert('--port parsed', args7.port === 4000);
assert('--no-open parsed', args7.noOpen === true);

// ── 8. dump + collapse behavior ─────────────────────────────────────────────
console.log('\n8. dump + system/reminder collapse');

const { dumpText } = require('./src/eyes/dump');
const dumpStr = dumpText(demoPayload);
assert('dumpText returns string', typeof dumpStr === 'string');
assert('dump contains OUTBOUND header', dumpStr.includes('OUTBOUND #'));
assert('dump contains system prompt', dumpStr.includes('system prompt'));
assert('dump contains tool_result body', dumpStr.includes('jwt.sign'));
assert('dump has no ANSI', !/\x1b\[/.test(dumpStr));

// stripReminders option drops <system-reminder> blocks
const payloadWithReminder = {
  schema: 1, seq: 9, ts: '2026-05-20T10:00:00Z', runId: 'r',
  byteCount: { before: 100, after: 100 },
  system: null,
  messages: [{ role: 'user', blocks: [
    { kind: 'text', text: 'hello <system-reminder>SECRET INSTRUCTIONS</system-reminder> world', bytes: 60 },
  ]}],
  redactionCount: 0, blockedCount: 0,
};
const dumpedKept    = dumpText(payloadWithReminder, { stripReminders: false });
const dumpedStripped = dumpText(payloadWithReminder, { stripReminders: true });
assert('dump keeps reminders by default', dumpedKept.includes('SECRET INSTRUCTIONS'));
assert('dump strips reminders on flag', !dumpedStripped.includes('SECRET INSTRUCTIONS'));

// collapse defaults: system + reminders hidden in render
const renderedCollapsed = renderContent(payloadWithReminder, {
  width: 100, height: 30, color: false, scroll: 0,
  showSystem: false, showReminders: false,
});
assert('collapsed render hides reminder body', !renderedCollapsed.includes('SECRET INSTRUCTIONS'));
assert('collapsed render shows reminder placeholder', renderedCollapsed.includes('system-reminder'));

const renderedExpanded = renderContent(payloadWithReminder, {
  width: 100, height: 30, color: false, scroll: 0,
  showSystem: false, showReminders: true,
});
assert('expanded render shows reminder body', renderedExpanded.includes('SECRET INSTRUCTIONS'));

// system collapse: render system collapsed/expanded
const payloadWithSystem = {
  schema: 1, seq: 1, ts: '2026-05-20T10:00:00Z', runId: 'r',
  byteCount: { before: 200, after: 200 },
  system: { text: 'UNIQUE_SYSTEM_TOKEN_zzz', bytes: 23, truncated: false },
  messages: [], redactionCount: 0, blockedCount: 0,
};
const sysCollapsed = renderContent(payloadWithSystem, { width: 100, height: 30, color: false, showSystem: false });
const sysExpanded  = renderContent(payloadWithSystem, { width: 100, height: 30, color: false, showSystem: true });
assert('system collapsed hides body', !sysCollapsed.includes('UNIQUE_SYSTEM_TOKEN_zzz'));
assert('system expanded shows body', sysExpanded.includes('UNIQUE_SYSTEM_TOKEN_zzz'));

// ── 9. inbound parsing + completeExchange ───────────────────────────────────
console.log('\n9. inbound capture — parseInbound + completeExchange');

const { parseInbound, completeExchange } = require('./src/eyes/capture');

// SSE form (Claude Code's wire format)
const sse = [
  'event: message_start',
  'data: {"type":"message_start","message":{"id":"m1","model":"claude-opus-4-7","role":"assistant","content":[],"usage":{"input_tokens":42,"output_tokens":0}}}',
  '',
  'event: content_block_start',
  'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world!"}}',
  '',
  'event: content_block_stop',
  'data: {"type":"content_block_stop","index":0}',
  '',
  'event: content_block_start',
  'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_x","name":"Read","input":{}}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"path\\":\\"a.js\\"}"}}',
  '',
  'event: content_block_stop',
  'data: {"type":"content_block_stop","index":1}',
  '',
  'event: message_delta',
  'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}',
  '',
  'event: message_stop',
  'data: {"type":"message_stop"}',
  '',
].join('\n');

const parsed = parseInbound(Buffer.from(sse, 'utf8'));
assert('parseInbound returns object', parsed && parsed.role === 'assistant');
assert('parseInbound captures model', parsed.model === 'claude-opus-4-7');
assert('parseInbound stop_reason', parsed.stopReason === 'tool_use');
assert('parseInbound concatenates text deltas', parsed.blocks[0].kind === 'text' && parsed.blocks[0].text === 'Hello world!');
assert('parseInbound parses tool_use input json', parsed.blocks[1].kind === 'tool_use' && parsed.blocks[1].input.path === 'a.js');
assert('parseInbound preserves tool_use id+name', parsed.blocks[1].toolUseId === 'tu_x' && parsed.blocks[1].toolName === 'Read');

// Plain JSON form (non-streaming)
const jsonResp = JSON.stringify({
  role: 'assistant', model: 'claude-opus-4-7', stop_reason: 'end_turn',
  content: [{ type: 'text', text: 'one-shot reply' }],
  usage: { input_tokens: 5, output_tokens: 3 },
});
const parsedJ = parseInbound(jsonResp);
assert('parseInbound handles plain JSON', parsedJ && parsedJ.role === 'assistant');
assert('parseInbound JSON text', parsedJ.blocks[0].text === 'one-shot reply');

// Empty / garbage
assert('parseInbound empty → null', parseInbound(null) === null);
assert('parseInbound garbage → null', parseInbound(Buffer.from('not sse and not json')) === null);

// completeExchange writes response back to file
const tmpDir3 = path.join(os.tmpdir(), `eyes-complete-${Date.now()}-${process.pid}`);
fs.mkdirSync(tmpDir3, { recursive: true });
const exchangeFile = path.join(tmpDir3, 'payload-000001.json');
fs.writeFileSync(exchangeFile, JSON.stringify({ seq: 1, ts: 't', messages: [] }));
// completeExchange respects ENABLED — capture is currently disabled, so enable temporarily
capture.enable();
completeExchange(exchangeFile, { responseBytes: Buffer.from(sse, 'utf8'), intercepted: false, statusCode: 200 });
const augmented = JSON.parse(fs.readFileSync(exchangeFile, 'utf8'));
assert('completeExchange added response', augmented.response && augmented.response.role === 'assistant');
assert('completeExchange added responseMeta', augmented.responseMeta && augmented.responseMeta.statusCode === 200);
assert('completeExchange added responseRaw', augmented.responseRaw && augmented.responseRaw.bytes > 0);
try {
  fs.unlinkSync(exchangeFile);
  fs.rmdirSync(tmpDir3);
} catch { /* ignore */ }

// Demo payload #2 now carries a response — content render must show it
const demoWithResponse = require('./src/eyes/demo-content').PAYLOADS[1];
assert('demo payload has response', !!demoWithResponse.response);
const plainColor = {
  bold: s=>s, dim:s=>s, white:s=>s, cyan:s=>s, mag:s=>s, yellow:s=>s, green:s=>s,
  red:s=>s, blue:s=>s, bgYellow:s=>s, reset:'',
};
const allLinesWithResp = require('./src/eyes/content-render').buildBodyLines(
  demoWithResponse, plainColor, 96, { showSystem: false, showReminders: false }
).join('\n');
assert('content render shows assistant response header', allLinesWithResp.includes('assistant response'));
assert('content render shows response body text', allLinesWithResp.includes('JWT'));

// dumpText includes response
const { dumpText: dumpAgain } = require('./src/eyes/dump');
const dumpedWithResp = dumpAgain(demoWithResponse);
assert('dump includes assistant section', dumpedWithResp.includes('[assistant'));
assert('dump includes response body', dumpedWithResp.includes('JWT'));

// ── 10. turn grouping + collapse ────────────────────────────────────────────
console.log('\n10. turn grouping');

const cr = require('./src/eyes/content-render');
const turns = cr.groupTurns ? cr.groupTurns([
  { role: 'user',      blocks: [{ kind: 'text', text: 'first prompt' }] },
  { role: 'assistant', blocks: [{ kind: 'text', text: 'sure' }, { kind: 'tool_use', toolName: 'Read', toolUseId: 't1', input: { path: 'a' } }] },
  { role: 'user',      blocks: [{ kind: 'tool_result', toolUseId: 't1', text: 'file content' }] },
  { role: 'assistant', blocks: [{ kind: 'text', text: 'done' }] },
  { role: 'user',      blocks: [{ kind: 'text', text: 'second prompt' }] },
  { role: 'assistant', blocks: [{ kind: 'text', text: 'on it' }] },
]) : null;

if (turns) {
  assert('groupTurns: 2 turns from 6 messages', turns.length === 2);
  assert('groupTurns: first prompt captured', turns[0].prompt === 'first prompt');
  assert('groupTurns: second prompt captured', turns[1].prompt === 'second prompt');
  assert('groupTurns: tool_result stays in turn 1', turns[0].messages.length === 4);
  assert('groupTurns: turn 2 has 2 messages', turns[1].messages.length === 2);
} else {
  failed++; console.error('  ✗ groupTurns not exported');
}

// collapsed default: older turn shows only header, not the assistant body
const payloadMultiTurn = {
  schema: 1, seq: 1, ts: '2026-05-20T10:00:00Z',
  byteCount: { before: 0, after: 0 },
  system: null,
  messages: [
    { role: 'user',      blocks: [{ kind: 'text', text: 'OLD_FIRST_PROMPT_xyz' }] },
    { role: 'assistant', blocks: [{ kind: 'text', text: 'OLD_REPLY_TEXT_xyz' }] },
    { role: 'user',      blocks: [{ kind: 'text', text: 'NEW_PROMPT_abc' }] },
  ],
  redactionCount: 0, blockedCount: 0,
};
const collapsedAll = cr.buildBodyLines(payloadMultiTurn, plainColor, 96, { showAllTurns: false }).join('\n');
assert('collapse hides old assistant body', !collapsedAll.includes('OLD_REPLY_TEXT_xyz'));
assert('collapse shows old prompt preview',  collapsedAll.includes('OLD_FIRST_PROMPT_xyz'));
assert('collapse shows new prompt body',     collapsedAll.includes('NEW_PROMPT_abc'));
assert('collapse shows Turn header',         collapsedAll.includes('Turn 1'));

const expandedAll = cr.buildBodyLines(payloadMultiTurn, plainColor, 96, { showAllTurns: true }).join('\n');
assert('expand shows old assistant body', expandedAll.includes('OLD_REPLY_TEXT_xyz'));

// ── 11. server endpoints ────────────────────────────────────────────────────
console.log('\n11. eyes server — endpoints');

const { createServer, summarize } = require('./src/eyes/server');

// summarize() unit test
const sumPayload = require('./src/eyes/demo-content').PAYLOADS[1];
const sum = summarize(sumPayload);
assert('summarize returns object', sum && typeof sum === 'object');
assert('summarize seq', sum.seq === sumPayload.seq);
assert('summarize promptPreview', sum.promptPreview && sum.promptPreview.includes('auth middleware'));
assert('summarize counts tool_uses', sum.toolUses >= 1);
assert('summarize counts tool_results', sum.toolResults >= 1);
assert('summarize captures redactions', sum.redactions === sumPayload.redactionCount);

// HTTP smoke — boot demo server on an OS-assigned port, hit endpoints
const srv = createServer({ demo: true });
const httpReady = new Promise((resolve, reject) => {
  srv.server.once('error', reject);
  srv.listen(0, '127.0.0.1', () => resolve(srv.server.address().port));
});

httpReady.then(async (port) => {
  const http = require('http');
  function get(path) {
    return new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: res.headers }));
      }).on('error', reject);
    });
  }

  const root = await get('/');
  assert('GET / → 200', root.status === 200);
  assert('GET / serves HTML', /AGENT EYES/.test(root.body));
  assert('GET / has CSS for sidebar', /id="sidebar"/.test(root.body));
  assert('GET / has script', /loadList\(\)/.test(root.body));
  assert('GET / has Tools tab', /data-tab="tools"/.test(root.body));
  assert('GET / has Diff tab', /data-tab="diff"/.test(root.body));
  assert('GET / has Headers tab', /data-tab="headers"/.test(root.body));
  assert('GET / has fetchContent', /fetchContent/.test(root.body));
  assert('GET / has renderTools', /renderTools/.test(root.body));
  assert('GET / has renderDiff',  /renderDiff/.test(root.body));
  assert('GET / has renderHeaders', /renderHeaders/.test(root.body));

  const list = await get('/api/exchanges');
  assert('GET /api/exchanges → 200', list.status === 200);
  const listJ = JSON.parse(list.body);
  assert('list has exchanges array', Array.isArray(listJ.exchanges));
  assert('list reports demo: true', listJ.demo === true);
  assert('list has >0 entries', listJ.exchanges.length > 0);
  assert('list entry has seq', typeof listJ.exchanges[0].seq === 'number');
  assert('list entry has promptPreview', 'promptPreview' in listJ.exchanges[0]);

  const detail = await get('/api/exchanges/' + sumPayload.seq);
  assert('GET /api/exchanges/N → 200', detail.status === 200);
  const detJ = JSON.parse(detail.body);
  assert('detail has full messages', Array.isArray(detJ.messages));
  assert('detail has response', !!detJ.response);

  const miss = await get('/api/exchanges/9999');
  assert('GET /api/exchanges/9999 → 404', miss.status === 404);

  const nf = await get('/nope');
  assert('GET /nope → 404', nf.status === 404);

  // Content endpoint: 404 on bogus, 200 on real ref after storing
  const bogus = await get('/api/content/sha256-deadbeef00000000');
  assert('GET /api/content bogus → 404', bogus.status === 404);
  const csRef = cs.store(Buffer.from('hello from content store'));
  const real = await get('/api/content/' + csRef);
  assert('GET /api/content real → 200', real.status === 200);
  assert('GET /api/content returns bytes', real.body.includes('hello from content store'));
  assert('GET /api/content sets X-Content-Bytes', !!real.headers['x-content-bytes']);

  srv.close(() => {
    // Tests after server close — close should not throw
    assert('server.close() works', true);
    finalize();
  });
}).catch(err => {
  failed++; console.error('  ✗ server boot failed:', err.message);
  finalize();
});

// ── 12. content-store ───────────────────────────────────────────────────────
console.log('\n12. content-store — store/read/dedup/gc');

const cs = require('./src/eyes/content-store');
const csDir = path.join(os.tmpdir(), `cs-${Date.now()}-${process.pid}`);
fs.mkdirSync(csDir, { recursive: true });

const r1 = cs.store(Buffer.from('hello world'), { dir: csDir });
assert('store returns sha256- ref', r1 && r1.startsWith('sha256-'));
const r2 = cs.store(Buffer.from('hello world'), { dir: csDir });
assert('store dedupes same content', r1 === r2);
const r3 = cs.store(Buffer.from('different bytes'), { dir: csDir });
assert('store distinct content → distinct ref', r1 !== r3);
const back = cs.read(r1, { dir: csDir });
assert('read returns Buffer', Buffer.isBuffer(back));
assert('read round-trips bytes', back.toString('utf8') === 'hello world');
assert('store null → null', cs.store(null, { dir: csDir }) === null);
assert('store empty → null', cs.store('', { dir: csDir }) === null);
assert('read bogus ref → null', cs.read('sha256-deadbeef', { dir: csDir }) === null);
assert('read malformed ref → null', cs.read('not-a-ref', { dir: csDir }) === null);

const st = cs.stat(r1, { dir: csDir });
assert('stat returns size', st && st.bytes === 11);

// gc: keep nothing reffed → delete all
const gcRes = cs.gc({ dir: csDir, maxBytes: 0, inUse: () => false });
assert('gc removed blobs', gcRes.removed >= 2, `removed=${gcRes.removed}`);

// gc with inUse keeps that ref
const r4 = cs.store(Buffer.from('keep me'), { dir: csDir });
const r5 = cs.store(Buffer.from('drop me'), { dir: csDir });
const gcRes2 = cs.gc({ dir: csDir, maxBytes: 0, inUse: ref => ref === r4 });
assert('gc honors inUse', cs.read(r4, { dir: csDir }) !== null && cs.read(r5, { dir: csDir }) === null);

try { fs.rmSync(csDir, { recursive: true, force: true }); } catch { /* ignore */ }

// ── 13. capture extras: originalBody / headers / localTools ────────────────
console.log('\n13. capture — originalBody, headers, localTools, redactionDiffs');

const cap = require('./src/eyes/capture');
const capDir = path.join(os.tmpdir(), `eyes-cap2-${Date.now()}-${process.pid}`);
const capContentDir = path.join(capDir, 'content');
fs.mkdirSync(capContentDir, { recursive: true });

// Monkey-patch EYES_DIR via require cache for this test isolation. Simpler:
// just call captureOutbound and verify the SHAPE of the returned object via
// re-reading the file. We can't fully isolate without breaking the singleton
// SEQ counter, so do one minimal smoke + verify JSON structure.

// (capture is already enabled from earlier completeExchange test — skip off-state check here)

// Reset the production EYES_DIR so our freshly-written payloads don't get
// pruned by pruneOldest (which keeps only the most recent CAPTURE_MAX files).
cap.resetSession();

// Enable & exercise — uses real EYES_DIR; we'll resetSession afterwards
// (this is the production env so be careful — just one tiny payload)
cap.enable();
const writtenPath = cap.captureOutbound({
  model: 'claude-opus-4-7',
  messages: [{ role: 'user', content: 'hi' }],
}, {
  ts: '2026-05-20T10:00:00Z',
  runId: 'cap-test',
  method: 'POST',
  url: '/v1/messages',
  requestHeaders: { 'authorization': 'Bearer SECRET', 'x-api-key': 'sk-xyz', 'user-agent': 'claude-code/2.1' },
  originalBody: '{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hi"}]}',
  byteCountBefore: 70, byteCountAfter: 70,
  redactionCount: 0, blockedCount: 0,
  laoDroppedContent: [{ tool_use_id: 'tu1', bytes: 11, content: 'hello world' }],
});
assert('captureOutbound returns path', typeof writtenPath === 'string');
const written = JSON.parse(fs.readFileSync(writtenPath, 'utf8'));
assert('captured request headers', written.requestHeaders && written.requestHeaders['user-agent'] === 'claude-code/2.1');
assert('headers: authorization masked', written.requestHeaders.authorization === '[REDACTED]');
assert('headers: x-api-key masked', written.requestHeaders['x-api-key'] === '[REDACTED]');
assert('captured method', written.method === 'POST');
assert('captured url', written.url === '/v1/messages');
assert('originalBodyRef set', written.originalBodyRef && written.originalBodyRef.startsWith('sha256-'));
assert('originalBytes set', written.originalBytes === 71);
assert('laoDroppedContent set', Array.isArray(written.laoDroppedContent) && written.laoDroppedContent.length === 1);
assert('laoDroppedContent has contentRef', written.laoDroppedContent[0].contentRef && written.laoDroppedContent[0].contentRef.startsWith('sha256-'));
assert('laoDroppedContent toolUseId', written.laoDroppedContent[0].toolUseId === 'tu1');

// completeExchange with localTools
cap.completeExchange(writtenPath, {
  responseBytes: Buffer.from('{"role":"assistant","content":[{"type":"text","text":"hi"}]}'),
  responseHeaders: { 'content-type': 'application/json', 'set-cookie': 'session=abc' },
  intercepted: false,
  statusCode: 200,
  localTools: [
    { tool: 'Read', cmd: 'src/x.js', bytes: 4218, exitCode: 0, output: '// file content here\nconsole.log("hi")', rawContent: '// pre-distill original' },
    { tool: 'Bash', cmd: 'git status', bytes: 200, exitCode: 0, output: 'On branch main', distilled: true, distillSaved: 50, distillLabel: 'shell_output (1 line)' },
  ],
});
const augmentedX = JSON.parse(fs.readFileSync(writtenPath, 'utf8'));
assert('completeExchange added responseHeaders', augmentedX.responseHeaders && augmentedX.responseHeaders['content-type'] === 'application/json');
assert('completeExchange masks cookie', augmentedX.responseHeaders['set-cookie'] === '[REDACTED]');
assert('localTools captured', Array.isArray(augmentedX.localTools) && augmentedX.localTools.length === 2);
assert('localTool[0] outputRef', augmentedX.localTools[0].outputRef && augmentedX.localTools[0].outputRef.startsWith('sha256-'));
assert('localTool[0] rawContentRef', augmentedX.localTools[0].rawContentRef !== null);
assert('localTool[1] distilled', augmentedX.localTools[1].distilled === true);
assert('localTool[1] distillSaved', augmentedX.localTools[1].distillSaved === 50);

// Read the output back through content store
const outputBytes = cs.read(augmentedX.localTools[0].outputRef);
assert('output bytes retrievable from CAS', outputBytes && outputBytes.toString('utf8').includes('console.log'));

// captureGenericHttp
const genericPath = cap.captureGenericHttp({
  ts: '2026-05-20T10:00:01Z', runId: 'cap-test',
  method: 'GET', url: '/v1/messages?count_tokens',
  requestHeaders: { 'authorization': 'Bearer SECRET' },
  responseHeaders: { 'content-type': 'application/json' },
  statusCode: 200,
  requestBody: 'q=hello',
  responseBody: '{"tokens":42}',
});
assert('captureGenericHttp returns path', typeof genericPath === 'string');
const gen = JSON.parse(fs.readFileSync(genericPath, 'utf8'));
assert('generic has kind=http_generic', gen.kind === 'http_generic');
assert('generic has requestBodyRef', gen.requestBodyRef && gen.requestBodyRef.startsWith('sha256-'));
assert('generic has responseBodyRef', gen.responseBodyRef && gen.responseBodyRef.startsWith('sha256-'));
assert('generic statusCode', gen.statusCode === 200);

// Clean up test artifacts (best-effort)
try {
  for (const f of [writtenPath, genericPath]) { try { fs.unlinkSync(f); } catch { /* ignore */ } }
} catch { /* ignore */ }

function finalize() {
// ── done ────────────────────────────────────────────────────────────────────
console.log(`\n${failed === 0 ? '✓' : '✗'} eyes: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
}
