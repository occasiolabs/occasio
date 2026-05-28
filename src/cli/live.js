'use strict';

/**
 * occasio live: watch the active session in real time.
 *
 * Opens the chain file at ~/.occasio/pipeline-events.jsonl, tails it, and
 * re-renders a compact dashboard on every append. Intended to run in a
 * second terminal beside `occasio claude`.
 *
 * No new dependency. Uses fs.watch on the chain file plus a small
 * ANSI-cursor-position dance to redraw in place.
 *
 * Exits cleanly on Ctrl-C.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const {
  loadEvents, summarize, buildToolStats, currentRunId, CHAIN_FILE,
} = require('../models/events');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

const CLEAR_SCREEN = '\x1b[2J\x1b[H';

function shortTs(iso) { return iso ? iso.slice(11, 19) : '        '; }

function actionColor(a) {
  if (a === 'BLOCK')     return col.r;
  if (a === 'TRANSFORM') return col.c;
  if (a === 'LOCAL')     return col.g;
  if (a === 'PASS')      return col.d;
  return col.d;
}

function render() {
  const out = [];
  const runId = currentRunId();
  out.push(col.b('⚡ Occasio live') + col.d('   (Ctrl-C to exit)'));
  out.push('');
  if (!runId) {
    out.push(col.d('  No active run. Start one with: occasio claude'));
    out.push('');
    return out.join('\n');
  }

  const reqEvents  = loadEvents({ kind: 'request',   runId });
  const toolEvents = loadEvents({ kind: 'tool_call', runId });
  const acct  = summarize(reqEvents);
  const tools = buildToolStats(toolEvents);

  out.push(col.b('  run: ') + runId);
  out.push('');
  out.push(col.b('  Counters'));
  out.push(`    ${col.d('cost      ')} ${col.y('$' + acct.cost.toFixed(4))}`);
  out.push(`    ${col.d('requests  ')} ${acct.requests}`);
  out.push(`    ${col.d('tools     ')} ${tools.total} (` +
           `local: ${col.g(tools.local)}, ` +
           `cloud: ${tools.pass}, ` +
           `blocked: ${col.r(tools.blocked)}, ` +
           `shaped: ${col.c(tools.transformed)})`);
  if (tools.secrets_redacted) {
    out.push(`    ${col.d('secrets   ')} ${col.c(tools.secrets_redacted)} redacted`);
  }
  out.push('');

  const recent = loadEvents({ runId }).slice(-12);
  out.push(col.b('  Last 12 chain events'));
  if (!recent.length) {
    out.push(col.d('    (none yet)'));
  } else {
    for (const e of recent) {
      const tc = actionColor(e.action || '');
      const kind = (e.kind || '').padEnd(13);
      const tool = (e.tool_name || e.event_type || '').padEnd(18).slice(0, 18);
      const act  = e.action ? tc(e.action) : '';
      out.push(`    ${col.d(shortTs(e.ts))}  ${col.d(kind)}  ${tool}  ${act}`);
    }
  }
  out.push('');
  out.push(col.d(`  last redraw: ${new Date().toLocaleTimeString()}`));
  out.push('');
  return out.join('\n');
}

function run() {
  process.stdout.write(CLEAR_SCREEN + render());

  let pending = false;
  const redraw = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => {
      pending = false;
      process.stdout.write(CLEAR_SCREEN + render());
    }, 100);
  };

  let watcher;
  try {
    // fs.watch can throw on missing file; create the parent dir if absent
    const dir = path.dirname(CHAIN_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // Touch the chain file if missing so the watcher has something to attach to.
    if (!fs.existsSync(CHAIN_FILE)) fs.writeFileSync(CHAIN_FILE, '');
    watcher = fs.watch(CHAIN_FILE, { persistent: true }, () => redraw());
  } catch (e) {
    process.stderr.write(`occasio live: cannot watch ${CHAIN_FILE}: ${e.message}\n`);
    return 1;
  }

  // Periodic redraw so the "last redraw" timestamp and any session.json change
  // refresh even if no chain append happens for a while.
  const interval = setInterval(redraw, 5000);

  const cleanup = () => {
    clearInterval(interval);
    try { watcher.close(); } catch { /* ignore */ }
    process.stdout.write('\n');
    process.exit(0);
  };
  process.on('SIGINT',  cleanup);
  process.on('SIGTERM', cleanup);
  // Keep event loop alive
}

module.exports = { run, render };
