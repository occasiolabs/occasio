// `occasio` with no args prints a unified live snapshot of the active run:
// pointer config, accounting totals, tool-call breakdown, the last five chain
// events, and an anomaly count for the last fifteen minutes. The proxy is not
// launched. To start a session use `occasio claude`.
//
// Every counter is read from the hash-chained audit log via src/models/events.js.
// session.json contributes only config-y fields (mode, budget, model, start, cwd).

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const {
  loadEvents,
  currentRunId,
  summarize,
  buildToolStats,
  SESSION_FILE,
} = require('../models/events');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

const LOG_DIR = path.join(os.homedir(), '.occasio');

function readConfig() {
  try { return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); }
  catch { return null; }
}

function fmtTime(iso) {
  if (!iso) return '';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function shortTs(iso) {
  if (!iso) return '';
  return iso.slice(11, 19);
}

function render() {
  const out = [];
  const push = line => out.push(line);

  const cfg   = readConfig();
  const runId = currentRunId();

  push(col.b('\n⚡ Occasio'));
  push('');

  if (!runId && !cfg) {
    push(col.d('  No session data yet.'));
    push(col.d('  Start one with:  occasio claude'));
    push('');
    return out.join('\n');
  }

  // ── Active run ───────────────────────────────────────────────────────────
  push(col.b('  Active run'));
  if (runId) push(`    ${col.d('run_id  ')} ${runId}`);
  if (cfg?.start)  push(`    ${col.d('started ')} ${fmtTime(cfg.start)}`);
  if (cfg?.cwd)    push(`    ${col.d('cwd     ')} ${cfg.cwd}`);
  if (cfg?.mode)   push(`    ${col.d('mode    ')} ${cfg.mode}`);
  if (cfg?.model)  push(`    ${col.d('model   ')} ${cfg.model}`);
  if (cfg?.budget != null) push(`    ${col.d('budget  ')} $${Number(cfg.budget).toFixed(4)}`);
  push('');

  // ── Accounting (this run) ────────────────────────────────────────────────
  const requestEvents = runId ? loadEvents({ kind: 'request',   runId }) : [];
  const toolEvents    = runId ? loadEvents({ kind: 'tool_call', runId }) : [];
  const acct          = summarize(requestEvents);
  const tools         = buildToolStats(toolEvents);

  push(col.b('  Accounting'));
  push(`    ${col.d('cost    ')} ${col.y('$' + acct.cost.toFixed(4))}`);
  push(`    ${col.d('requests')} ${acct.requests}`);
  push(`    ${col.d('tokens  ')} ${(acct.input_tokens/1000).toFixed(1)}k in, ${(acct.output_tokens/1000).toFixed(1)}k out`);
  const totalSaved = acct.cache_savings + acct.lao_cost_saved + acct.distill_cost_saved;
  if (totalSaved > 0.00001) {
    push(`    ${col.d('saved   ')} ${col.g('$' + totalSaved.toFixed(4))}`);
  }
  push('');

  // ── Tools (this run) ─────────────────────────────────────────────────────
  push(col.b('  Tools'));
  const totalLocal = acct.tools_local_count + acct.tools_mcp_count;
  const denom = Math.max(acct.tools_attempted, totalLocal);
  if (denom > 0) {
    const pct = Math.round(totalLocal / denom * 100);
    const cColor = pct >= 80 ? col.g : pct >= 50 ? col.y : col.r;
    push(`    ${col.d('local   ')} ${cColor(totalLocal + ' of ' + denom + ' (' + pct + '%)')}`);
  } else {
    push(`    ${col.d('local   ')} 0`);
  }
  if (acct.blocked)            push(`    ${col.d('blocked ')} ${col.r(acct.blocked)}`);
  if (tools.transformed)       push(`    ${col.d('shaped  ')} ${col.c(tools.transformed)}`);
  if (tools.secrets_redacted)  push(`    ${col.d('secrets ')} ${col.c(tools.secrets_redacted)} redacted in tool results`);
  if (acct.budget_exceeded)    push(`    ${col.d('budget  ')} ${col.r(acct.budget_exceeded)} request(s) blocked`);
  push('');

  // ── Last 5 chain events ──────────────────────────────────────────────────
  push(col.b('  Last 5 chain events'));
  const recent = runId ? loadEvents({ runId }).slice(-5) : loadEvents({}).slice(-5);
  if (!recent.length) {
    push(col.d('    (none yet)'));
  } else {
    for (const e of recent) {
      const ts   = shortTs(e.ts);
      const kind = (e.kind || '').padEnd(13);
      const tool = e.tool_name || e.event_type || '';
      const act  = e.action || '';
      const actColor =
        act === 'BLOCK'     ? col.r :
        act === 'TRANSFORM' ? col.c :
        act === 'LOCAL'     ? col.g :
        act === 'PASS'      ? col.d : col.d;
      push(`    ${col.d(ts)}  ${col.d(kind)}  ${tool.padEnd(20)}  ${act ? actColor(act) : ''}`);
    }
  }
  push('');

  // ── Anomalies (last 15 minutes) ──────────────────────────────────────────
  push(col.b('  Anomalies (last 15 minutes)'));
  try {
    const sinceIso = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const recentForAnom = loadEvents({ since: sinceIso });
    let anomalies = null;
    try {
      const anomMod = require('../anomaly');
      if (anomMod && typeof anomMod.detectAll === 'function') {
        const res = anomMod.detectAll(recentForAnom);
        anomalies = Array.isArray(res) ? res : (res && res.findings) || null;
      } else if (anomMod && typeof anomMod.run === 'function') {
        const res = anomMod.run(recentForAnom);
        anomalies = Array.isArray(res) ? res : (res && res.findings) || null;
      }
    } catch { /* anomaly module unavailable; fall through */ }

    if (anomalies === null) {
      push(col.d(`    (not computed inline, run: occasio anomalies)`));
    } else if (!anomalies.length) {
      push(col.d('    none in window'));
    } else {
      const bySev = { HIGH: 0, MEDIUM: 0, LOW: 0 };
      for (const a of anomalies) {
        const sev = (a && a.severity) || 'LOW';
        bySev[sev] = (bySev[sev] || 0) + 1;
      }
      const parts = [];
      if (bySev.HIGH)   parts.push(col.r(`${bySev.HIGH} high`));
      if (bySev.MEDIUM) parts.push(col.y(`${bySev.MEDIUM} medium`));
      if (bySev.LOW)    parts.push(col.d(`${bySev.LOW} low`));
      push(`    ${parts.join(', ') || col.d('none in window')}`);
    }
  } catch {
    push(col.d('    (unavailable, run: occasio anomalies)'));
  }
  push('');

  // ── Footer hints ─────────────────────────────────────────────────────────
  push(col.d('  Next:'));
  push(col.d('    occasio claude              start a new session'));
  push(col.d('    occasio status              full session summary'));
  push(col.d('    occasio replay --detail     per-run audit'));
  push(col.d('    occasio doctor              setup health check'));
  push('');

  return out.join('\n');
}

function run() {
  process.stdout.write(render());
}

module.exports = { run, render };
