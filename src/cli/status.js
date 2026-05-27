// `occasio status` — session summary (cost, savings, coverage, budget).
//
// Phase-4 of the truth-source unification: all counters derive from the
// hash-chained audit log via src/models/events.js. session.json is read
// only for config-y fields (budget, mode, start, model, log_file) — those
// move out in Phase 5 and this file's session.json read disappears.

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { calcCompoundingSavings } = require('../cost/prices');
const { fmtBudget }              = require('../budget');
const {
  loadEvents,
  currentRunId,
  summarize,
  buildToolStats,
  SESSION_FILE,
} = require('../models/events');

const LOG_DIR = path.join(os.homedir(), '.occasio');

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function getLogFile() { return path.join(LOG_DIR, 'logs', `${todayStr()}.jsonl`); }

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function run() {
  // session.json provides config-only fields during the transition:
  // budget, mode, start, model, log_file. All COUNTERS come from chain.
  let cfg = null;
  try { cfg = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch { /* none */ }

  console.log(col.b('\n⚡ Occasio\n'));

  const runId = currentRunId();
  if (!runId && !cfg) {
    console.log(col.d('  No session data yet. Run: occasio claude\n'));
    return;
  }

  // Pull every counter from the chain — single source of truth.
  const requestEvents = runId ? loadEvents({ kind: 'request',   runId }) : [];
  const toolEvents    = runId ? loadEvents({ kind: 'tool_call', runId }) : [];
  const acct  = summarize(requestEvents);
  const tools = buildToolStats(toolEvents);

  const cacheSav = acct.cache_savings;
  const laoSav   = acct.lao_cost_saved;
  const distSav  = acct.distill_cost_saved;
  const payload  = laoSav + distSav;
  // Compounding savings still derive from the JSONL log file (cross-request
  // context-reentry effect). Migrating that calculator to the chain is a
  // Phase-5 item; today's status continues to source it as before.
  const { savings: context } =
    calcCompoundingSavings(runId, cfg?.log_file || getLogFile(), cfg?.model || '');
  const totalSav  = payload + context + cacheSav;
  const broaderCf = acct.cost + totalSav;
  const savedPct  = broaderCf > 0.00001 ? Math.round(totalSav / broaderCf * 100) : 0;

  // Headline
  if (totalSav > 0.00001) {
    console.log(col.g(`  Saved:       $${totalSav.toFixed(4)}`) +
      col.d(`  (${savedPct}% off — would have cost $${broaderCf.toFixed(4)})`));
  } else {
    console.log(col.d(`  Saved:       $0.0000  (no interceptable tool calls in this session yet)`));
  }
  console.log(col.y(`  Cost:        $${acct.cost.toFixed(4)}`));

  // Coverage — same clamp logic as before to keep the displayed ratio 0–100%.
  const totalLocal = acct.tools_local_count + acct.tools_mcp_count;
  const denom      = Math.max(acct.tools_attempted, totalLocal);
  if (denom > 0) {
    const cpct = Math.round(totalLocal / denom * 100);
    const cColor = cpct >= 80 ? col.g : cpct >= 50 ? col.y : col.r;
    console.log(cColor(`  Ran locally: ${totalLocal} of ${denom} tool calls (${cpct}%)`));
  }

  if (acct.blocked) console.log(col.r(`  Blocked:     ${acct.blocked} secrets`));
  if (tools.secrets_redacted) {
    console.log(col.c(`  Redacted:    ${tools.secrets_redacted} secret${tools.secrets_redacted !== 1 ? 's' : ''} in tool results`));
  }
  if (tools.transformed) {
    console.log(col.c(`  Transforms:  ${tools.transformed} tool result${tools.transformed !== 1 ? 's' : ''} shaped`));
  }
  if (cfg?.budget != null) {
    const pct = Math.min(999, Math.round(acct.cost / cfg.budget * 100));
    const budgetStr = fmtBudget(acct.cost, cfg.budget);
    const budgetColor = pct >= 100 ? col.r : pct >= 80 ? col.y : col.g;
    console.log(budgetColor(`  Budget:      ${budgetStr}`));
    if (acct.budget_exceeded) {
      console.log(col.r(`  BudgetBlk:   ${acct.budget_exceeded} request(s) blocked`));
    }
  }

  // Detail
  console.log(col.d(`  ────`));
  console.log(col.d(`  Requests:    ${acct.requests} · ${(acct.input_tokens/1000).toFixed(1)}k tokens in · ${(acct.output_tokens/1000).toFixed(1)}k out`));
  if (totalSav > 0.00001) {
    const parts = [];
    if (payload  > 0.00001) parts.push(`$${payload.toFixed(4)} payload`);
    if (context  > 0.00001) parts.push(`$${context.toFixed(4)} context`);
    if (cacheSav > 0.00001) parts.push(`$${cacheSav.toFixed(4)} cache`);
    if (parts.length) console.log(col.d(`  Breakdown:   ${parts.join(' + ')}`));
  }
  const tail = [];
  if (cfg?.mode)  tail.push(`Mode: ${cfg.mode}`);
  if (cfg?.start) tail.push(`Since: ${new Date(cfg.start).toLocaleString()}`);
  if (tail.length) console.log(col.d(`  ${tail.join('   ·   ')}`));
  console.log('');
}

module.exports = { run };
