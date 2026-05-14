// `occasio status` — session summary (cost, savings, coverage, budget).
// Read-only against ~/.occasio/session.json + today's JSONL log.

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { calcCompoundingSavings } = require('../cost/prices');
const { fmtBudget }              = require('../budget');

const LOG_DIR      = path.join(os.homedir(), '.occasio');
const SESSION_FILE = path.join(LOG_DIR, 'session.json');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function getLogFile() { return path.join(LOG_DIR, 'logs', `${todayStr()}.jsonl`); }

function run() {
  let s = null; try { s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch {}
  console.log(col.b('\n⚡ Occasio\n'));
  if (!s) { console.log(col.d('  No session data yet. Run: occasio claude\n')); return; }

  const cacheSav  = s.cache_savings      || 0;
  const laoSav    = s.lao_cost_saved     || 0;
  const distSav   = s.distill_cost_saved || 0;
  const payload   = laoSav + distSav;
  const { savings: context } =
    calcCompoundingSavings(s.run_id, s.log_file || getLogFile(), s.model || '');
  const totalSav  = payload + context + cacheSav;
  const broaderCf = (s.cost || 0) + totalSav;
  const savedPct  = broaderCf > 0.00001 ? Math.round(totalSav / broaderCf * 100) : 0;

  // Headline
  if (totalSav > 0.00001) {
    console.log(col.g(`  Saved:       $${totalSav.toFixed(4)}`) +
      col.d(`  (${savedPct}% off — would have cost $${broaderCf.toFixed(4)})`));
  } else {
    console.log(col.d(`  Saved:       $0.0000  (no interceptable tool calls in this session yet)`));
  }
  console.log(col.y(`  Cost:        $${s.cost.toFixed(4)}`));

  // Plain-English coverage. Defensive: legacy sessions (pre-multi-round-fix)
  // may have tools_attempted undercounted relative to tools_local_count.
  // We clamp the denominator to at least the numerator so the displayed
  // ratio is always 0–100% and never reads "X of Y < X (>100%)".
  const localCnt   = s.tools_local_count || 0;
  const mcpCnt     = s.tools_mcp_count   || 0;
  const attempted  = s.tools_attempted   || 0;
  const totalLocal = localCnt + mcpCnt;
  const denom      = Math.max(attempted, totalLocal);
  if (denom > 0) {
    const cpct = Math.round(totalLocal / denom * 100);
    const cColor = cpct >= 80 ? col.g : cpct >= 50 ? col.y : col.r;
    console.log(cColor(`  Ran locally: ${totalLocal} of ${denom} tool calls (${cpct}%)`));
  }
  if (s.blocked) console.log(col.r(`  Blocked:     ${s.blocked} secrets`));
  if (s.secrets_redacted) console.log(col.c(`  Redacted:    ${s.secrets_redacted} secret${s.secrets_redacted !== 1 ? 's' : ''} in tool results`));
  if (s.tools_transformed) console.log(col.c(`  Transforms:  ${s.tools_transformed} tool result${s.tools_transformed !== 1 ? 's' : ''} shaped`));
  if (s.budget != null) {
    const pct = Math.min(999, Math.round((s.cost || 0) / s.budget * 100));
    const budgetStr = fmtBudget(s.cost || 0, s.budget);
    const budgetColor = pct >= 100 ? col.r : pct >= 80 ? col.y : col.g;
    console.log(budgetColor(`  Budget:      ${budgetStr}`));
    if (s.budget_exceeded_count) console.log(col.r(`  BudgetBlk:   ${s.budget_exceeded_count} request(s) blocked`));
  }

  // Detail
  console.log(col.d(`  ────`));
  console.log(col.d(`  Requests:    ${s.requests} · ${(s.input_tokens/1000).toFixed(1)}k tokens in · ${(s.output_tokens/1000).toFixed(1)}k out`));
  if (totalSav > 0.00001) {
    const parts = [];
    if (payload  > 0.00001) parts.push(`$${payload.toFixed(4)} payload`);
    if (context  > 0.00001) parts.push(`$${context.toFixed(4)} context`);
    if (cacheSav > 0.00001) parts.push(`$${cacheSav.toFixed(4)} cache`);
    if (parts.length) console.log(col.d(`  Breakdown:   ${parts.join(' + ')}`));
  }
  const tail = [];
  if (s.mode)  tail.push(`Mode: ${s.mode}`);
  if (s.start) tail.push(`Since: ${new Date(s.start).toLocaleString()}`);
  if (tail.length) console.log(col.d(`  ${tail.join('   ·   ')}`));
  console.log('');
}

module.exports = { run };
