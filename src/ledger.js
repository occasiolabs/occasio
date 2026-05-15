'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

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

function readDayLog(dateStr) {
  const logFile = path.join(LOG_DIR, 'logs', `${dateStr}.jsonl`);
  if (!fs.existsSync(logFile)) return [];
  const lines = fs.readFileSync(logFile, 'utf8').split('\n');
  const result = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    try { result.push(JSON.parse(line)); } catch { /* ignore */ }
  }
  return result;
}

// Filter entries to those at or after sessionStart (ISO string).
// Uses entry.iso when available; falls back to HH:MM:SS string comparison.
function readSessionEntries(entries, sessionStart) {
  if (!sessionStart || !entries.length) return entries;
  const startHms = new Date(sessionStart).toTimeString().slice(0, 8);
  const filtered = entries.filter(e => {
    if (e.iso) return e.iso >= sessionStart;
    return (e.ts || '') >= startHms;
  });
  return filtered.length > 0 ? filtered : entries;
}

// Aggregate totals from a list of log entries.
// Handles both new entries (event_type field) and old entries (intercepted flag).
function summarize(entries) {
  const t = {
    requests: 0, cloud_sent: 0, local_only: 0, blocked: 0, trimmed: 0,
    budget_exceeded: 0,
    input_tokens: 0, output_tokens: 0,
    cache_read_tokens: 0, cache_write_tokens: 0,
    cost: 0, cache_savings: 0, lao_cost_saved: 0, lao_tokens_saved: 0,
    distill_cost_saved: 0, distill_tokens_saved: 0,
    tools_local_count: 0,
  };
  for (const e of entries) {
    t.requests++;
    const et = e.event_type || (e.intercepted ? 'local_only' : 'cloud_sent');
    if (et === 'cloud_sent')           t.cloud_sent++;
    else if (et === 'local_only')      t.local_only++;
    else if (et === 'blocked')         t.blocked++;
    else if (et === 'trimmed')         t.trimmed++;
    else if (et === 'budget_exceeded') t.budget_exceeded++;
    t.input_tokens          += e.input_tokens          || 0;
    t.output_tokens         += e.output_tokens         || 0;
    t.cache_read_tokens     += e.cache_read_tokens     || 0;
    t.cache_write_tokens    += e.cache_write_tokens    || 0;
    t.cost                  += e.cost                  || 0;
    t.cache_savings         += e.cache_savings         || 0;
    t.lao_cost_saved        += e.lao_cost_saved        || 0;
    t.lao_tokens_saved      += e.lao_tokens_saved      || 0;
    t.distill_cost_saved    += e.distill_cost_saved    || 0;
    t.distill_tokens_saved  += e.distill_tokens_saved  || 0;
    t.tools_local_count     += e.tools_local_count     || 0;
  }
  return t;
}

function fmtN(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'k';
  return String(n || 0);
}

function eventCol(et) {
  switch (et) {
    case 'cloud_sent':      return col.c('cloud_sent ');
    case 'local_only':      return col.g('local_only ');
    case 'blocked':         return col.r('blocked    ');
    case 'trimmed':         return col.y('trimmed    ');
    case 'budget_exceeded': return col.r('budget_exc ');
    default:                return col.d((et || 'unknown').padEnd(11));
  }
}

function resolveEventType(e) {
  return e.event_type || (e.intercepted ? 'local_only' : 'cloud_sent');
}

function printEntry(e, idx) {
  const ts    = e.ts || '??:??:??';
  const model = (e.model || '—').replace('claude-', '').replace(/-\d{8}$/, '');
  const inp   = fmtN(e.input_tokens  || 0).padStart(7);
  const out   = fmtN(e.output_tokens || 0).padStart(5);
  const cost  = `$${(e.cost || 0).toFixed(4)}`;
  const et    = resolveEventType(e);

  let extra = '';
  if ((e.tools_local_count || 0) > 0) extra += col.d(` · ${e.tools_local_count} tools local`);
  if ((e.lao_tokens_saved  || 0) > 0) extra += col.d(` · ${fmtN(e.lao_tokens_saved)} trimmed`);
  if (et === 'blocked' && e.secrets?.length > 0)  extra += col.r(` · 🛑 ${e.secrets[0].label || 'secret'}`);
  if (et !== 'blocked' && e.secrets?.length > 0)  extra += col.y(` · ⚠ ${e.secrets[0].label || 'secret'}`);

  const idxStr = idx !== undefined ? col.d(`${String(idx + 1).padStart(4)}. `) : '      ';
  console.log(`${idxStr}${col.d(ts)}  ${eventCol(et)}  ${col.d(model.padEnd(16))}  ${col.y(inp)} in /${col.y(out)} out  ${col.g(cost)}${extra}`);
}

function printSummary(totals, scope, runId) {
  const { requests, cloud_sent = 0, local_only = 0, blocked = 0, trimmed = 0,
          input_tokens, output_tokens, cost,
          cache_savings, lao_cost_saved, distill_cost_saved = 0,
          distill_tokens_saved = 0, tools_local_count } = totals;
  const saved = (cache_savings || 0) + (lao_cost_saved || 0) + distill_cost_saved;

  console.log(col.b(`\n⚡ Occasio Ledger  —  Summary`));
  if (runId) console.log(col.d(`   run: ${runId}`));
  console.log(col.d(`   scope: ${scope}\n`));

  console.log(`  ${col.b('Requests'.padEnd(16))}  ${requests}`);
  console.log(`  ${col.d('  cloud_sent'.padEnd(16))}  ${cloud_sent}`);
  if (trimmed)  console.log(`  ${col.d('  trimmed'.padEnd(16))}  ${trimmed}`);
  console.log(`  ${col.d('  local_only'.padEnd(16))}  ${local_only}`);
  if (blocked)          console.log(`  ${col.d('  blocked'.padEnd(16))}  ${blocked}`);
  if (totals.budget_exceeded) console.log(`  ${col.r('  budget_exc'.padEnd(16))}  ${totals.budget_exceeded}`);

  console.log(`\n  ${col.b('Tokens in'.padEnd(16))}  ${fmtN(input_tokens || 0)}`);
  console.log(`  ${col.b('Tokens out'.padEnd(16))}  ${fmtN(output_tokens || 0)}`);
  console.log(col.y(`  ${'Cost'.padEnd(18)}  $${(cost || 0).toFixed(4)}`));

  if (saved > 0.00001) {
    const parts = [];
    if ((cache_savings       || 0) > 0.00001) parts.push(`cache $${cache_savings.toFixed(4)}`);
    if ((lao_cost_saved      || 0) > 0.00001) parts.push(`LAO $${lao_cost_saved.toFixed(4)}`);
    if (distill_cost_saved        > 0.00001)  parts.push(`distill $${distill_cost_saved.toFixed(4)}`);
    console.log(col.g(`  ${'Saved'.padEnd(18)}  $${saved.toFixed(4)}`) + col.d(` (${parts.join(' + ')})`));
  }

  if ((tools_local_count || 0) > 0) console.log(col.g(`  ${'Tools local'.padEnd(18)}  ${tools_local_count}`));
  if (distill_tokens_saved > 0) console.log(col.c(`  ${'Distilled'.padEnd(18)}  ${fmtN(distill_tokens_saved)} tokens saved across tool outputs`));
  console.log('');
}

function runLedgerCli(args) {
  let scope       = 'session';
  let limit       = 10;
  let showSummary = false;

  const scopeIdx = args.indexOf('--scope');
  if (scopeIdx >= 0) scope = args[scopeIdx + 1] || 'session';

  const lastIdx = args.indexOf('--last');
  if (lastIdx >= 0) limit = parseInt(args[lastIdx + 1], 10) || 10;

  if (args.includes('--summary')) showSummary = true;

  let session = null;
  try { session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch { /* ignore */ }

  const todayEntries = readDayLog(todayStr());
  const entries = scope === 'session'
    ? readSessionEntries(todayEntries, session?.start)
    : todayEntries;

  const runId = session?.run_id || null;

  if (showSummary) {
    printSummary(summarize(entries), scope, runId);
    return;
  }

  // List view
  console.log(col.b(`\n⚡ Occasio Ledger`));
  let headerLine = '';
  if (runId) headerLine += col.d(`run: ${runId}`);
  if (session?.start) headerLine += col.d(`${runId ? '  ·  ' : ''}started ${new Date(session.start).toTimeString().slice(0, 8)}`);
  if (headerLine) console.log(`   ${headerLine}`);
  console.log(col.d(`   scope: ${scope}  ·  ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} total\n`));

  if (!entries.length) {
    console.log(col.d('   No entries yet. Run: occasio claude\n'));
    return;
  }

  const slice  = entries.slice(-limit);
  const offset = entries.length - slice.length;
  slice.forEach((e, i) => printEntry(e, offset + i));
  console.log('');

  if (entries.length > limit) {
    console.log(col.d(`   Showing last ${limit} of ${entries.length}  ·  --last ${entries.length} for all  ·  --summary for totals\n`));
  } else {
    console.log(col.d(`   ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}  ·  --summary for totals  ·  --scope today for full day\n`));
  }
}

module.exports = { readDayLog, readSessionEntries, summarize, runLedgerCli };
