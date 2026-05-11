'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const LOG_DIR = path.join(os.homedir(), '.localfirst');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

// Group entries by run_id, sorted by iso within each run.
// Entries without a run_id are placed under the key 'legacy'.
function groupByRun(entries) {
  const map = new Map();
  for (const e of entries) {
    const key = e.run_id || 'legacy';
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(e);
  }
  for (const [, arr] of map) {
    arr.sort((a, b) => {
      const ai = a.iso || a.ts || '';
      const bi = b.iso || b.ts || '';
      return ai < bi ? -1 : ai > bi ? 1 : 0;
    });
  }
  return map;
}

// Aggregate per-run stats from a sorted array of entries.
function buildRunStats(runEntries) {
  const zero = {
    count: 0, cloud_sent: 0, local_only: 0, blocked: 0, trimmed: 0, budget_exceeded: 0,
    input_tokens: 0, output_tokens: 0, cost: 0,
    cache_savings: 0, lao_cost_saved: 0, lao_tokens_saved: 0,
    distill_cost_saved: 0, distill_tokens_saved: 0,
    tools_local_count: 0,
    start: null, end: null, durationMs: 0,
  };
  if (!runEntries || !runEntries.length) return zero;

  const stats = { ...zero };
  for (const e of runEntries) {
    stats.count++;
    const et = e.event_type || (e.intercepted ? 'local_only' : 'cloud_sent');
    if      (et === 'cloud_sent')      stats.cloud_sent++;
    else if (et === 'local_only')      stats.local_only++;
    else if (et === 'blocked')         stats.blocked++;
    else if (et === 'trimmed')         stats.trimmed++;
    else if (et === 'budget_exceeded') stats.budget_exceeded++;

    stats.input_tokens         += e.input_tokens         || 0;
    stats.output_tokens        += e.output_tokens        || 0;
    stats.cost                 += e.cost                 || 0;
    stats.cache_savings        += e.cache_savings        || 0;
    stats.lao_cost_saved       += e.lao_cost_saved       || 0;
    stats.lao_tokens_saved     += e.lao_tokens_saved     || 0;
    stats.distill_cost_saved   += e.distill_cost_saved   || 0;
    stats.distill_tokens_saved += e.distill_tokens_saved || 0;
    stats.tools_local_count    += e.tools_local_count    || 0;

    const ts = e.iso || null;
    if (ts) {
      if (!stats.start || ts < stats.start) stats.start = ts;
      if (!stats.end   || ts > stats.end)   stats.end   = ts;
    }
  }
  if (stats.start && stats.end) {
    stats.durationMs = new Date(stats.end) - new Date(stats.start);
  }
  return stats;
}

function fmtN(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n || 0);
}

function fmtDuration(ms) {
  if (!ms || ms < 1000) return '<1s';
  const totalSecs = Math.floor(ms / 1000);
  const m = Math.floor(totalSecs / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${totalSecs % 60}s`;
  return `${totalSecs}s`;
}

function shortId(runId) {
  if (!runId || runId === 'legacy') return runId || 'legacy';
  return runId.slice(0, 8) + '…';
}

function eventTypeLabel(et) {
  switch (et) {
    case 'cloud_sent':      return col.c('cloud_sent ');
    case 'local_only':      return col.g('local_only ');
    case 'blocked':         return col.r('blocked    ');
    case 'trimmed':         return col.y('trimmed    ');
    case 'budget_exceeded': return col.r('budget_exc ');
    default:                return col.d(((et || 'unknown')).padEnd(11));
  }
}

function resolveEventType(e) {
  return e.event_type || (e.intercepted ? 'local_only' : 'cloud_sent');
}

function printRunHeader(runId, stats) {
  const id    = shortId(runId);
  const start = stats.start ? new Date(stats.start).toTimeString().slice(0, 8) : '?';
  const end   = stats.end   ? new Date(stats.end).toTimeString().slice(0, 8)   : '?';
  const dur   = fmtDuration(stats.durationMs);

  const evParts = [];
  if (stats.cloud_sent)      evParts.push(col.c(`${stats.cloud_sent} cloud`));
  if (stats.local_only)      evParts.push(col.g(`${stats.local_only} local`));
  if (stats.trimmed)         evParts.push(col.y(`${stats.trimmed} trimmed`));
  if (stats.blocked)         evParts.push(col.r(`${stats.blocked} blocked`));
  if (stats.budget_exceeded) evParts.push(col.r(`${stats.budget_exceeded} budget_exc`));

  const saved = (stats.cache_savings || 0) + (stats.lao_cost_saved || 0) + (stats.distill_cost_saved || 0);
  const costStr  = col.y(`$${stats.cost.toFixed(4)}`);
  const savedStr = saved > 0.00001 ? col.g(`  saved $${saved.toFixed(4)}`) : '';
  const tokenStr = col.d(`${fmtN(stats.input_tokens)} in / ${fmtN(stats.output_tokens)} out`);

  console.log(`\n  ${col.b('──')} Run ${col.b(id)}  ${col.d(`${start} → ${end}  (${dur})`)}  ${col.b('──')}`);
  console.log(`     ${stats.count} event${stats.count === 1 ? '' : 's'}:  ${evParts.join(col.d('  \xb7  '))}  ${col.d('\xb7')}  ${tokenStr}`);
  console.log(`     ${costStr}${savedStr}`);
}

function printRunDetail(runId, entries) {
  const stats = buildRunStats(entries);
  const id    = shortId(runId);
  const start = stats.start ? new Date(stats.start).toISOString() : '?';
  const end   = stats.end   ? new Date(stats.end).toISOString()   : '?';
  const dur   = fmtDuration(stats.durationMs);

  console.log(col.b(`\n⚡ LocalFirst Replay  —  Run ${id}`));
  if (runId && runId !== 'legacy') console.log(col.d(`   run_id: ${runId}`));
  console.log(col.d(`   ${start}  →  ${end}  (${dur})\n`));

  entries.forEach((e, i) => {
    const ts    = e.ts || (e.iso ? new Date(e.iso).toTimeString().slice(0, 8) : '??:??:??');
    const et    = resolveEventType(e);
    const model = (e.model || '—').replace('claude-', '').replace(/-\d{8}$/, '');
    const inp   = fmtN(e.input_tokens  || 0).padStart(7);
    const out   = fmtN(e.output_tokens || 0).padStart(5);
    const cost  = `$${(e.cost || 0).toFixed(4)}`;
    const idxStr = col.d(`${String(i + 1).padStart(4)}. `);

    let extra = '';
    if ((e.tools_local_count || 0) > 0) {
      const names = (e.tools || []).map(t => t.tool).filter(Boolean).slice(0, 3).join(', ');
      extra += col.d(` \xb7 ${e.tools_local_count} tools local${names ? ` (${names})` : ''}`);
    }
    if ((e.distill_tokens_saved || 0) > 0) extra += col.y(` \xb7 ✂ ${fmtN(e.distill_tokens_saved)} distilled`);
    if ((e.lao_tokens_saved     || 0) > 0) extra += col.c(` \xb7 ✂ LAO ${fmtN(e.lao_tokens_saved)}`);
    if (et === 'blocked' && (e.secrets || []).length > 0)   extra += col.r(` \xb7 🛑 ${e.secrets[0].label || 'secret'}`);
    if (et !== 'blocked' && (e.secrets || []).length > 0)  extra += col.y(` \xb7 ⚠ ${e.secrets[0].label || 'secret'}`);
    if ((e.blocked || []).length > 0)                      extra += col.r(` \xb7 rule-blocked`);
    if (et === 'budget_exceeded')           extra += col.r(` \xb7 🚫 $${(e.budget_spent || 0).toFixed(4)} of $${(e.budget_limit || 0).toFixed(4)}`);

    console.log(`${idxStr}${col.d(ts)}  ${eventTypeLabel(et)}  ${col.d(model.padEnd(16))}  ${col.y(inp)} in /${col.y(out)} out  ${col.g(cost)}${extra}`);

    // Boundary sub-line: one indented line clarifying what crossed the cloud boundary
    const pad = '         ';
    if (et === 'local_only' && (e.tools || []).length > 0) {
      const cmds = e.tools.slice(0, 3).map(t => (t.cmd || '?').split(/\s+/)[0]).join(', ');
      const more = e.tools.length > 3 ? ` +${e.tools.length - 3}` : '';
      console.log(col.d(`${pad}⚡ local: ${cmds}${more}  → results forwarded to Anthropic`));
    } else if (et === 'trimmed' && (e.lao_dropped || []).length > 0) {
      const dropped = e.lao_dropped.slice(0, 3).map(f => f.split(/[/\\]/).pop()).join(', ');
      const more = e.lao_dropped.length > 3 ? ` +${e.lao_dropped.length - 3}` : '';
      console.log(col.y(`${pad}✂ LAO removed: ${dropped}${more}`));
    } else if ((et === 'cloud_sent' || et === 'trimmed') && (e.file_tokens || []).length > 0) {
      const fnames = e.file_tokens.slice(0, 3).map(f => f.name.split(/[/\\]/).pop()).join(', ');
      const moreF  = e.file_tokens.length > 3 ? ` +${e.file_tokens.length - 3}` : '';
      console.log(col.d(`${pad}→ files in context: ${fnames}${moreF}`));
    } else if (et === 'blocked') {
      const sec = (e.secrets || []).map(s => s.label || 'secret').slice(0, 2).join(', ');
      if (sec) console.log(col.r(`${pad}🛑 blocked: ${sec}`));
    }
  });

  const saved = (stats.cache_savings || 0) + (stats.lao_cost_saved || 0) + (stats.distill_cost_saved || 0);
  const savedStr   = saved > 0.00001 ? col.g(`  \xb7  saved $${saved.toFixed(4)}`) : '';
  const localStr   = stats.local_only ? col.g(`  \xb7  ${stats.local_only} local`)  : '';
  const blockedStr = stats.blocked    ? col.r(`  \xb7  ${stats.blocked} blocked`)    : '';
  const trimmedStr = stats.trimmed    ? col.y(`  \xb7  ${stats.trimmed} trimmed`)    : '';
  console.log(col.d(`\n  Total:  `) + col.y(`$${stats.cost.toFixed(4)}`) + savedStr + localStr + trimmedStr + blockedStr + '\n');
}

// ── Token attribution ─────────────────────────────────────────────────────────
//
// "Where did this run's context tokens come from?"
//
// Walks a run's JSONL entries and reconstructs a per-source breakdown of the
// total input_tokens reported by Anthropic. Three classes:
//
//   tool_contributions — Σ kept_bytes / 4 per canonical tool category. This
//                        approximates how many tokens of each tool's output
//                        first entered the model's context. APPROXIMATE
//                        (chars/4) and marked with '~'.
//   cache_reuse        — Σ cache_read_tokens. EXACT (Anthropic-reported).
//   residual           — Σ input_tokens − Σ tool_kept_tokens. Includes
//                        system prompt, user messages, and cross-request
//                        tool_result carry-over. We do NOT inspect request
//                        bodies; carry-over is folded into residual rather
//                        than mis-attributed to tools.
//
// "Prevented from re-entering" is summed exactly from the per-request log
// fields (distill_tokens_saved, lao_tokens_saved, plus a derived
// context_budget_saved from tools[].kept_bytes vs bytes when the prevention
// reason is 'context_budget').
//
// The function returns a plain JS object; renderers and CLI live below.

const TOOL_CATEGORY_MAP = {
  Read: 'read_file',     read_file:  'read_file',
  Glob: 'find_files',    find_files: 'find_files',
  Grep: 'grep',          grep:       'grep',
  Bash: 'shell_bash',    shell_bash: 'shell_bash',
  PowerShell: 'shell_powershell', shell_powershell: 'shell_powershell',
  TodoWrite: 'todo_write', todo_write: 'todo_write',
  TodoRead:  'todo_read',  todo_read:  'todo_read',
};
function categoryOf(toolName) {
  return TOOL_CATEGORY_MAP[toolName] || (toolName ? String(toolName).toLowerCase() : 'unknown');
}
function tokensFromBytes(b) {
  return Math.ceil((b || 0) / 4);
}

function attributeRun(runEntries) {
  const base = {
    request_count: 0,
    model: null,
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
    tool_contributions: {},     // category → tokens
    tool_kept_total: 0,
    prevented: {
      distill_clip:   0,
      redact_secrets: 0,
      context_budget: 0,
      lao_drop:       0,
    },
    prevented_total: 0,
    residual_tokens: 0,
    counterfactual_input_tokens: 0,
    approximations: ['tool_contributions (chars/4)', 'residual (input_tokens − tool_kept)'],
  };
  if (!Array.isArray(runEntries) || runEntries.length === 0) return base;

  for (const e of runEntries) {
    base.request_count++;
    base.model              = base.model || e.model || null;
    base.input_tokens       += (e.input_tokens       || 0);
    base.output_tokens      += (e.output_tokens      || 0);
    base.cache_read_tokens  += (e.cache_read_tokens  || 0);
    base.cache_write_tokens += (e.cache_write_tokens || 0);
    base.prevented.distill_clip += (e.distill_tokens_saved || 0);
    base.prevented.lao_drop     += (e.lao_tokens_saved     || 0);

    if (!Array.isArray(e.tools)) continue;
    for (const t of e.tools) {
      const cat = categoryOf(t.tool);
      const kept = typeof t.kept_bytes === 'number' ? t.kept_bytes : (t.bytes || 0);
      const keptTokens = tokensFromBytes(kept);
      base.tool_contributions[cat] = (base.tool_contributions[cat] || 0) + keptTokens;
      base.tool_kept_total += keptTokens;
      // Context-budget savings derived from raw - kept on tools where the
      // reason recorded by interceptor.js was 'context_budget'. The distill
      // and redact paths already populate distill_tokens_saved /
      // secretsRedacted-bytes elsewhere; only the budget path lacks a
      // dedicated saved-tokens field.
      if (t.prevention_reason === 'context_budget' && typeof t.bytes === 'number' && typeof t.kept_bytes === 'number') {
        const saved = tokensFromBytes(Math.max(0, t.bytes - t.kept_bytes));
        base.prevented.context_budget += saved;
      }
      if (typeof t.secretsRedacted === 'number' && t.secretsRedacted > 0 &&
          typeof t.bytes === 'number' && typeof t.kept_bytes === 'number') {
        // Approximate: bytes redacted ≈ delta. For full-redaction this is the
        // honest figure; for partial-redaction it slightly overstates.
        const saved = tokensFromBytes(Math.max(0, t.bytes - t.kept_bytes));
        base.prevented.redact_secrets += saved;
      }
    }
  }

  base.prevented_total = base.prevented.distill_clip
                       + base.prevented.redact_secrets
                       + base.prevented.context_budget
                       + base.prevented.lao_drop;
  base.residual_tokens = Math.max(0, base.input_tokens - base.tool_kept_total);
  base.counterfactual_input_tokens = base.input_tokens + base.prevented_total;
  return base;
}

function fmtAttribution(attr, runId) {
  if (!attr || attr.request_count === 0) {
    return '\n  (no entries in this run)\n';
  }
  const lines = [];
  const C = col;
  const bar = (n, max, width = 24) => {
    if (max <= 0) return '';
    const cells = Math.min(width, Math.round((n / max) * width));
    return '█'.repeat(cells);
  };
  const maxComponent = Math.max(
    attr.tool_kept_total,
    attr.cache_read_tokens,
    attr.residual_tokens,
    1,
  );

  lines.push('');
  lines.push(`${C.b('Run')} ${C.d(shortId(runId || ''))}${attr.model ? '  ' + C.d(attr.model) : ''}  ${C.d(`(${attr.request_count} requests)`)}`);
  lines.push('');
  lines.push(`  ${C.b('Tokens reaching the model (Σ across run):')}`);
  const toolsSorted = Object.entries(attr.tool_contributions).sort((a, b) => b[1] - a[1]);
  if (toolsSorted.length === 0) {
    lines.push(`    ${C.d('(no tool calls in this run)')}`);
  } else {
    lines.push(`    ${C.b('Tool contributions')}     ${C.y(`~${fmtN(attr.tool_kept_total)}t`)}   ${C.d('(kept_bytes / 4)')}`);
    for (const [cat, tok] of toolsSorted) {
      lines.push(`      ${cat.padEnd(20)} ${('~' + fmtN(tok) + 't').padStart(8)}   ${C.c(bar(tok, maxComponent))}`);
    }
  }
  lines.push(`    ${C.b('Cache reuse')}            ${C.g(fmtN(attr.cache_read_tokens) + 't')}     ${C.c(bar(attr.cache_read_tokens, maxComponent))}   ${C.d('(Anthropic prompt cache, exact)')}`);
  lines.push(`    ${C.b('Residual')}               ${fmtN(attr.residual_tokens) + 't'.padEnd(7)}    ${C.c(bar(attr.residual_tokens, maxComponent))}   ${C.d('(system + user + carry-over)')}`);
  lines.push(`    ${C.d('─────')}`);
  lines.push(`    ${C.b('Σ input_tokens')}         ${C.b(fmtN(attr.input_tokens) + 't')}     ${C.d('(Anthropic-reported, exact)')}`);
  lines.push('');
  lines.push(`  ${C.b('Prevented from re-entering:')}`);
  const p = attr.prevented;
  lines.push(`    distill_clip            ${('~' + fmtN(p.distill_clip) + 't').padStart(8)}`);
  lines.push(`    redact_secrets          ${('~' + fmtN(p.redact_secrets) + 't').padStart(8)}`);
  lines.push(`    context_budget          ${('~' + fmtN(p.context_budget) + 't').padStart(8)}`);
  lines.push(`    lao_drop                ${('~' + fmtN(p.lao_drop) + 't').padStart(8)}`);
  lines.push(`    ${C.d('─────')}`);
  lines.push(`    ${C.b('Total prevented')}         ${C.r('~' + fmtN(attr.prevented_total) + 't')}`);
  lines.push('');
  const pct = attr.counterfactual_input_tokens > 0
    ? Math.round((attr.prevented_total / attr.counterfactual_input_tokens) * 100)
    : 0;
  lines.push(`  ${C.b('Counterfactual:')}        would have been ~${fmtN(attr.counterfactual_input_tokens)}t  ${C.d(`(~${pct}% prevented)`)}`);
  lines.push('');
  lines.push(C.d('  Token figures with ~ are approximate (chars/4). Σ input_tokens and cache values are exact.'));
  return lines.join('\n');
}

function runReplayCli(args) {
  let limit     = 3;
  let detail    = false;
  let runFilter = null;
  const attribute = args.includes('--attribute');

  const lastIdx = args.indexOf('--last');
  if (lastIdx >= 0) limit = parseInt(args[lastIdx + 1], 10) || 3;

  if (args.includes('--detail')) detail = true;

  const runIdx = args.indexOf('--run');
  if (runIdx >= 0) { runFilter = args[runIdx + 1] || null; detail = true; }

  const today   = todayStr();
  const logFile = path.join(LOG_DIR, 'logs', `${today}.jsonl`);
  const entries = [];
  if (fs.existsSync(logFile)) {
    const lines = fs.readFileSync(logFile, 'utf8').split('\n');
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      try { entries.push(JSON.parse(line)); } catch {}
    }
  }

  const runsMap = groupByRun(entries);

  if (runFilter) {
    let matchedKey = null;
    for (const key of runsMap.keys()) {
      if (key.startsWith(runFilter) || key === runFilter) { matchedKey = key; break; }
    }
    if (!matchedKey) {
      console.log(col.d(`\n   No run found matching '${runFilter}' in today's log.\n`));
      return;
    }
    if (attribute) {
      console.log(col.b(`\n⚡ LocalFirst Replay — Token Attribution`));
      console.log(fmtAttribution(attributeRun(runsMap.get(matchedKey)), matchedKey));
      return;
    }
    printRunDetail(matchedKey, runsMap.get(matchedKey));
    return;
  }

  // Order runs by earliest entry iso, show last N
  const runList = Array.from(runsMap.entries())
    .map(([runId, runEntries]) => ({ runId, runEntries, start: runEntries[0]?.iso || runEntries[0]?.ts || '' }))
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));

  const sliced = runList.slice(-limit);
  const total  = runList.length;

  console.log(col.b(`\n⚡ LocalFirst Replay`));
  console.log(col.d(`   ${today}  \xb7  ${total} run${total === 1 ? '' : 's'} today\n`));

  if (!sliced.length) {
    console.log(col.d('   No runs yet. Run: localfirst claude\n'));
    return;
  }

  for (const { runId, runEntries } of sliced) {
    if (attribute) {
      console.log(fmtAttribution(attributeRun(runEntries), runId));
    } else if (detail) {
      printRunDetail(runId, runEntries);
    } else {
      printRunHeader(runId, buildRunStats(runEntries));
    }
  }

  if (total > limit) {
    console.log(col.d(`\n   Showing ${sliced.length} of ${total} runs  \xb7  --last ${total} for all  \xb7  --detail for event breakdown\n`));
  } else {
    console.log(col.d(`\n   ${total} run${total === 1 ? '' : 's'}  \xb7  --detail for event breakdown  \xb7  --run <id> for a specific run\n`));
  }
}

module.exports = { groupByRun, buildRunStats, attributeRun, fmtAttribution, runReplayCli };
