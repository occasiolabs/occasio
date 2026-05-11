'use strict';

/**
 * inspect.js — Cloud-boundary manifest for LocalFirst log entries.
 *
 * Answers per-request:
 *   - What exactly reached Anthropic?
 *   - What ran locally and why?
 *   - What was trimmed or distilled before send?
 *   - What was blocked and never sent?
 *
 * All display is derived from existing JSONL log fields plus two new ones:
 *   lao_dropped              (string[]) — files LAO removed before send
 *   outbound_message_count   (number)   — messages in the forwarded request
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { readDayLog, readSessionEntries } = require('./ledger');

const LOG_DIR      = path.join(os.homedir(), '.localfirst');
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

function fmtN(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n || 0);
}

/**
 * Extract structured cloud-boundary facts from a raw log entry.
 * Pure function — no I/O, fully testable.
 *
 * @param  {object} entry   A JSONL log entry
 * @returns {BoundaryFacts}
 */
function buildBoundaryFacts(entry) {
  if (!entry || typeof entry !== 'object') return null;

  const et = entry.event_type || (entry.intercepted ? 'local_only' : 'cloud_sent');

  return {
    event_type:              et,
    // true for any event type where something reached Anthropic (even after trim/intercept)
    reached_anthropic:       et !== 'blocked' && et !== 'budget_exceeded',
    blocked_entirely:        et === 'blocked' || et === 'budget_exceeded',

    // Tokens Anthropic actually reported (exact — from provider response)
    input_tokens:            entry.input_tokens  || 0,
    output_tokens:           entry.output_tokens || 0,
    cost:                    entry.cost          || 0,
    cache_read_tokens:       entry.cache_read_tokens  || 0,
    cache_write_tokens:      entry.cache_write_tokens || 0,
    cache_savings:           entry.cache_savings || 0,

    // Files in context (names + approximate token counts — estimated by LocalFirst analyzer)
    files_in_context:        entry.file_tokens   || [],

    // How many messages were in the outbound request (exact — from request body)
    outbound_message_count:  entry.outbound_message_count || null,

    // What LAO removed before forwarding (exact — recorded at trim time)
    lao_dropped:             entry.lao_dropped   || [],
    lao_tokens_saved:        entry.lao_tokens_saved  || 0,
    lao_cost_saved:          entry.lao_cost_saved    || 0,

    // Tool runs executed locally (exact — from interceptor)
    tools_local:             (entry.tools || []),
    tools_distilled:         (entry.tools || []).filter(t => t.distilled),
    distill_tokens_saved:    entry.distill_tokens_saved || 0,

    // Blocked by secret detection (exact — from analyzer)
    secrets_detected:        entry.secrets || [],
    files_rule_blocked:      entry.blocked || [],

    // Budget enforcement
    budget_limit:            entry.budget_limit  ?? null,
    budget_spent:            entry.budget_spent  ?? null,
  };
}

// ── Boundary section renderers ─────────────────────────────────────────────────

const RULE = col.d('─'.repeat(56));

function sectionHeader(icon, label, note) {
  const noteStr = note ? col.d(`  (${note})`) : '';
  return `\n${icon} ${col.b(label)}${noteStr}`;
}

function renderCloudSent(facts) {
  // LAO trim section (if applicable)
  if (facts.lao_dropped.length > 0 || facts.lao_tokens_saved > 0) {
    console.log(sectionHeader(col.y('✂'), 'TRIMMED BEFORE SEND', 'LAO context optimizer'));
    for (const f of facts.lao_dropped) {
      const name = f.split(/[/\\]/).slice(-2).join('/');
      console.log(`    ${col.d(name)}  ${col.y('removed')}`);
    }
    if (facts.lao_dropped.length === 0 && facts.lao_tokens_saved > 0) {
      console.log(col.d(`    (file list unavailable — log entry predates v0.5.3)`));
    }
    if (facts.lao_tokens_saved > 0) {
      console.log(col.y(`    Tokens saved:  ~${fmtN(facts.lao_tokens_saved)}`
        + (facts.lao_cost_saved > 0 ? col.g(`  ($${facts.lao_cost_saved.toFixed(4)})`) : '')));
    }
  }

  // Cloud payload
  console.log(sectionHeader(col.c('→'), 'SENT TO ANTHROPIC', 'provider-reported token counts'));
  console.log(`    Tokens:   ${col.y(fmtN(facts.input_tokens) + ' in')} / ${col.y(fmtN(facts.output_tokens) + ' out')}   ${col.g('$' + facts.cost.toFixed(4))}`);
  if (facts.outbound_message_count) {
    console.log(col.d(`    Messages: ${facts.outbound_message_count} in request`));
  }
  if (facts.cache_read_tokens > 0) {
    console.log(col.d(`    Cache:    ${fmtN(facts.cache_read_tokens)} tokens read`
      + (facts.cache_savings > 0 ? `  (saved $${facts.cache_savings.toFixed(4)})` : '')));
  }

  const fts = facts.files_in_context;
  if (fts.length > 0) {
    console.log(col.d(`    Files in context (names from request body — token counts are estimates):`));
    const show = fts.slice(0, 8);
    for (const f of show) {
      const name = (f.name || '?').split(/[/\\]/).slice(-2).join('/');
      console.log(`      ${name.padEnd(40)} ${col.d('~' + fmtN(f.tokens || 0) + ' tokens')}`);
    }
    if (fts.length > 8) console.log(col.d(`      … and ${fts.length - 8} more files`));
  } else if (facts.input_tokens > 0) {
    console.log(col.d(`    (no per-file breakdown — file analysis not available for this request)`));
  }

  // Distilled tool results note
  const dist = facts.tools_distilled;
  if (dist.length > 0) {
    console.log(sectionHeader(col.y('✂'), 'DISTILLED BEFORE RE-ENTERING MODEL', 'tool output reduced'));
    for (const t of dist) {
      const cmd = (t.cmd || '?').slice(0, 48);
      console.log(`    ${cmd.padEnd(50)}  ${col.y('✂ ' + (t.distillLabel || 'distilled'))}`);
    }
    console.log(col.d(`    Full output saved locally. Run: ${col.b('localfirst distill')}  to view.`));
  }
}

function renderLocalOnly(facts) {
  const tools = facts.tools_local;

  if (tools.length > 0) {
    console.log(sectionHeader(col.g('⚡'), 'EXECUTED LOCALLY', 'tool results forwarded to Anthropic in follow-up call'));
    for (const t of tools) {
      const cmd = (t.cmd || '?').slice(0, 46);
      const sz  = t.bytes != null ? `${(t.bytes / 1024).toFixed(1)} KB`.padStart(9) : ''.padStart(9);
      const nat = t.native  ? col.g(' native') : col.d(' exec  ');
      const dis = t.distilled ? col.y(` ✂ ${(t.distillLabel || 'distilled').slice(0, 30)}`) : '';
      console.log(`    ${cmd.padEnd(48)} ${col.d(sz)}${nat}${dis}`);
    }
    console.log(col.d(`\n    Note: "local" means execution happened on this machine (not in Claude Code's`));
    console.log(col.d(`    subprocess). Tool results were forwarded to Anthropic in LocalFirst's follow-up call.`));
  }

  if (facts.input_tokens > 0 || facts.output_tokens > 0) {
    console.log(sectionHeader(col.c('→'), 'SENT TO ANTHROPIC', 'initial + follow-up calls combined'));
    console.log(`    Tokens:   ${col.y(fmtN(facts.input_tokens) + ' in')} / ${col.y(fmtN(facts.output_tokens) + ' out')}   ${col.g('$' + facts.cost.toFixed(4))}`);
    if (facts.cache_read_tokens > 0) {
      console.log(col.d(`    Cache:    ${fmtN(facts.cache_read_tokens)} tokens read  (saved $${facts.cache_savings.toFixed(4)})`));
    }
  }

  const dist = facts.tools_distilled;
  if (dist.length > 0) {
    console.log(sectionHeader(col.y('✂'), 'DISTILLED BEFORE FORWARDING', 'tool output reduced before re-entering model'));
    for (const t of dist) {
      console.log(`    ${(t.cmd || '?').slice(0, 48).padEnd(50)}  ${col.y('✂ ' + (t.distillLabel || ''))}`);
    }
    console.log(col.d(`    Run: ${col.b('localfirst distill')}  to view raw output.`));
  }
}

function renderBlocked(facts) {
  console.log(`\n${col.r('🛑 BLOCKED')}  ${col.d('— nothing was sent to Anthropic')}`);
  const secs = facts.secrets_detected;
  if (secs.length > 0) {
    console.log(col.r(`\n  Detected secrets:`));
    for (const s of secs) {
      const line = s.line ? col.d(` line ${s.line}`) : '';
      console.log(`    ${col.r('×')}  ${s.label || 'secret'}${line}`);
    }
  }
  const blk = facts.files_rule_blocked;
  if (blk.length > 0) {
    console.log(col.r(`\n  Rule-blocked files:`));
    for (const f of blk) console.log(`    ${col.r('×')}  ${f}`);
  }
}

function renderBudgetExceeded(facts) {
  console.log(`\n${col.r('🚫 BUDGET EXCEEDED')}  ${col.d('— nothing was sent to Anthropic')}`);
  if (facts.budget_limit != null) {
    console.log(`    Budget limit:  ${col.y('$' + facts.budget_limit.toFixed(4))}`);
    console.log(`    Spent so far:  ${col.r('$' + (facts.budget_spent || 0).toFixed(4))}`);
    const overage = (facts.budget_spent || 0) - facts.budget_limit;
    if (overage > 0) console.log(col.d(`    Over by:       $${overage.toFixed(4)}`));
  }
  console.log(col.d(`    Reset: localfirst clear  |  Increase: restart with --budget N`));
}

// ── Main entry renderer ────────────────────────────────────────────────────────

const ET_LABEL = {
  cloud_sent:      col.c('[cloud_sent]'),
  local_only:      col.g('[local_only]'),
  trimmed:         col.y('[trimmed]'),
  blocked:         col.r('[blocked]'),
  budget_exceeded: col.r('[budget_exceeded]'),
};

/**
 * Print a full boundary manifest for one log entry.
 * @param {object} entry     Raw log entry
 * @param {number} idxLabel  1-based display index
 * @param {number} total     Total entries in the view (for header)
 */
function printBoundaryEntry(entry, idxLabel, total) {
  const facts  = buildBoundaryFacts(entry);
  if (!facts) return;

  const ts    = entry.ts || (entry.iso ? new Date(entry.iso).toTimeString().slice(0, 8) : '?');
  const model = (entry.model || '').replace('claude-', '').replace(/-\d{8}$/, '');
  const label = ET_LABEL[facts.event_type] || col.d(`[${facts.event_type}]`);
  const ofStr = total > 1 ? ` of ${total}` : '';

  console.log(`\n${col.b('⚡ Request ' + idxLabel + ofStr)}  ${label}  ${col.d(ts)}  ${col.d(model)}`);
  console.log(RULE);

  switch (facts.event_type) {
    case 'cloud_sent':
    case 'trimmed':
      renderCloudSent(facts);
      break;
    case 'local_only':
      renderLocalOnly(facts);
      break;
    case 'blocked':
      renderBlocked(facts);
      break;
    case 'budget_exceeded':
      renderBudgetExceeded(facts);
      break;
    default:
      console.log(col.d(`  (unknown event type: ${facts.event_type})`));
  }

  console.log('\n' + RULE);
}

// ── CLI ────────────────────────────────────────────────────────────────────────

function runInspectCli(args) {
  let session = null;
  try { session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch {}

  const todayEntries = readDayLog(todayStr());

  const scopeIdx = args.indexOf('--scope');
  const scope    = scopeIdx >= 0 ? (args[scopeIdx + 1] || 'session') : 'session';
  const entries  = scope === 'session'
    ? readSessionEntries(todayEntries, session?.start)
    : todayEntries;

  if (!entries.length) {
    console.log(col.d(`\n  No log entries yet. Run: localfirst claude\n`));
    return;
  }

  // --entry N: single entry by 0-based index
  const entryFlagIdx = args.indexOf('--entry');
  if (entryFlagIdx >= 0) {
    const n = parseInt(args[entryFlagIdx + 1]);
    if (isNaN(n) || n < 0 || n >= entries.length) {
      console.log(col.r(`  No entry at index ${n} (${entries.length} total in scope).`));
      return;
    }
    console.log(col.b(`\n⚡ LocalFirst Inspect  —  Entry ${n + 1} of ${entries.length}`));
    printBoundaryEntry(entries[n], n + 1, entries.length);
    return;
  }

  // --run <id-prefix>: all entries matching run_id prefix
  const runFlagIdx = args.indexOf('--run');
  if (runFlagIdx >= 0) {
    const runFilter  = args[runFlagIdx + 1] || '';
    const runEntries = entries.filter(e => e.run_id && e.run_id.startsWith(runFilter));
    if (!runEntries.length) {
      console.log(col.d(`\n  No entries for run: ${runFilter}\n`));
      return;
    }
    const shortId = runFilter.slice(0, 8);
    console.log(col.b(`\n⚡ LocalFirst Inspect  —  Run ${shortId}  (${runEntries.length} event${runEntries.length === 1 ? '' : 's'})`));
    runEntries.forEach((e, i) => printBoundaryEntry(e, i + 1, runEntries.length));
    return;
  }

  // default / --last N: last N entries (default 1)
  const lastFlagIdx = args.indexOf('--last');
  const limit       = lastFlagIdx >= 0 ? (parseInt(args[lastFlagIdx + 1]) || 1) : 1;
  const slice       = entries.slice(-limit);
  const offset      = entries.length - slice.length;

  console.log(col.b(`\n⚡ LocalFirst Inspect`));
  console.log(col.d(`   scope: ${scope}  ·  ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}  ·  showing last ${slice.length}\n`));

  slice.forEach((e, i) => printBoundaryEntry(e, offset + i + 1, entries.length));

  console.log(col.d(`\n  --last N   show last N entries    --entry N  inspect by index`));
  console.log(col.d(`  --run <id> inspect a specific run --scope today  full-day scope\n`));
}

module.exports = { buildBoundaryFacts, printBoundaryEntry, runInspectCli };
