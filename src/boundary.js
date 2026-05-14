'use strict';

/**
 * boundary.js — per-request "what crossed the boundary" view.
 *
 * Reads existing per-request JSONL entries from ~/.occasio/logs/ and
 * projects each request into a three-column accounting:
 *
 *   produced  — raw bytes/tokens each tool emitted
 *   re-entered — bytes/tokens that actually re-entered the model's next request
 *   prevented  — bytes/tokens kept out, classified by reason
 *
 * The data primitives (`bytes`, `kept_bytes`, `prevention_reason`) are
 * recorded per tool call in `interceptor.js`. Older log entries that predate
 * the new fields are handled by falling back to `bytes` (treated as "kept
 * fully"). No new audit-chain fields are introduced.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const LOG_DIR = path.join(os.homedir(), '.occasio', 'logs');

// Char-per-token ratio used by the analyzer. Approximate; every token
// figure surfaced by this module is prefixed with '~' in the renderer.
const CHARS_PER_TOKEN = 4;

function estTokens(bytes) {
  return Math.ceil((bytes || 0) / CHARS_PER_TOKEN);
}

const PREVENTION_LABELS = {
  distill_clip:    'distilled',
  redact_secrets:  'redacted',
  block:           'blocked',
  context_budget:  'budget-clipped',
};

/**
 * Build a per-request boundary view from a single JSONL log entry.
 *
 * @param  {object} entry  parsed JSONL log entry
 * @returns {object|null}  { iso, model, event_type, tools: [...], totals: {...} }
 */
function buildBoundaryView(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const toolRuns = Array.isArray(entry.tools) ? entry.tools : [];

  const tools = toolRuns.map((t) => {
    const raw  = typeof t.bytes      === 'number' ? t.bytes      : 0;
    // Backward compat: log entries written before kept_bytes treat the entire
    // raw output as kept (no shaping was recorded).
    const kept = typeof t.kept_bytes === 'number' ? t.kept_bytes : raw;
    const prevented = Math.max(0, raw - kept);
    const reason =
      t.prevention_reason ||
      (t.distilled        ? 'distill_clip'   :
       t.secretsRedacted  ? 'redact_secrets' :
       t.blocked          ? 'block'          : null);

    return {
      tool:         t.tool || '(unknown)',
      tool_use_id:  t.tool_use_id || null,
      cmd:          t.cmd  || '',
      raw_bytes:        raw,
      kept_bytes:       kept,
      prevented_bytes:  prevented,
      raw_tokens:       estTokens(raw),
      kept_tokens:      estTokens(kept),
      prevented_tokens: estTokens(prevented),
      prevention_reason: reason,
      prevention_label:  reason ? (PREVENTION_LABELS[reason] || reason) : null,
      native:           !!t.native,
    };
  });

  const totalRaw       = tools.reduce((s, t) => s + t.raw_bytes,       0);
  const totalKept      = tools.reduce((s, t) => s + t.kept_bytes,      0);
  const totalPrevented = Math.max(0, totalRaw - totalKept);

  return {
    iso:        entry.iso,
    model:      entry.model || '',
    event_type: entry.event_type || '',
    run_id:     entry.run_id || null,
    tools,
    totals: {
      raw_bytes:        totalRaw,
      kept_bytes:       totalKept,
      prevented_bytes:  totalPrevented,
      raw_tokens:       estTokens(totalRaw),
      kept_tokens:      estTokens(totalKept),
      prevented_tokens: estTokens(totalPrevented),
    },
  };
}

// ── Renderer ──────────────────────────────────────────────────────────────────

const C = (() => {
  const noColor = process.env.NO_COLOR || !process.stdout.isTTY;
  if (noColor) return new Proxy({}, { get: () => (s) => s });
  return {
    b: (s) => `\x1b[1m${s}\x1b[0m`,
    d: (s) => `\x1b[2m${s}\x1b[0m`,
    g: (s) => `\x1b[32m${s}\x1b[0m`,
    y: (s) => `\x1b[33m${s}\x1b[0m`,
    c: (s) => `\x1b[36m${s}\x1b[0m`,
    r: (s) => `\x1b[31m${s}\x1b[0m`,
  };
})();

function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  return `${(b / 1024).toFixed(1)} KB`;
}

function renderBoundaryView(view, opts = {}) {
  if (!view) return '';
  const lines = [];
  const tag = view.event_type ? `[${view.event_type}]` : '';
  lines.push('');
  lines.push(`${C.b('Request')}  ${C.d(view.iso || '')}  ${C.d(view.model)}  ${C.d(tag)}`);
  lines.push('');

  if (view.tools.length === 0) {
    lines.push(C.d('  (no tool calls in this request)'));
    return lines.join('\n');
  }

  lines.push(`  ${C.b('Tool'.padEnd(12))} ${C.b('Target'.padEnd(34))} ${C.b('Produced'.padEnd(16))} ${C.b('Re-entered'.padEnd(16))} ${C.b('Prevented')}`);
  lines.push(`  ${C.d('─'.repeat(12))} ${C.d('─'.repeat(34))} ${C.d('─'.repeat(16))} ${C.d('─'.repeat(16))} ${C.d('─'.repeat(20))}`);

  for (const t of view.tools) {
    const target = (t.cmd || '').slice(0, 32).padEnd(34);
    const produced = `${fmtBytes(t.raw_bytes)} ~${t.raw_tokens}t`.padEnd(16);
    const kept = (t.kept_bytes === t.raw_bytes ? C.g(`${fmtBytes(t.kept_bytes)} ~${t.kept_tokens}t`) : C.y(`${fmtBytes(t.kept_bytes)} ~${t.kept_tokens}t`)).padEnd(t.kept_bytes === t.raw_bytes ? 21 : 21);
    const prevented = t.prevented_bytes === 0
      ? C.d('—')
      : `${C.r('~' + t.prevented_tokens + 't')} ${C.d('(' + t.prevention_label + ')')}`;
    lines.push(`  ${t.tool.padEnd(12)} ${target} ${produced} ${kept} ${prevented}`);
  }

  lines.push('');
  lines.push(`  ${C.b('Totals:')}`);
  lines.push(`    produced       ${fmtBytes(view.totals.raw_bytes)}  ~${view.totals.raw_tokens}t`);
  lines.push(`    re-entered     ${C.g(fmtBytes(view.totals.kept_bytes) + '  ~' + view.totals.kept_tokens + 't')}`);
  lines.push(`    prevented      ${view.totals.prevented_bytes === 0
    ? C.d('0 B  ~0t')
    : C.r(fmtBytes(view.totals.prevented_bytes) + '  ~' + view.totals.prevented_tokens + 't')}`);
  lines.push('');
  lines.push(C.d('  Token figures are approximate (chars/4). Audit chain at') + ' ' + C.d('~/.occasio/pipeline-events.jsonl'));
  return lines.join('\n');
}

// ── Log reader ────────────────────────────────────────────────────────────────

function readEntries({ scope = 'today' } = {}) {
  const today = (() => {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  })();

  let files = [];
  try {
    files = fs.readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl'));
  } catch { /* logs dir absent */ }
  if (scope === 'today') files = files.filter(f => f === `${today}.jsonl`);
  files.sort();

  const entries = [];
  for (const f of files) {
    let text;
    try { text = fs.readFileSync(path.join(LOG_DIR, f), 'utf8'); } catch { continue; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { entries.push(JSON.parse(line)); } catch { /* skip malformed */ }
    }
  }
  return entries;
}

// ── CLI ───────────────────────────────────────────────────────────────────────

function runBoundaryCli(args = []) {
  const lastIdx  = args.indexOf('--last');
  const entryIdx = args.indexOf('--entry');
  const runIdx   = args.indexOf('--run');
  const json     = args.includes('--json');
  const scopeIdx = args.indexOf('--scope');

  const scope = scopeIdx >= 0 ? (args[scopeIdx + 1] || 'today') : 'today';
  const all = readEntries({ scope });
  if (all.length === 0) {
    process.stdout.write('\n  ' + C.d('No requests in scope. Run a session first.') + '\n');
    return { ok: true, count: 0 };
  }

  // Selection: --entry N (1-indexed), --run <prefix>, --last N, default last 1
  let selected;
  if (entryIdx >= 0) {
    const n = parseInt(args[entryIdx + 1], 10);
    selected = isFinite(n) && n >= 1 && n <= all.length ? [all[n - 1]] : [];
  } else if (runIdx >= 0) {
    const prefix = (args[runIdx + 1] || '');
    selected = all.filter(e => (e.run_id || '').startsWith(prefix));
  } else {
    const n = lastIdx >= 0 ? Math.max(1, parseInt(args[lastIdx + 1], 10) || 1) : 1;
    selected = all.slice(-n);
  }

  if (selected.length === 0) {
    process.stdout.write('\n  ' + C.d('No matching requests.') + '\n');
    return { ok: false, count: 0 };
  }

  if (json) {
    const views = selected.map(buildBoundaryView).filter(Boolean);
    process.stdout.write(JSON.stringify(views, null, 2) + '\n');
    return { ok: true, count: views.length };
  }

  process.stdout.write('\n' + C.b('Occasio Boundary') + '   ' +
    C.d(`scope: ${scope}  ·  ${all.length} entries  ·  showing ${selected.length}`) + '\n');
  for (const e of selected) {
    const view = buildBoundaryView(e);
    process.stdout.write(renderBoundaryView(view) + '\n');
  }
  return { ok: true, count: selected.length };
}

module.exports = {
  buildBoundaryView,
  renderBoundaryView,
  runBoundaryCli,
  readEntries,
};
