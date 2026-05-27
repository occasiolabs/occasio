'use strict';

/**
 * Single read facade over the audit chain at ~/.occasio/pipeline-events.jsonl.
 *
 * After Phase 2 of the truth-source unification, the chain contains three
 * event kinds:
 *
 *   - kind: "tool_call"      — behavioral attestation per tool invocation
 *   - kind: "policy_loaded"  — synthetic event when policy.yml is loaded
 *   - kind: "request"        — per-request accounting (cost, tokens, savings)
 *
 * All Inspect CLI commands (status, ledger, replay, boundary, inspect,
 * report, preflight, recap) read through this module. No command parses
 * pipeline-events.jsonl directly. This is the only place that knows the
 * row schemas and how to filter/aggregate them.
 *
 * Why: prior to this module, logs/*.jsonl and session.json were a second
 * (ungeprotected) source of truth. `status` and `ledger` would disagree on
 * counters because each read from different files. With everything routed
 * through the chain via this module, drift is impossible — and the
 * tamper-evidence claim covers every number the user sees.
 *
 * Read-only. No mutation, no chain writes.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const LOG_DIR      = path.join(os.homedir(), '.occasio');
const CHAIN_FILE   = process.env.OCCASIO_AUDIT_FILE
  || path.join(LOG_DIR, 'pipeline-events.jsonl');
const SESSION_FILE = path.join(LOG_DIR, 'session.json');

// ── Low-level chain read ───────────────────────────────────────────────────

/**
 * Read pipeline-events.jsonl and return an array of parsed rows.
 * Malformed lines are skipped silently (consistent with verifier behaviour).
 * Returns [] if the file doesn't exist.
 */
function readChain(file = CHAIN_FILE) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch { /* skip malformed */ }
  }
  return out;
}

// ── Filters ────────────────────────────────────────────────────────────────

function todayDateString(now = new Date()) {
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function isToday(rowTs, now = new Date()) {
  if (!rowTs) return false;
  return rowTs.slice(0, 10) === todayDateString(now);
}

/**
 * Load events from the chain, optionally filtered.
 *
 * Options:
 *   - file:     override chain file path (used by tests)
 *   - kind:     "request" | "tool_call" | "policy_loaded" | array | undefined (all)
 *   - runId:    only events with this run_id
 *   - cwd:      only events with this cwd (works for kind:"request" rows;
 *               tool_call rows do not carry cwd today, so they are excluded
 *               when cwd is set — caller's responsibility to be aware)
 *   - today:    only events whose ts (ISO) falls on today's date (local tz)
 *   - since:    ISO string lower bound (inclusive)
 *   - until:    ISO string upper bound (exclusive)
 *
 * Returns events in chain order (write order).
 */
function loadEvents(opts = {}) {
  const rows = readChain(opts.file);
  const wantKinds = opts.kind
    ? (Array.isArray(opts.kind) ? new Set(opts.kind) : new Set([opts.kind]))
    : null;

  const out = [];
  for (const r of rows) {
    if (wantKinds && !wantKinds.has(r.kind)) continue;
    if (opts.runId && r.run_id !== opts.runId) continue;
    if (opts.cwd && r.cwd !== opts.cwd) continue;
    if (opts.today && !isToday(r.ts)) continue;
    if (opts.since && (!r.ts || r.ts < opts.since)) continue;
    if (opts.until && (!r.ts || r.ts >= opts.until)) continue;
    out.push(r);
  }
  return out;
}

// ── Session pointer ────────────────────────────────────────────────────────

/**
 * Read the current run's identifier from session.json. After Phase 5 this
 * is the ONLY thing session.json carries; until then we deliberately ignore
 * all the legacy counter fields that still live there.
 *
 * Returns null if session.json is missing or unparseable — callers should
 * treat that as "no active run; show all-runs view."
 */
function currentRunId(file = SESSION_FILE) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    return s.run_id || null;
  } catch {
    return null;
  }
}

// ── Grouping & stats ───────────────────────────────────────────────────────

/**
 * Group events by run_id, sorted by ts within each run.
 * Events without a run_id (legacy / policy_loaded) are placed under 'legacy'.
 */
function groupByRun(events) {
  const map = new Map();
  for (const e of events) {
    const key = e.run_id || 'legacy';
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(e);
  }
  for (const [, arr] of map) {
    arr.sort((a, b) => {
      const ai = a.ts || '';
      const bi = b.ts || '';
      return ai < bi ? -1 : ai > bi ? 1 : 0;
    });
  }
  return map;
}

/**
 * Pick the N most-recently-ended runs from a grouped map.
 * Each returned entry is { runId, events, start, end }.
 */
function pickRecentRuns(rowsByRun, n) {
  const entries = [...rowsByRun.entries()].map(([id, events]) => ({
    runId: id,
    events,
    start: events.length ? events[0].ts || '' : '',
    end:   events.length ? events[events.length - 1].ts || '' : '',
  }));
  entries.sort((a, b) => a.end < b.end ? 1 : -1);
  return entries.slice(0, n);
}

// Zero-initialized accounting stats — the canonical shape that summarize()
// and buildRunStats() both return. Documented here once so callers know
// every field is always present (no undefined-handling needed).
function zeroAccountingStats() {
  return {
    requests: 0,
    cloud_sent: 0, local_only: 0, blocked: 0, trimmed: 0,
    budget_exceeded: 0, partial_intercept: 0,
    input_tokens: 0, output_tokens: 0,
    cache_read_tokens: 0, cache_write_tokens: 0,
    cost: 0, cache_savings: 0,
    lao_tokens_saved: 0, lao_cost_saved: 0,
    distill_tokens_saved: 0, distill_cost_saved: 0,
    tools_attempted: 0, tools_local_count: 0, tools_mcp_count: 0,
    start: null, end: null, durationMs: 0,
  };
}

/**
 * Aggregate accounting totals over a list of kind:"request" events.
 *
 * Accepts any list — events of other kinds are skipped, so passing a
 * mixed-kind event list (e.g. the full chain for a run) works correctly
 * and counts only the request rows.
 */
function summarize(events) {
  const t = zeroAccountingStats();
  for (const e of events) {
    if (e.kind && e.kind !== 'request') continue;
    t.requests++;
    const et = e.event_type;
    if      (et === 'cloud_sent')        t.cloud_sent++;
    else if (et === 'local_only')        t.local_only++;
    else if (et === 'blocked')           t.blocked++;
    else if (et === 'trimmed')           t.trimmed++;
    else if (et === 'budget_exceeded')   t.budget_exceeded++;
    else if (et === 'partial_intercept') t.partial_intercept++;
    t.input_tokens         += e.input_tokens         || 0;
    t.output_tokens        += e.output_tokens        || 0;
    t.cache_read_tokens    += e.cache_read_tokens    || 0;
    t.cache_write_tokens   += e.cache_write_tokens   || 0;
    t.cost                 += e.cost                 || 0;
    t.cache_savings        += e.cache_savings        || 0;
    t.lao_tokens_saved     += e.lao_tokens_saved     || 0;
    t.lao_cost_saved       += e.lao_cost_saved       || 0;
    t.distill_tokens_saved += e.distill_tokens_saved || 0;
    t.distill_cost_saved   += e.distill_cost_saved   || 0;
    t.tools_attempted      += e.tools_attempted      || 0;
    t.tools_local_count    += e.tools_local_count    || 0;
    t.tools_mcp_count      += e.tools_mcp_count      || 0;
    if (e.ts) {
      if (!t.start || e.ts < t.start) t.start = e.ts;
      if (!t.end   || e.ts > t.end)   t.end   = e.ts;
    }
  }
  if (t.start && t.end) t.durationMs = new Date(t.end) - new Date(t.start);
  return t;
}

/**
 * Build per-run statistics. Accepts events for a single run (mixed kinds OK).
 * Equivalent to summarize() but produced from a run-events array directly.
 * Provided as a thin alias so callers can express intent ("stats for this run").
 */
function buildRunStats(runEvents) {
  return summarize(runEvents || []);
}

// ── Tool-call aggregation (behavioral side) ────────────────────────────────

/**
 * Count tool_call events in a list, broken down by action.
 * Used by recap/replay to surface "what did the agent actually do".
 */
function buildToolStats(events) {
  const out = {
    total: 0,
    by_tool: {},
    blocked: 0, transformed: 0, local: 0, pass: 0,
    secrets_redacted: 0,
  };
  for (const e of events) {
    if (e.kind !== 'tool_call') continue;
    out.total++;
    const tool = e.tool_name || 'unknown';
    out.by_tool[tool] = (out.by_tool[tool] || 0) + 1;
    if      (e.action === 'BLOCK')     out.blocked++;
    else if (e.action === 'TRANSFORM') out.transformed++;
    else if (e.action === 'LOCAL')     out.local++;
    else if (e.action === 'PASS')      out.pass++;
    out.secrets_redacted += e.secrets_redacted || 0;
  }
  return out;
}

module.exports = {
  // chain location (exported for tests + diagnostics)
  CHAIN_FILE,
  SESSION_FILE,
  // primary API
  loadEvents,
  currentRunId,
  // grouping
  groupByRun,
  pickRecentRuns,
  // aggregation
  summarize,
  buildRunStats,
  buildToolStats,
  zeroAccountingStats,
  // low-level (exported for tests)
  readChain,
  isToday,
  todayDateString,
};
