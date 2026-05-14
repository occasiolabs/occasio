'use strict';

/**
 * occasio report — structured governance export (ARCH-27).
 *
 * Usage:
 *   occasio report [--format json|csv] [--days N]
 *
 * Reads:
 *   ~/.occasio/pipeline-events.jsonl  — per-tool audit events (tool access, blocks)
 *   ~/.occasio/logs/YYYY-MM-DD.jsonl  — per-request cost/token summary
 *
 * Outputs a structured document answering:
 *   "What data did the AI agent access, what was blocked, and did any secrets appear?"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { verifyFile } = require('../audit/verifier');

const LOG_DIR     = path.join(os.homedir(), '.occasio');
const EVENTS_FILE = path.join(LOG_DIR, 'pipeline-events.jsonl');
const LOGS_DIR    = path.join(LOG_DIR, 'logs');

// ── Helpers ───────────────────────────────────────────────────────────────────

function todayStr(d) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

function cutoffMs(days) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function readJsonlFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

/** Read all daily JSONL logs within the period. */
function readDailyLogs(days) {
  const cutoff = cutoffMs(days);
  const entries = [];
  try {
    const files = fs.readdirSync(LOGS_DIR)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
      .filter(f => {
        const [y, m, d2] = f.replace('.jsonl', '').split('-').map(Number);
        return new Date(y, m - 1, d2).getTime() >= cutoff - 86400000;
      });
    for (const f of files) {
      entries.push(...readJsonlFile(path.join(LOGS_DIR, f)));
    }
  } catch { /* logs dir absent */ }
  return entries;
}

/** Filter pipeline events to those within the period. */
function filterEvents(events, days) {
  const cutoff = cutoffMs(days);
  return events.filter(e => e.ts && new Date(e.ts).getTime() >= cutoff);
}

// ── Report builder ────────────────────────────────────────────────────────────

function buildReport(days) {
  const allEvents   = readJsonlFile(EVENTS_FILE);
  const periodEvents = filterEvents(allEvents, days);
  const dailyLogs   = readDailyLogs(days);

  // Unique sessions from daily logs
  const sessionIds = new Set(dailyLogs.map(e => e.session_id || e.run_id).filter(Boolean));
  const totalCost  = dailyLogs.reduce((s, e) => s + (typeof e.cost === 'number' ? e.cost : 0), 0);

  // Tool-call events with path metadata
  const toolCallEvents = periodEvents.filter(e => e.kind === 'tool_call');

  // Access log: tool calls that actually ran (LOCAL or TRANSFORM, not BLOCK)
  const accessLog = toolCallEvents
    .filter(e => e.action !== 'BLOCK' && e.tool_inputs && e.tool_inputs.path)
    .map(e => ({
      ts:         e.ts,
      session_id: e.session_id || null,
      tool:       e.tool_name,
      path:       e.tool_inputs.path,
      action:     e.action,
      reason:     e.reason || null,
    }));

  // Blocked accesses: tool calls blocked by path policy
  const blockedAccesses = toolCallEvents
    .filter(e => e.action === 'BLOCK' && (e.reason === 'path-denied' || e.reason === 'path-not-allowed'))
    .map(e => ({
      ts:         e.ts,
      session_id: e.session_id || null,
      tool:       e.tool_name,
      path:       (e.tool_inputs && e.tool_inputs.path) || null,
      action:     e.action,
      reason:     e.reason,
    }));

  // Secret events: rows where secrets_redacted > 0
  const secretEvents = periodEvents
    .filter(e => typeof e.secrets_redacted === 'number' && e.secrets_redacted > 0)
    .map(e => ({
      ts:               e.ts,
      session_id:       e.session_id || null,
      tool:             e.tool_name,
      secrets_redacted: e.secrets_redacted,
      action:           e.action,
    }));

  // Audit integrity over the full file (chain is cumulative, not period-scoped)
  const integrity = verifyFile(EVENTS_FILE);

  return {
    generated_at: new Date().toISOString(),
    period_days:  days,
    summary: {
      sessions:          sessionIds.size || dailyLogs.length,
      requests:          dailyLogs.length,
      cost_usd:          Math.round(totalCost * 100000) / 100000,
      files_accessed:    accessLog.length,
      paths_blocked:     blockedAccesses.length,
      secrets_detected:  secretEvents.length,
      requests_blocked:  periodEvents.filter(e => e.action === 'BLOCK' && e.kind !== 'tool_call').length,
    },
    audit_integrity: {
      verified:       integrity.ok,
      chain_length:   integrity.chained,
      first_event_ts: periodEvents.length ? periodEvents[0].ts : null,
      last_event_ts:  periodEvents.length ? periodEvents[periodEvents.length - 1].ts : null,
    },
    access_log:       accessLog,
    blocked_accesses: blockedAccesses,
    secret_events:    secretEvents,
  };
}

// ── CSV serialiser ────────────────────────────────────────────────────────────

function csvEscape(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function toCsv(report) {
  const lines = [];

  // Summary header
  const s = report.summary;
  lines.push(`# generated_at: ${report.generated_at}`);
  lines.push(`# period_days: ${report.period_days}`);
  lines.push(`# sessions: ${s.sessions}, requests: ${s.requests}, cost_usd: ${s.cost_usd}`);
  lines.push(`# files_accessed: ${s.files_accessed}, paths_blocked: ${s.paths_blocked}, secrets_detected: ${s.secrets_detected}`);
  const iv = report.audit_integrity;
  lines.push(`# audit_chain_verified: ${iv.verified}, chain_length: ${iv.chain_length}`);
  lines.push('');

  // Access log
  lines.push('# === Access Log ===');
  lines.push('ts,session_id,tool,path,action,reason');
  for (const r of report.access_log) {
    lines.push([r.ts, r.session_id, r.tool, r.path, r.action, r.reason].map(csvEscape).join(','));
  }

  if (report.blocked_accesses.length) {
    lines.push('');
    lines.push('# === Blocked Accesses ===');
    lines.push('ts,session_id,tool,path,action,reason');
    for (const r of report.blocked_accesses) {
      lines.push([r.ts, r.session_id, r.tool, r.path, r.action, r.reason].map(csvEscape).join(','));
    }
  }

  if (report.secret_events.length) {
    lines.push('');
    lines.push('# === Secret Events ===');
    // path intentionally excluded from CSV secret events (report export must not itself leak paths)
    lines.push('ts,session_id,tool,secrets_redacted,action');
    for (const r of report.secret_events) {
      lines.push([r.ts, r.session_id, r.tool, r.secrets_redacted, r.action].map(csvEscape).join(','));
    }
  }

  return lines.join('\n');
}

// ── CLI entry point ───────────────────────────────────────────────────────────

function runReportCli(args) {
  const formatIdx = (args || []).indexOf('--format');
  const format    = formatIdx >= 0 ? (args[formatIdx + 1] || 'json') : 'json';
  const daysIdx   = (args || []).indexOf('--days');
  const days      = daysIdx  >= 0 ? (parseInt(args[daysIdx + 1], 10) || 30) : 30;

  if (format !== 'json' && format !== 'csv') {
    process.stderr.write(`[Occasio] report: unknown format "${format}", use json or csv\n`);
    process.exit(1);
  }

  const report = buildReport(days);

  if (format === 'csv') {
    process.stdout.write(toCsv(report) + '\n');
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
}

module.exports = { runReportCli, buildReport };
