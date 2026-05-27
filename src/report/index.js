'use strict';

/**
 * occasio report — structured governance export (ARCH-27).
 *
 * Usage:
 *   occasio report [--format json|csv] [--days N]
 *
 * After the Phase-4 truth-source unification, this command reads exclusively
 * from the hash-chained audit log: tool-call events for behavioral facts,
 * and kind:"request" events for cost/token summaries. Logs/*.jsonl is no
 * longer consulted — the governance export is now fully attested.
 *
 * Outputs a structured document answering:
 *   "What data did the AI agent access, what was blocked, and did any secrets appear?"
 */

const path = require('path');
const os   = require('os');
const { verifyFile } = require('../audit/verifier');
const eventsModel    = require('../models/events');

const LOG_DIR     = path.join(os.homedir(), '.occasio');
const EVENTS_FILE = path.join(LOG_DIR, 'pipeline-events.jsonl');

// ── Helpers ───────────────────────────────────────────────────────────────────

function cutoffIso(days) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

// ── Report builder ────────────────────────────────────────────────────────────

function buildReport(days) {
  const cutoff = cutoffIso(days);
  const periodEvents  = eventsModel.loadEvents({ since: cutoff });
  const requestEvents = periodEvents.filter(e => e.kind === 'request');

  // Unique sessions from chain request rows. Replaces the old per-day log scan;
  // the run_id field is canonical across the chain.
  const sessionIds = new Set(requestEvents.map(e => e.session_id || e.run_id).filter(Boolean));
  const totalCost  = requestEvents.reduce((s, e) => s + (typeof e.cost === 'number' ? e.cost : 0), 0);

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
      sessions:          sessionIds.size,
      requests:          requestEvents.length,
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
