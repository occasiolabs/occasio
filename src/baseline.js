'use strict';

/**
 * baseline.js — per-project agent behaviour baseline + anomaly detection.
 *
 * Reads ~/.localfirst/logs/*.jsonl, groups by run_id, and builds a frequency
 * profile of tool usage scoped to a single project root (cwd). A subsequent
 * `compare` pass flags any session whose tool calls deviate from that profile
 * — new paths, new tool categories, new shell verbs, or volume spikes.
 *
 * Storage: ~/.localfirst/baseline/<cwd-hash>.json. One file per project root.
 * Mining is opt-in (`localfirst baseline learn`), comparison is opt-in
 * (`localfirst baseline compare`). The proxy never auto-records or auto-checks.
 *
 * Schema requirement: log entries must have a `cwd` field. Entries without
 * `cwd` are silently skipped — they predate v0.6.3.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const LOG_DIR      = path.join(os.homedir(), '.localfirst', 'logs');
const BASELINE_DIR = path.join(os.homedir(), '.localfirst', 'baseline');

// Patterns that bump severity to "high" regardless of baseline novelty.
// Read of any of these is treated as a high-severity anomaly even when the
// baseline is empty (cold-start protection for the most-sensitive locations).
const SENSITIVE_PATH_PATTERNS = [
  /[\\/]\.ssh([\\/]|$)/i,
  /[\\/]\.aws([\\/]|$)/i,
  /[\\/]\.gnupg([\\/]|$)/i,
  /[\\/]\.gcloud([\\/]|$)/i,
  /[\\/]\.azure([\\/]|$)/i,
  /[\\/]credentials([\\/]|$)/i,
  /[\\/]secrets([\\/]|$)/i,
  /[\\/]\.env([\\/.]|$)/i,
  /^\/etc\/(shadow|passwd|sudoers)/,
  /[\\/]private[\\/]/i,
];

// Shell verbs whose first occurrence is always at least medium severity.
// Network-touching / destructive / privilege-escalating commands.
const HIGH_RISK_SHELL_VERBS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'ssh', 'scp', 'sftp', 'rsync',
  'rm', 'rmdir', 'dd', 'mkfs', 'format',
  'sudo', 'su', 'doas', 'pkexec',
  'npm', 'pip', 'gem', 'cargo', 'apt', 'brew',
]);

// Tool categories we track in the baseline. Canonical names only.
const TRACKED_TOOLS = new Set([
  'read_file', 'find_files', 'grep',
  'shell_bash', 'shell_powershell',
  'todo_write', 'todo_read',
]);

// ── normalisation ────────────────────────────────────────────────────────────

function normCwd(c) {
  if (!c) return '';
  return process.platform === 'win32' ? c.toLowerCase() : c;
}

function cwdHash(c) {
  return crypto.createHash('sha256').update(normCwd(c)).digest('hex').slice(0, 16);
}

function baselinePathFor(c) {
  return path.join(BASELINE_DIR, `${cwdHash(c)}.json`);
}

// Map an agent-protocol tool name to a canonical category.
function canonicalToolName(name) {
  if (!name) return null;
  const lower = String(name).toLowerCase();
  if (lower === 'read' || lower === 'read_file')        return 'read_file';
  if (lower === 'glob' || lower === 'find_files')       return 'find_files';
  if (lower === 'grep')                                  return 'grep';
  if (lower === 'bash' || lower === 'shell_bash')        return 'shell_bash';
  if (lower === 'powershell' || lower === 'shell_powershell') return 'shell_powershell';
  if (lower === 'todowrite' || lower === 'todo_write')   return 'todo_write';
  if (lower === 'todoread'  || lower === 'todo_read')    return 'todo_read';
  return null;
}

function isSensitivePath(p) {
  if (!p || typeof p !== 'string') return false;
  return SENSITIVE_PATH_PATTERNS.some(re => re.test(p));
}

function firstWord(cmd) {
  if (!cmd || typeof cmd !== 'string') return null;
  const m = cmd.trim().match(/^([A-Za-z][\w.+-]*)/);
  return m ? m[1].toLowerCase() : null;
}

// ── log reading ──────────────────────────────────────────────────────────────

function readRecentEntries({ days = 30 } = {}) {
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  let files = [];
  try { files = fs.readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')); }
  catch { return []; }
  files.sort();
  const entries = [];
  for (const f of files) {
    let text;
    try { text = fs.readFileSync(path.join(LOG_DIR, f), 'utf8'); } catch { continue; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line);
        if (!e.iso) continue;
        if (new Date(e.iso).getTime() < cutoff) continue;
        entries.push(e);
      } catch { /* skip malformed */ }
    }
  }
  return entries;
}

function filterByCwd(entries, c) {
  const target = normCwd(c);
  return entries.filter(e => normCwd(e.cwd) === target);
}

function groupByRun(entries) {
  const runs = new Map();
  for (const e of entries) {
    const k = e.run_id || '__nokey__';
    if (!runs.has(k)) runs.set(k, []);
    runs.get(k).push(e);
  }
  return Array.from(runs.values());
}

// Extract per-tool-call records from a run.
// Each record: { tool, path, verb }  (path/verb may be null)
function extractToolCalls(run) {
  const out = [];
  for (const entry of run) {
    if (!Array.isArray(entry.tools)) continue;
    for (const t of entry.tools) {
      const canonical = canonicalToolName(t.tool);
      if (!canonical || !TRACKED_TOOLS.has(canonical)) continue;
      const rec = { tool: canonical, path: null, verb: null };
      if (canonical === 'read_file' || canonical === 'find_files' || canonical === 'grep') {
        if (t.cmd && typeof t.cmd === 'string') rec.path = t.cmd;
      } else if (canonical === 'shell_bash' || canonical === 'shell_powershell') {
        rec.verb = firstWord(t.cmd);
      }
      out.push(rec);
    }
  }
  return out;
}

// ── mining ───────────────────────────────────────────────────────────────────

function median(arr) {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function quantile(arr, q) {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * q));
  return sorted[idx];
}

/**
 * Build a baseline object from a list of run-grouped tool-call records.
 * Pure function — does not touch the filesystem.
 *
 * @param {Array<Array<object>>} runRecords  output of extractToolCalls per run
 * @param {object} meta  { project_root }
 * @returns {object} baseline
 */
function buildBaseline(runRecords, meta = {}) {
  const tools  = {};
  const paths  = {};
  const verbs  = {};
  const counts = [];

  for (const run of runRecords) {
    counts.push(run.length);
    const seenInRun = { tools: new Set(), paths: new Set(), verbs: new Set() };
    for (const r of run) {
      tools[r.tool] = tools[r.tool] || { count: 0, sessions: 0 };
      tools[r.tool].count += 1;
      seenInRun.tools.add(r.tool);
      if (r.path) {
        paths[r.path] = paths[r.path] || { count: 0, sessions: 0 };
        paths[r.path].count += 1;
        seenInRun.paths.add(r.path);
      }
      if (r.verb) {
        verbs[r.verb] = verbs[r.verb] || { count: 0, sessions: 0 };
        verbs[r.verb].count += 1;
        seenInRun.verbs.add(r.verb);
      }
    }
    for (const t of seenInRun.tools) tools[t].sessions += 1;
    for (const p of seenInRun.paths) paths[p].sessions += 1;
    for (const v of seenInRun.verbs) verbs[v].sessions += 1;
  }

  return {
    schema_version: 1,
    generated_at:   new Date().toISOString(),
    project_root:   meta.project_root || null,
    session_count:  runRecords.length,
    tools, paths, verbs,
    session_tool_counts: {
      median: median(counts),
      p75:    quantile(counts, 0.75),
      p95:    quantile(counts, 0.95),
      max:    counts.length ? Math.max(...counts) : 0,
    },
  };
}

/**
 * High-level mining: read logs for the last N days, scope to the given
 * project root, return a baseline object. Does not write to disk.
 */
function mineBaseline({ cwd, days = 30 } = {}) {
  if (!cwd) throw new Error('mineBaseline requires { cwd }');
  const all   = readRecentEntries({ days });
  const scoped = filterByCwd(all, cwd);
  const runs   = groupByRun(scoped);
  const runRecords = runs.map(extractToolCalls);
  return buildBaseline(runRecords, { project_root: cwd });
}

// ── comparison ───────────────────────────────────────────────────────────────

/**
 * Compare a session (array of tool-call records) against a baseline.
 * Returns { anomalies: [...], summary: {...} }.
 *
 * Anomaly types:
 *   new_path        — path not in baseline
 *   new_tool        — tool category not in baseline
 *   new_shell_verb  — shell verb not in baseline
 *   sensitive_path  — read of a path in SENSITIVE_PATH_PATTERNS (always high)
 *   volume_spike    — session tool count exceeds baseline.p95 × 1.5
 */
function compareSession(session, baseline) {
  const anomalies = [];
  const baseTools = (baseline && baseline.tools) || {};
  const basePaths = (baseline && baseline.paths) || {};
  const baseVerbs = (baseline && baseline.verbs) || {};
  const baseSessions = (baseline && baseline.session_count) || 0;
  const lowConfidence = baseSessions < 5;

  const seenPaths = new Set();
  const seenVerbs = new Set();
  const seenTools = new Set();

  for (const r of session) {
    // Sensitive path: always flag, regardless of baseline state
    if (r.path && isSensitivePath(r.path)) {
      anomalies.push({
        type: 'sensitive_path',
        detail: `${r.tool} ${r.path}`,
        severity: 'high',
      });
    }
    // New tool category
    if (!seenTools.has(r.tool)) {
      seenTools.add(r.tool);
      if (!baseTools[r.tool] && baseSessions > 0) {
        anomalies.push({
          type: 'new_tool',
          detail: r.tool,
          severity: 'medium',
        });
      }
    }
    // New path (read_file / find_files / grep)
    if (r.path && !seenPaths.has(r.path)) {
      seenPaths.add(r.path);
      if (!basePaths[r.path] && baseSessions > 0 && !isSensitivePath(r.path)) {
        anomalies.push({
          type: 'new_path',
          detail: `${r.tool} ${r.path}`,
          severity: 'medium',
        });
      }
    }
    // New shell verb
    if (r.verb && !seenVerbs.has(r.verb)) {
      seenVerbs.add(r.verb);
      if (!baseVerbs[r.verb] && baseSessions > 0) {
        anomalies.push({
          type: 'new_shell_verb',
          detail: r.verb,
          severity: HIGH_RISK_SHELL_VERBS.has(r.verb) ? 'high' : 'medium',
        });
      }
    }
  }

  // Volume spike: only when baseline has enough data to define "normal"
  if (baseSessions >= 5 && session.length > 0) {
    const p95 = baseline.session_tool_counts.p95 || 0;
    if (p95 > 0 && session.length > p95 * 1.5) {
      anomalies.push({
        type: 'volume_spike',
        detail: `${session.length} tool calls (baseline p95 ${p95})`,
        severity: session.length > p95 * 3 ? 'high' : 'medium',
      });
    }
  }

  return {
    anomalies,
    summary: {
      session_tool_calls: session.length,
      baseline_sessions:  baseSessions,
      low_confidence:     lowConfidence,
      high_severity:      anomalies.filter(a => a.severity === 'high').length,
      medium_severity:    anomalies.filter(a => a.severity === 'medium').length,
    },
  };
}

// ── persistence ──────────────────────────────────────────────────────────────

function readBaseline(c) {
  try {
    const text = fs.readFileSync(baselinePathFor(c), 'utf8');
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function writeBaseline(c, baseline) {
  if (!fs.existsSync(BASELINE_DIR)) fs.mkdirSync(BASELINE_DIR, { recursive: true });
  fs.writeFileSync(baselinePathFor(c), JSON.stringify(baseline, null, 2));
  return baselinePathFor(c);
}

function deleteBaseline(c) {
  try { fs.unlinkSync(baselinePathFor(c)); return true; } catch { return false; }
}

// ── renderers ────────────────────────────────────────────────────────────────

const C = (() => {
  if (process.env.NO_COLOR || !process.stdout.isTTY) {
    return new Proxy({}, { get: () => (s) => s });
  }
  return {
    b: (s) => `\x1b[1m${s}\x1b[0m`,
    d: (s) => `\x1b[2m${s}\x1b[0m`,
    g: (s) => `\x1b[32m${s}\x1b[0m`,
    y: (s) => `\x1b[33m${s}\x1b[0m`,
    r: (s) => `\x1b[31m${s}\x1b[0m`,
    c: (s) => `\x1b[36m${s}\x1b[0m`,
  };
})();

function fmtBaseline(b) {
  if (!b) return '\n  (no baseline)\n';
  const lines = [];
  lines.push('');
  lines.push(`  ${C.b('Project:')}        ${b.project_root || '(unknown)'}`);
  lines.push(`  ${C.b('Generated:')}      ${b.generated_at}`);
  lines.push(`  ${C.b('Sessions:')}       ${b.session_count}`);
  lines.push('');
  lines.push(`  ${C.b('Tool categories used:')}`);
  for (const [t, v] of Object.entries(b.tools || {}).sort((a, b) => b[1].count - a[1].count)) {
    lines.push(`    ${t.padEnd(18)} ${String(v.count).padStart(5)} calls   in ${v.sessions} session(s)`);
  }
  lines.push('');
  const pathEntries = Object.entries(b.paths || {}).sort((a, b) => b[1].count - a[1].count);
  if (pathEntries.length) {
    lines.push(`  ${C.b('Top paths:')}`);
    for (const [p, v] of pathEntries.slice(0, 10)) {
      lines.push(`    ${v.count.toString().padStart(4)}× ${C.d(p)}`);
    }
    if (pathEntries.length > 10) lines.push(`    ${C.d(`… and ${pathEntries.length - 10} more`)}`);
    lines.push('');
  }
  const verbEntries = Object.entries(b.verbs || {}).sort((a, b) => b[1].count - a[1].count);
  if (verbEntries.length) {
    lines.push(`  ${C.b('Shell verbs:')}`);
    for (const [v, e] of verbEntries) {
      lines.push(`    ${v.padEnd(12)} ${String(e.count).padStart(4)} calls   in ${e.sessions} session(s)`);
    }
    lines.push('');
  }
  const s = b.session_tool_counts || {};
  lines.push(`  ${C.b('Session size:')}   median ${s.median}  p75 ${s.p75}  p95 ${s.p95}  max ${s.max}`);
  return lines.join('\n');
}

function fmtComparison(cmp) {
  const lines = [];
  if (!cmp) return '\n  (no comparison)\n';
  lines.push('');
  const { summary, anomalies } = cmp;
  lines.push(`  ${C.b('Session:')}        ${summary.session_tool_calls} tool calls`);
  lines.push(`  ${C.b('Baseline:')}       ${summary.baseline_sessions} sessions${summary.low_confidence ? C.d('  (low confidence — <5 sessions)') : ''}`);
  if (anomalies.length === 0) {
    lines.push('');
    lines.push(`  ${C.g('✓ No anomalies. Session matches baseline.')}`);
    return lines.join('\n');
  }
  lines.push('');
  lines.push(`  ${C.b('Anomalies:')}      ${C.r(summary.high_severity + ' high')}, ${C.y(summary.medium_severity + ' medium')}`);
  lines.push('');
  for (const a of anomalies) {
    const sev = a.severity === 'high' ? C.r('HIGH  ')
              : a.severity === 'medium' ? C.y('MED   ')
              : C.d('LOW   ');
    lines.push(`    ${sev} ${a.type.padEnd(16)} ${a.detail}`);
  }
  return lines.join('\n');
}

// ── CLI ──────────────────────────────────────────────────────────────────────

function runBaselineCli(args = []) {
  const sub = args[0];
  const daysIdx = args.indexOf('--days');
  const days    = daysIdx >= 0 ? (parseInt(args[daysIdx + 1], 10) || 30) : 30;
  const cwd     = process.cwd();

  if (!sub || sub === 'show') {
    const b = readBaseline(cwd);
    if (!b) {
      process.stdout.write('\n  ' + C.d(`No baseline for this project. Run: ${C.b('localfirst baseline learn')}`) + '\n');
      return { ok: false };
    }
    process.stdout.write(`\n${C.b('LocalFirst Baseline')}\n` + fmtBaseline(b) + '\n');
    return { ok: true };
  }

  if (sub === 'learn') {
    const baseline = mineBaseline({ cwd, days });
    const target = writeBaseline(cwd, baseline);
    process.stdout.write(`\n${C.b('LocalFirst Baseline — learn')}\n`);
    process.stdout.write(`  Source: last ${days} days of logs\n`);
    process.stdout.write(`  Saved:  ${target}\n`);
    process.stdout.write(fmtBaseline(baseline) + '\n');
    return { ok: true, baseline };
  }

  if (sub === 'compare') {
    const baseline = readBaseline(cwd);
    if (!baseline) {
      process.stdout.write('\n  ' + C.d(`No baseline yet. Run: ${C.b('localfirst baseline learn')}`) + '\n');
      return { ok: false };
    }
    // Compare LAST run (most recent run_id) for this cwd.
    const all  = readRecentEntries({ days });
    const scoped = filterByCwd(all, cwd);
    const runs = groupByRun(scoped);
    if (runs.length === 0) {
      process.stdout.write('\n  ' + C.d('No recent sessions for this project to compare.') + '\n');
      return { ok: false };
    }
    // Pick the run whose latest event is the most recent.
    const lastRun = runs
      .map(r => ({ run: r, lastIso: r.reduce((m, e) => Math.max(m, new Date(e.iso || 0).getTime()), 0) }))
      .sort((a, b) => b.lastIso - a.lastIso)[0].run;
    const session = extractToolCalls(lastRun);
    const cmp = compareSession(session, baseline);
    process.stdout.write(`\n${C.b('LocalFirst Baseline — compare')}\n` + fmtComparison(cmp) + '\n');
    return { ok: cmp.anomalies.length === 0, comparison: cmp };
  }

  if (sub === 'reset') {
    const ok = deleteBaseline(cwd);
    process.stdout.write('\n  ' + (ok ? C.g('Baseline deleted.') : C.d('No baseline to delete.')) + '\n');
    return { ok };
  }

  process.stdout.write('\n  ' + C.r(`Unknown subcommand: ${sub}`) + '\n');
  process.stdout.write('  ' + C.d('Use: localfirst baseline [learn|show|compare|reset]') + '\n');
  return { ok: false };
}

module.exports = {
  // pure functions
  buildBaseline, mineBaseline, compareSession,
  extractToolCalls, groupByRun, filterByCwd,
  canonicalToolName, isSensitivePath, firstWord,
  // io
  readBaseline, writeBaseline, deleteBaseline, baselinePathFor,
  readRecentEntries,
  // renderers
  fmtBaseline, fmtComparison,
  // cli
  runBaselineCli,
  // exported for tests
  TRACKED_TOOLS, SENSITIVE_PATH_PATTERNS, HIGH_RISK_SHELL_VERBS,
};
