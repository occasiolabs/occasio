'use strict';

/**
 * Preflight pattern miner (ARCH-26, read-only).
 *
 * Reads ~/.occasio/logs/*.jsonl, groups entries by run_id, and identifies
 * which tool calls appear consistently at the start of sessions for a given
 * project root. No execution, no caching, no side effects.
 *
 * Schema requirement: log entries must have a `cwd` field (added in v0.6.3).
 * Entries without `cwd` are silently skipped; the mine() output will show
 * how many cwd-tagged sessions were found.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

const LOG_DIR = path.join(os.homedir(), '.occasio');

// Only mine these tool types. Shell commands are too variable to be useful
// as preflight candidates; todo tools carry no path information.
const MINEABLE_TOOLS = new Set([
  'Read', 'Glob', 'Grep',           // Claude Code agent-protocol names
  'read_file', 'find_files', 'grep', // Cline / canonical names
]);

// Number of tools to consider "early in session" (per ARCH-26 design)
const EARLY_TOOL_LIMIT = 5;

// Minimum sessions before a pattern is surfaced
const MIN_SESSIONS_FOR_PATTERN = 3;

// -------------------------------------------------------------------
// Normalization helpers
// -------------------------------------------------------------------

function normalizeToolName(name) {
  if (name === 'Read'     || name === 'read_file')  return 'read';
  if (name === 'Glob'     || name === 'find_files') return 'glob';
  if (name === 'Grep'     || name === 'grep')       return 'grep';
  return (name || 'unknown').toLowerCase();
}

// Make a path relative to a root directory.
// Returns the basename if the path is outside the root (e.g. cross-drive on Windows).
function relativize(root, absPath) {
  if (!root || !absPath) return absPath || '';
  try {
    const rel = path.relative(root, absPath);
    // Starts with '..' means outside root — fall back to basename for readability
    return rel.startsWith('..') ? path.basename(absPath) : rel;
  } catch {
    return absPath;
  }
}

// Build a stable, comparable key for a tool call within a project.
// Read: key on relative file path (the cmd field is the absolute path).
// Glob / Grep: key on the pattern string (cmd is the pattern).
// Shell / other: excluded by MINEABLE_TOOLS guard before this is called.
function buildToolKey(toolRecord, projectRoot) {
  const name = normalizeToolName(toolRecord.tool);
  const cmd  = toolRecord.cmd || '';

  if (name === 'read') {
    const rel = relativize(projectRoot, cmd);
    return `${name}:${rel}`;
  }
  // glob and grep: cmd is already the pattern string
  return `${name}:${cmd}`;
}

// -------------------------------------------------------------------
// Git root detection (cached, non-fatal)
// -------------------------------------------------------------------

const _gitRootCache = new Map();

function getGitRoot(dir) {
  if (!dir) return null;
  if (_gitRootCache.has(dir)) return _gitRootCache.get(dir);
  try {
    if (!fs.existsSync(dir)) {
      _gitRootCache.set(dir, null);
      return null;
    }
    const raw = execSync('git rev-parse --show-toplevel', {
      cwd: dir,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 2000,
    }).toString().trim();
    // Normalize separators so Windows forward-slash git output matches path.resolve()
    const normalized = raw.split('/').join(path.sep);
    _gitRootCache.set(dir, normalized);
    return normalized;
  } catch {
    _gitRootCache.set(dir, null);
    return null;
  }
}

// -------------------------------------------------------------------
// Log reading
// -------------------------------------------------------------------

function readRecentEntries(days, logsDir) {
  const dir = logsDir || path.join(LOG_DIR, 'logs');
  const entries = [];
  try {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const files = fs.readdirSync(dir)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
      .filter(f => {
        try { return new Date(f.slice(0, 10)) >= cutoff; } catch { return false; }
      })
      .sort(); // chronological; oldest first
    for (const f of files) {
      const raw = fs.readFileSync(path.join(dir, f), 'utf8');
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try { entries.push(JSON.parse(trimmed)); } catch { /* ignore */ }
      }
    }
  } catch { /* ignore */ }
  return entries;
}

// -------------------------------------------------------------------
// Run grouping and early-tool extraction
// -------------------------------------------------------------------

// Group entries by run_id (entries without run_id are skipped).
// Sort each group's entries by iso timestamp ascending.
function groupByRun(entries) {
  const map = new Map();
  for (const e of entries) {
    if (!e.run_id) continue;
    if (!map.has(e.run_id)) map.set(e.run_id, []);
    map.get(e.run_id).push(e);
  }
  for (const arr of map.values()) {
    arr.sort((a, b) => {
      const ai = a.iso || a.ts || '';
      const bi = b.iso || b.ts || '';
      return ai < bi ? -1 : ai > bi ? 1 : 0;
    });
  }
  return map;
}

// Pick cwd from the first entry in a run that carries the field.
// Returns null for runs logged before cwd was added to the schema.
function runCwd(runEntries) {
  for (const e of runEntries) {
    if (typeof e.cwd === 'string' && e.cwd) return e.cwd;
  }
  return null;
}

// Extract the first EARLY_TOOL_LIMIT mineable tool calls across all entries
// of a run, in chronological order of the entries they appear in.
function earlyTools(runEntries, limit) {
  const result = [];
  for (const entry of runEntries) {
    if (!Array.isArray(entry.tools)) continue;
    for (const t of entry.tools) {
      if (!MINEABLE_TOOLS.has(t.tool)) continue;
      result.push(t);
      if (result.length >= limit) return result;
    }
  }
  return result;
}

// -------------------------------------------------------------------
// Median helper
// -------------------------------------------------------------------

function median(arr) {
  if (!arr.length) return 1;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid    = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

// -------------------------------------------------------------------
// Core miner
// -------------------------------------------------------------------

/**
 * Mine opening-move patterns from logs.
 *
 * Options:
 *   days      — how many days of logs to scan (default: 30)
 *   logsDir   — override log directory (for tests)
 *   filterCwd — if provided, only return patterns for this working directory
 *
 * Returns an array of project records, each shaped:
 * {
 *   projectRoot: string,       // git root or raw cwd
 *   totalSessions: number,     // distinct run_ids with cwd for this project
 *   legacySessions: number,    // run_ids seen but lacking cwd field (info only)
 *   tools: Array<{
 *     key: string,             // stable tool key
 *     tool: string,            // 'read' | 'glob' | 'grep'
 *     cmd: string,             // display-friendly target/pattern
 *     count: number,           // sessions that included this tool early
 *     totalSessions: number,   // same as parent.totalSessions
 *     confidence: number,      // count / totalSessions  (0–1)
 *     medianPosition: number,  // 1-indexed median ordinal position in early window
 *   }>
 * }
 */
function mine(opts) {
  const { days = 30, logsDir, filterCwd } = opts || {};

  const entries = readRecentEntries(days, logsDir);
  const runsMap = groupByRun(entries);

  // Determine what project root the caller wants (if filtering)
  let filterRoot = null;
  if (filterCwd) {
    filterRoot = getGitRoot(filterCwd) || filterCwd;
  }

  // project_root → { projectRoot, sessions: Set, toolCounts: Map, legacySessions: number }
  const projects = new Map();

  for (const [, runEntries] of runsMap) {
    const cwd = runCwd(runEntries);
    if (!cwd) {
      // Pre-schema run with no cwd — can't attribute to a project, skip.
      continue;
    }

    const gitRoot     = getGitRoot(cwd);
    const projectRoot = gitRoot || cwd;

    if (filterRoot && projectRoot !== filterRoot) continue;

    if (!projects.has(projectRoot)) {
      projects.set(projectRoot, {
        projectRoot,
        sessions:    new Set(),
        toolCounts:  new Map(),   // toolKey → { count, positions[], tool, cmd }
        legacySessions: 0,
      });
    }

    const proj = projects.get(projectRoot);
    proj.sessions.add(runEntries[0].run_id);

    const tools = earlyTools(runEntries, EARLY_TOOL_LIMIT);
    tools.forEach((t, idx) => {
      const key = buildToolKey(t, projectRoot);
      if (!proj.toolCounts.has(key)) {
        proj.toolCounts.set(key, {
          count:     0,
          positions: [],
          tool:      normalizeToolName(t.tool),
          cmd:       t.cmd || '',
        });
      }
      const rec = proj.toolCounts.get(key);
      rec.count++;
      rec.positions.push(idx + 1); // 1-indexed position in early window
    });
  }

  const result = [];
  for (const [, proj] of projects) {
    const totalSessions = proj.sessions.size;
    if (totalSessions === 0) continue;

    const toolsList = [];
    for (const [key, rec] of proj.toolCounts) {
      const confidence    = rec.count / totalSessions;
      const medianPosition = median(rec.positions);
      toolsList.push({
        key,
        tool:         rec.tool,
        cmd:          rec.cmd,
        count:        rec.count,
        totalSessions,
        confidence,
        medianPosition,
      });
    }

    // Sort: confidence desc, then median position asc (earlier = better preflight candidate)
    toolsList.sort((a, b) =>
      b.confidence - a.confidence || a.medianPosition - b.medianPosition
    );

    result.push({
      projectRoot:    proj.projectRoot,
      totalSessions,
      legacySessions: proj.legacySessions,
      tools:          toolsList,
    });
  }

  return result;
}

module.exports = {
  mine,
  // Exported for testing
  readRecentEntries,
  groupByRun,
  earlyTools,
  buildToolKey,
  normalizeToolName,
  relativize,
  getGitRoot,
  median,
  runCwd,
  EARLY_TOOL_LIMIT,
  MIN_SESSIONS_FOR_PATTERN,
};
