'use strict';

/**
 * localfirst preflight — CLI entry point (ARCH-26, read-only).
 *
 * Usage:
 *   localfirst preflight               Print opening-move pattern table
 *   localfirst preflight --show        Same (alias for future flag compatibility)
 *   localfirst preflight --days N      Use last N days of logs (default: 30)
 *   localfirst preflight --reset       Clear pattern store (available after ARCH-27)
 */

const os   = require('os');
const path = require('path');
const {
  mine,
  getGitRoot,
  MIN_SESSIONS_FOR_PATTERN,
} = require('./miner');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

// Minimum display confidence threshold — patterns below this are not shown
const DISPLAY_THRESHOLD = 0.40;

// Maximum table rows
const MAX_ROWS = 10;

function ordinal(n) {
  const r = Math.round(n);
  if (r === 1) return '1st';
  if (r === 2) return '2nd';
  if (r === 3) return '3rd';
  return `${r}th+`;
}

function truncate(s, maxLen) {
  if (s.length <= maxLen) return s;
  return '…' + s.slice(-(maxLen - 1)); // right-side truncation preserves filename
}

function runPreflightCli(args, opts) {
  const { cwd: cwdOverride, logsDir } = opts || {};

  const daysIdx = (args || []).indexOf('--days');
  const days    = daysIdx >= 0 ? (parseInt(args[daysIdx + 1], 10) || 30) : 30;
  const reset   = (args || []).includes('--reset');

  const cwd         = cwdOverride || process.cwd();
  const gitRoot     = getGitRoot(cwd);
  const projectRoot = gitRoot || cwd;
  const displayRoot = projectRoot.replace(os.homedir(), '~');
  const rootLabel   = gitRoot ? 'git root' : 'directory';

  console.log(col.b('\n⚡ LocalFirst — Opening-move patterns\n'));

  // --reset: placeholder until ARCH-27 adds persistent pattern store
  if (reset) {
    console.log(`  ${col.d(`${displayRoot}  (${rootLabel})`)}`);
    console.log(col.d('\n  Pattern store reset will be available after ARCH-27 (pattern persistence).\n'));
    return { ok: true };
  }

  const allProjects = mine({ days, logsDir, filterCwd: cwd });
  const proj        = allProjects.find(p => p.projectRoot === projectRoot);

  // ── Empty-state handling ─────────────────────────────────────────────────────

  if (!proj || proj.totalSessions === 0) {
    console.log(`  ${col.d(`${displayRoot}  (${rootLabel})`)}`);
    console.log(col.d(`  0 sessions with cwd tracking  \xb7  last ${days} days\n`));
    console.log(col.d(`  No session history found for this project.`));
    if (!proj || proj.totalSessions === 0) {
      console.log(col.d(`  Patterns emerge after ${MIN_SESSIONS_FOR_PATTERN}+ sessions.`));
      console.log(col.d(`  (cwd tracking requires LocalFirst ≥v0.6.3)\n`));
    }
    return { ok: true, totalSessions: 0 };
  }

  if (proj.totalSessions < MIN_SESSIONS_FOR_PATTERN) {
    console.log(`  ${col.d(`${displayRoot}  (${rootLabel})`)}`);
    console.log(col.d(`  ${proj.totalSessions} session${proj.totalSessions !== 1 ? 's' : ''}  \xb7  last ${days} days\n`));
    console.log(col.d(`  Not enough history — patterns emerge after ${MIN_SESSIONS_FOR_PATTERN}+ sessions.\n`));
    return { ok: true, totalSessions: proj.totalSessions };
  }

  // ── Table ────────────────────────────────────────────────────────────────────

  const candidates = proj.tools
    .filter(t => t.confidence >= DISPLAY_THRESHOLD)
    .slice(0, MAX_ROWS);

  console.log(`  ${col.d(`${displayRoot}  (${rootLabel})`)}`);
  console.log(col.d(`  ${proj.totalSessions} sessions  \xb7  last ${days} days  \xb7  first 5 tool calls per session\n`));

  if (!candidates.length) {
    console.log(col.d(`  No consistent patterns found. Sessions in this project vary too much.\n`));
    return { ok: true, totalSessions: proj.totalSessions, candidates: 0 };
  }

  // Column widths
  const W_NUM    = 2;
  const W_TOOL   = 6;
  const W_TARGET = 44;
  const W_SEEN   = 9;
  const W_CONF   = 11;
  const W_POS    = 10;

  const header = [
    '#'.padEnd(W_NUM),
    'Tool'.padEnd(W_TOOL),
    'Target'.padEnd(W_TARGET),
    'Seen'.padStart(W_SEEN),
    'Confidence'.padStart(W_CONF),
    'Position'.padStart(W_POS),
  ].join('  ');

  const divider = [
    '─'.repeat(W_NUM),
    '─'.repeat(W_TOOL),
    '─'.repeat(W_TARGET),
    '─'.repeat(W_SEEN),
    '─'.repeat(W_CONF),
    '─'.repeat(W_POS),
  ].join('  ');

  console.log(`  ${col.d(header)}`);
  console.log(`  ${col.d(divider)}`);

  for (let i = 0; i < candidates.length; i++) {
    const c       = candidates[i];
    const numStr  = String(i + 1).padEnd(W_NUM);
    const toolStr = c.tool.padEnd(W_TOOL);
    const target  = truncate(c.cmd, W_TARGET).padEnd(W_TARGET);
    const seen    = `${c.count} / ${c.totalSessions}`.padStart(W_SEEN);
    const confPct = `${Math.round(c.confidence * 100)}%`.padStart(W_CONF);
    const posStr  = ordinal(c.medianPosition).padStart(W_POS);

    const confColor = c.confidence >= 0.70 ? col.g
                    : c.confidence >= 0.50 ? col.y
                    : col.d;

    console.log(
      `  ${col.d(numStr)}  ${col.c(toolStr)}  ${col.d(target)}  ` +
      `${col.d(seen)}  ${confColor(confPct)}  ${col.d(posStr)}`
    );
  }

  console.log('');
  console.log(col.d(`  Patterns learned locally from tool-usage history, not prompt content.`));
  console.log(col.d(`  Preflight execution is off. Run localfirst with --preflight to enable (coming soon).`));
  console.log(col.d(`  To reset patterns for this project: localfirst preflight --reset\n`));

  return { ok: true, totalSessions: proj.totalSessions, candidates: candidates.length };
}

module.exports = { runPreflightCli };
