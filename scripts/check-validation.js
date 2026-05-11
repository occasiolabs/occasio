'use strict';
/**
 * check-validation.js — Post-session log checker for git interception.
 *
 * Reads interceptor-debug.log and reports whether any unhandled git commands
 * still fell through to the fallback path after a live session.
 *
 * Usage:
 *   node scripts/check-validation.js [--since HH:MM:SS]
 *
 * Examples:
 *   node scripts/check-validation.js                   # default: filter to current session start
 *   node scripts/check-validation.js --since 14:30:00  # override: only entries after 14:30
 *
 * PASS = no git fallback entries in the filtered window
 * FAIL = git fallback entries found (proxy stale or new command shape needs a new slice)
 */

'use strict';
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const LOG_FILE     = path.join(os.homedir(), '.localfirst', 'interceptor-debug.log');
const SESSION_FILE = path.join(os.homedir(), '.localfirst', 'session.json');

function timeToSeconds(hms) {
  if (!hms) return 0;
  const [h, m, s] = hms.split(':').map(Number);
  return h * 3600 + m * 60 + (s || 0);
}

// Extract HH:MM:SS in local time from a date string.
// ISO strings (e.g. "2026-05-08T17:11:50.396Z") are parsed as Date objects so
// UTC is converted to local time before extracting the components.
// Non-ISO formats (e.g. German "08.05.2026 19:11:50") fall back to regex.
function extractTimeStr(str) {
  if (!str) return null;
  const d = new Date(str);
  if (!isNaN(d.getTime())) {
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${h}:${m}:${s}`;
  }
  // Non-ISO fallback: extract first HH:MM:SS pattern literally.
  const match = /(\d{2}):(\d{2}):(\d{2})/.exec(str);
  return match ? `${match[1]}:${match[2]}:${match[3]}` : null;
}

// --since HH:MM:SS overrides; otherwise default to current session start.
const sinceIdx = process.argv.indexOf('--since');
let sinceStr   = sinceIdx >= 0 ? process.argv[sinceIdx + 1] : null;
let sinceSource = '--since flag';

if (!sinceStr) {
  try {
    const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
    sinceStr = extractTimeStr(s.start);
    sinceSource = 'session start';
  } catch { /* no session yet — check all entries */ }
}

const sinceSeconds = timeToSeconds(sinceStr);

// ── distinguish "no session" from "session ran cleanly with no fallbacks" ────
// session.json existing means a proxy session ran. interceptor-debug.log only
// gets populated when fallback events occur (or in --verbose mode). Their
// absence with a present session.json means PASS, not "no sessions ran".

const sessionExists = fs.existsSync(SESSION_FILE);
let sessionInterceptedCount = null;
if (sessionExists) {
  try {
    const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
    sessionInterceptedCount = s.intercepted_count ?? 0;
  } catch {}
}

if (!fs.existsSync(LOG_FILE)) {
  if (!sessionExists) {
    console.log('ℹ  No session and no debug log — no sessions have run yet.');
    process.exit(0);
  }
  if (sessionInterceptedCount > 0) {
    console.log('LocalFirst git-interception validation check');
    console.log('─'.repeat(40));
    console.log(`Session intercepted_count : ${sessionInterceptedCount}`);
    console.log('');
    console.log('✓  PASS — session ran cleanly; no fallback events were recorded.');
    console.log('   (interceptor-debug.log is written only on fallback or --verbose.)');
    process.exit(0);
  }
  console.log('ℹ  Session exists but recorded zero intercepts and no fallback events.');
  console.log('   Run a session that triggers tool calls to validate the path.');
  process.exit(0);
}

const lines   = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean);
const entries = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

// Filter to entries at or after --since time (by HH:MM:SS ts field)
const fresh = sinceSeconds > 0
  ? entries.filter(e => e.ts && timeToSeconds(e.ts) >= sinceSeconds)
  : entries;

// Find entries where unhandled git context-gathering commands appear in cmds.
// Covers all observed shapes:
//   git status / git log --oneline -N       (bare forms, no -C)
//   git -C <path> status / log              (D-1 form, in case it reappears)
//   cd "..." && git status                  (Bash cwd-prefix chain)
//   Set-Location "..."; git status; ...     (PowerShell cwd-prefix chain)
const GIT_ANY = /^git\s+/i;          // any git invocation as the whole cmd
const CD_CHAIN = /^(?:cd|Set-Location)\s+/i;  // cwd-prefix compound chain
const gitFallbacks = fresh.filter(e =>
  Array.isArray(e.cmds) && e.cmds.some(c => GIT_ANY.test(c) || CD_CHAIN.test(c))
);

// ── read session stats ────────────────────────────────────────────────────────

let intercepted = null;
try {
  const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
  intercepted = s.intercepted_count;
} catch {}

// ── report ────────────────────────────────────────────────────────────────────

console.log('LocalFirst git-interception validation check');
console.log('─'.repeat(40));
if (sinceStr) console.log(`Filtering since (${sinceSource}): ${sinceStr}`);
console.log(`Total log entries checked : ${fresh.length}`);
if (intercepted !== null) console.log(`Session intercepted_count : ${intercepted}`);
console.log('');

if (gitFallbacks.length === 0) {
  console.log('✓  PASS — no git fallback entries found.');
  if (intercepted !== null && intercepted > 0) {
    console.log(`   intercepted_count=${intercepted} confirms active interception.`);
  } else if (intercepted === 0) {
    console.log('   ⚠  intercepted_count=0 — no tool intercepts recorded yet.');
    console.log('      Run a session that triggers git commands to confirm.');
  }
  process.exit(0);
} else {
  console.error(`✗  FAIL — ${gitFallbacks.length} git fallback entry(ies) found:`);
  for (const e of gitFallbacks) {
    console.error(`   [${e.ts}] ${e.fallback} | cmds: ${JSON.stringify(e.cmds)}`);
  }
  console.error('');
  console.error('   Likely causes: proxy is running stale code, or a new command shape needs a new slice.');
  console.error('   Check staleness: node scripts/restart-check.js');
  process.exit(1);
}
