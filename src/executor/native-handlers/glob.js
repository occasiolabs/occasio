'use strict';

/**
 * Native handler for the Glob tool.
 *
 * Pure filesystem function: takes a glob pattern (+ optional base path) and
 * returns a sorted list of matching paths. No dependency on the interceptor
 * pipeline, Anthropic API, or shell execution. Safe to import in any process
 * context.
 *
 * Extracted from src/runtime.js as Stage-2 Step 3 of the executor migration
 * (see docs/ADAPTER-STAGE-2-MIGRATION.md). src/runtime.js re-exports these
 * so existing consumers keep working unchanged.
 */

const fs   = require('fs');
const path = require('path');

// ── Glob tool support ──────────────────────────────────────────────────────────

// Characters that indicate shell injection in a glob pattern.
// We reject patterns containing these so handleGlobTool stays read-only.
const GLOB_INJECTION_RE = /[;&|`$<>!]/;

// Directories skipped during recursive glob walks.
const GLOB_SKIP = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', '__pycache__', '.venv', 'venv']);

// Maximum number of matches returned to avoid overwhelming the model context.
const GLOB_MAX = 500;

// Maximum recursion depth from baseDir. Hard cap on path-traversal DoS
// (a fuzz-discovered class — see THREAT-MODEL.md residual risk #5).
// Tunable via env for special-case repos.
const GLOB_MAX_DEPTH = Number(process.env.OCCASIO_GLOB_MAX_DEPTH) || 16;

// Soft wall-clock limit per walk in ms. Stops a walk that strayed onto a huge
// subtree (e.g. agent globbed up from /) before it burns seconds. Stop is
// best-effort — the caller still receives whatever was collected so far.
const GLOB_MAX_MS = Number(process.env.OCCASIO_GLOB_MAX_MS) || 2_000;

function isGlobHandleable(input) {
  if (!input || typeof input !== 'object') return false;
  const pattern = input.pattern;
  if (!pattern || typeof pattern !== 'string' || !pattern.trim()) return false;
  if (GLOB_INJECTION_RE.test(pattern)) return false;
  if (input.path != null && typeof input.path !== 'string') return false;
  return true;
}

// Escape regex metacharacters in a literal string segment.
function escapeRegexChars(s) {
  return s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/**
 * Convert a glob pattern to a RegExp.
 * Supports: ** (any path depth), * (single segment), ? (single char),
 * {ts,tsx} (alternation), [abc] (character classes).
 * Exported for unit testing.
 */
function globToRegex(pattern) {
  // Normalise Windows separators in the pattern.
  const p = pattern.replace(/\\/g, '/');

  let re = '';
  let i = 0;
  while (i < p.length) {
    // ** — match any path segments (including none), consuming the trailing /
    if (p[i] === '*' && p[i + 1] === '*') {
      re += '.*';
      i += 2;
      if (p[i] === '/') i++; // consume separator after **
      continue;
    }
    // * — match within a single path segment
    if (p[i] === '*') { re += '[^/]*'; i++; continue; }
    // ? — match a single character within a segment
    if (p[i] === '?') { re += '[^/]'; i++; continue; }
    // {a,b,c} — alternation
    if (p[i] === '{') {
      const end = p.indexOf('}', i);
      if (end !== -1) {
        const alts = p.slice(i + 1, end).split(',').map(escapeRegexChars);
        re += `(?:${alts.join('|')})`;
        i = end + 1;
        continue;
      }
    }
    // [abc] / [^abc] — pass character classes through verbatim
    if (p[i] === '[') {
      const end = p.indexOf(']', i);
      if (end !== -1) { re += p.slice(i, end + 1); i = end + 1; continue; }
    }
    re += escapeRegexChars(p[i]);
    i++;
  }

  // On Windows, matching is case-insensitive; on POSIX it's case-sensitive.
  const flags = process.platform === 'win32' ? 'i' : '';
  return new RegExp(`^${re}$`, flags);
}

/**
 * Walk `dir` recursively, collecting paths that match `regex`.
 * Results are relative to `baseDir`.
 */
function walkGlob(dir, baseDir, regex, results, depth = 0, deadline = Infinity) {
  if (results.length >= GLOB_MAX) return;
  if (depth >= GLOB_MAX_DEPTH) return;
  if (Date.now() >= deadline) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const entry of entries) {
    if (results.length >= GLOB_MAX) break;
    if (Date.now() >= deadline) break;
    if (GLOB_SKIP.has(entry.name)) continue;
    const abs     = path.join(dir, entry.name);
    // Normalise to forward slashes for matching (consistent on all platforms).
    const rel     = path.relative(baseDir, abs).replace(/\\/g, '/');
    if (entry.isDirectory()) {
      walkGlob(abs, baseDir, regex, results, depth + 1, deadline);
    } else if (regex.test(rel)) {
      results.push(rel);
    }
  }
}

/**
 * Resolve glob pattern + optional base path to a sorted list of matching paths,
 * relative to CWD.  Returns { output, exitCode, matchCount }.
 */
function handleGlobTool(input) {
  const pattern = (typeof input?.pattern === 'string' ? input.pattern : '').trim();
  if (!pattern) return { output: '(no pattern provided)', exitCode: 1, matchCount: 0 };

  const baseDir = input?.path
    ? path.resolve(process.cwd(), input.path)
    : process.cwd();

  const cwd = process.cwd();

  let regex;
  try { regex = globToRegex(pattern); }
  catch (e) { return { output: `Glob: invalid pattern: ${e.message}`, exitCode: 1, matchCount: 0 }; }

  const results = [];
  const deadline = Date.now() + GLOB_MAX_MS;
  walkGlob(baseDir, baseDir, regex, results, 0, deadline);
  const timedOut = Date.now() >= deadline;
  results.sort();

  const truncated = results.length >= GLOB_MAX;
  const lines = results.map(r => path.join(baseDir !== cwd ? baseDir : '', r).replace(/\\/g, '/'));
  const suffix = truncated ? `\n(truncated at ${GLOB_MAX} results)`
               : timedOut  ? `\n(truncated — walk exceeded ${GLOB_MAX_MS} ms)`
               : '';
  const output = lines.join('\n') + suffix;
  return { output: output || '(no matches)', exitCode: 0, matchCount: results.length };
}

module.exports = {
  GLOB_INJECTION_RE,
  GLOB_SKIP,
  GLOB_MAX,
  GLOB_MAX_DEPTH,
  GLOB_MAX_MS,
  isGlobHandleable,
  globToRegex,
  walkGlob,
  handleGlobTool,
};
