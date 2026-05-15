'use strict';

/**
 * Native handler for the Grep tool.
 *
 * Pure filesystem function: takes a regex pattern (+ optional path, glob, type,
 * output_mode, context flags) and returns matches in one of three formats
 * (files_with_matches | content | count). No dependency on the interceptor
 * pipeline, Anthropic API, or shell execution.
 *
 * Extracted from src/runtime.js as Stage-2 Step 4 of the executor migration
 * (see docs/ADAPTER-STAGE-2-MIGRATION.md). src/runtime.js re-exports these so
 * existing consumers keep working unchanged.
 *
 * Imports `globToRegex` and `GLOB_SKIP` from the Glob handler — the Grep file
 * filter shares the glob grammar, and both walks skip the same vendor dirs.
 */

const fs   = require('fs');
const path = require('path');

const { MAX_OUTPUT }                                            = require('./read');
const { globToRegex, GLOB_SKIP, GLOB_MAX_DEPTH, GLOB_MAX_MS }   = require('./glob');

// ── Grep tool support ──────────────────────────────────────────────────────────

const GREP_MAX_RESULTS = 250;   // default output cap — matches Claude Code head_limit default
const GREP_FILE_CAP   = 10_000; // safety limit on files walked before stopping

// File-type → extension mapping, matching ripgrep's --type names.
const GREP_TYPE_EXTS = new Map([
  ['js',   ['.js', '.mjs', '.cjs']],
  ['ts',   ['.ts', '.tsx', '.mts', '.cts']],
  ['py',   ['.py', '.pyi']],
  ['rust', ['.rs']],
  ['go',   ['.go']],
  ['java', ['.java']],
  ['rb',   ['.rb']],
  ['css',  ['.css', '.scss', '.sass', '.less']],
  ['html', ['.html', '.htm']],
  ['json', ['.json', '.jsonc']],
  ['md',   ['.md', '.mdx']],
  ['yaml', ['.yaml', '.yml']],
  ['sh',   ['.sh', '.bash', '.zsh']],
  ['c',    ['.c', '.h']],
  ['cpp',  ['.cpp', '.cc', '.cxx', '.hpp', '.hh']],
]);

const VALID_GREP_MODES = new Set(['content', 'files_with_matches', 'count']);

function isGrepHandleable(input) {
  if (!input || typeof input !== 'object') return false;
  const pattern = input.pattern;
  if (!pattern || typeof pattern !== 'string' || !pattern.trim()) return false;
  // Optional fields must be the right type when present.
  if (input.path        != null && typeof input.path        !== 'string')  return false;
  if (input.glob        != null && typeof input.glob        !== 'string')  return false;
  if (input.type        != null && typeof input.type        !== 'string')  return false;
  if (input.output_mode != null && !VALID_GREP_MODES.has(input.output_mode)) return false;
  // Cross-line matching (rg -U) requires full-file regex — not supported natively.
  if (input.multiline === true) return false;
  return true;
}

// Read a file for grep: returns null for binary files or on read error.
function tryReadGrep(absPath) {
  try {
    const buf = fs.readFileSync(absPath);
    if (buf.slice(0, 512).includes(0)) return null;  // binary file — skip
    return (buf.length > MAX_OUTPUT ? buf.slice(0, MAX_OUTPUT) : buf).toString('utf8');
  } catch { return null; }
}

// Walk directory collecting absolute file paths, honouring glob and type filters.
function walkGrepFiles(dir, baseDir, globRegex, globHasDir, typeExts, results, depth = 0, deadline = Infinity) {
  if (results.length >= GREP_FILE_CAP) return;
  if (depth >= GLOB_MAX_DEPTH) return;
  if (Date.now() >= deadline) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }
  for (const entry of entries) {
    if (results.length >= GREP_FILE_CAP) break;
    if (Date.now() >= deadline) break;
    if (GLOB_SKIP.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkGrepFiles(abs, baseDir, globRegex, globHasDir, typeExts, results, depth + 1, deadline);
    } else {
      if (typeExts && !typeExts.includes(path.extname(abs).toLowerCase())) continue;
      if (globRegex) {
        // Glob patterns with path separators match against the relative path;
        // plain filename globs (e.g. "*.ts") match against the basename only.
        const testStr = globHasDir
          ? path.relative(baseDir, abs).replace(/\\/g, '/')
          : path.basename(abs);
        if (!globRegex.test(testStr)) continue;
      }
      results.push(abs);
    }
  }
}

/**
 * Execute a structured Grep tool call locally.
 *
 * Supports: pattern, path, glob, type, output_mode (files_with_matches | content | count),
 * -i (case-insensitive), -C / context / -A / -B (context lines), head_limit, offset.
 *
 * Does NOT support multiline (cross-line regex) — isGrepHandleable rejects those.
 */
function handleGrepTool(input) {
  const pattern = (typeof input?.pattern === 'string' ? input.pattern : '').trim();
  if (!pattern) return { output: '(no pattern provided)', exitCode: 1, matchCount: 0 };

  const searchRoot = input?.path
    ? path.resolve(process.cwd(), input.path)
    : process.cwd();

  const outputMode  = input?.output_mode || 'files_with_matches';
  const caseInsens  = input?.['-i'] === true;
  const contextN    = typeof input?.['-C'] === 'number' ? input['-C'] :
                      typeof input?.context === 'number' ? input.context : 0;
  const linesBefore = typeof input?.['-B'] === 'number' ? input['-B'] : contextN;
  const linesAfter  = typeof input?.['-A'] === 'number' ? input['-A'] : contextN;
  const headLimit   = typeof input?.head_limit === 'number' && input.head_limit > 0
    ? Math.min(input.head_limit, GREP_MAX_RESULTS)
    : GREP_MAX_RESULTS;
  const skipLines   = typeof input?.offset === 'number' && input.offset > 0 ? input.offset : 0;

  let regex;
  try {
    regex = new RegExp(pattern, 'g' + (caseInsens ? 'i' : ''));
  } catch (e) {
    return { output: `Grep: invalid pattern: ${e.message}`, exitCode: 1, matchCount: 0 };
  }

  // Build type extension filter.
  let typeExts = null;
  if (input?.type) {
    const t = input.type.toLowerCase();
    typeExts = GREP_TYPE_EXTS.get(t) || [t.startsWith('.') ? t : `.${t}`];
  }

  // Build glob file filter.
  let globRegex  = null;
  let globHasDir = false;
  if (input?.glob) {
    try {
      globRegex  = globToRegex(input.glob);
      globHasDir = input.glob.includes('/') || input.glob.includes('**');
    } catch { /* ignore invalid glob — no filter applied */ }
  }

  // Collect candidate files.
  let files = [];
  const deadline = Date.now() + GLOB_MAX_MS;
  try {
    const stat = fs.statSync(searchRoot);
    if (stat.isFile()) {
      files.push(searchRoot);
    } else {
      walkGrepFiles(searchRoot, searchRoot, globRegex, globHasDir, typeExts, files, 0, deadline);
      files.sort();
    }
  } catch (e) {
    return { output: `Grep: cannot access path: ${e.message}`, exitCode: 1, matchCount: 0 };
  }

  const outputLines = [];
  let totalMatches  = 0;
  let truncated     = false;
  // wantMore also enforces the per-call wall-clock budget so the
  // file-read+match loop can't blow past it even if walkGrepFiles already
  // collected thousands of paths before the walk-deadline tripped.
  const wantMore    = () => outputLines.length < skipLines + headLimit
                         && Date.now() < deadline;
  const relOf       = abs => path.relative(searchRoot, abs).replace(/\\/g, '/') || path.basename(abs);

  if (outputMode === 'files_with_matches') {
    for (const absFile of files) {
      if (!wantMore()) { truncated = true; break; }
      const content = tryReadGrep(absFile);
      if (!content) continue;
      regex.lastIndex = 0;
      if (regex.test(content)) { totalMatches++; outputLines.push(relOf(absFile)); }
    }

  } else if (outputMode === 'count') {
    for (const absFile of files) {
      if (!wantMore()) { truncated = true; break; }
      const content = tryReadGrep(absFile);
      if (!content) continue;
      let count = 0;
      for (const line of content.split('\n')) { regex.lastIndex = 0; if (regex.test(line)) count++; }
      if (count > 0) { totalMatches += count; outputLines.push(`${relOf(absFile)}:${count}`); }
    }

  } else {  // content
    for (const absFile of files) {
      if (!wantMore()) { truncated = true; break; }
      const content = tryReadGrep(absFile);
      if (!content) continue;
      const fileLabel = relOf(absFile);
      const fileLines = content.split('\n');
      const matchSet  = new Set();
      for (let i = 0; i < fileLines.length; i++) {
        regex.lastIndex = 0;
        if (regex.test(fileLines[i])) matchSet.add(i);
      }
      if (!matchSet.size) continue;
      totalMatches += matchSet.size;

      // Merge context windows into non-overlapping groups.
      const sorted = [...matchSet].sort((a, b) => a - b);
      const groups = [];
      let gs = -1, ge = -1;
      for (const idx of sorted) {
        const s = Math.max(0, idx - linesBefore);
        const e = Math.min(fileLines.length - 1, idx + linesAfter);
        if (gs === -1) { gs = s; ge = e; }
        else if (s <= ge + 1) { ge = Math.max(ge, e); }
        else { groups.push([gs, ge]); gs = s; ge = e; }
      }
      if (gs !== -1) groups.push([gs, ge]);

      let firstGroup = true;
      for (const [gStart, gEnd] of groups) {
        if (!wantMore()) { truncated = true; break; }
        if (!firstGroup) outputLines.push('--');
        firstGroup = false;
        for (let i = gStart; i <= gEnd && wantMore(); i++) {
          const sep = matchSet.has(i) ? ':' : '-';
          outputLines.push(`${fileLabel}${sep}${i + 1}${sep}${fileLines[i]}`);
        }
      }
    }
  }

  const sliced  = outputLines.slice(skipLines, skipLines + headLimit);
  const text    = sliced.join('\n') || '(no matches)';
  const timedOut = Date.now() >= deadline;
  const suffix  = truncated ? '\n(truncated — use head_limit/offset to paginate)'
                : timedOut  ? `\n(truncated — walk exceeded ${GLOB_MAX_MS} ms)`
                : '';
  return { output: text + suffix, exitCode: 0, matchCount: totalMatches };
}

module.exports = {
  GREP_MAX_RESULTS,
  GREP_FILE_CAP,
  GREP_TYPE_EXTS,
  VALID_GREP_MODES,
  isGrepHandleable,
  tryReadGrep,
  walkGrepFiles,
  handleGrepTool,
};
