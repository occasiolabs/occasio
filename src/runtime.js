'use strict';

/**
 * runtime.js — Pure deterministic local execution core.
 *
 * Owns the structured tool handlers for Read, Glob, Grep, TodoWrite, and TodoRead.
 * These are pure filesystem / in-memory functions with no dependency on the
 * interceptor pipeline, Anthropic API, or shell execution.  Safe to import in
 * any process context: proxy, MCP server, CLI tools.
 *
 * Also exports executeLocalTool() — a higher-level wrapper that adds distillation,
 * token estimation, and secret scanning to the raw handler results.  Used by
 * mcp-server.js so the MCP path has parity with the interceptor path.
 *
 * Imported by:
 *   interceptor.js — for native tool dispatch inside interceptToolUse
 *   mcp-server.js  — for executeLocalTool (hardened execution wrapper)
 */

const fs   = require('fs');
const path = require('path');
const { distill }      = require('./distiller');
const { estimateTokens, scanSecrets } = require('./analyzer');

// ── Shared constants ───────────────────────────────────────────────────────────

const MAX_OUTPUT = 512 * 1024;  // 512 KB — same cap as exec maxBuffer

// File extensions the native Read handler cannot serve correctly.
// PDFs and images need structured rendering (base64, page extraction) that we
// cannot replicate; Jupyter notebooks need cell-by-cell parsing.  All others
// are treated as UTF-8 text and handled natively.
const READ_SKIP_EXTENSIONS = new Set([
  '.pdf', '.ipynb',
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico',
  '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib',
]);

// ── Shared helper ──────────────────────────────────────────────────────────────

function readFileNative(absPath) {
  const buf = fs.readFileSync(absPath);
  if (buf.length > MAX_OUTPUT) {
    return buf.slice(0, MAX_OUTPUT).toString('utf8') + '\n[truncated — file too large]';
  }
  return buf.toString('utf8');
}

// ── Read tool support ──────────────────────────────────────────────────────────

/**
 * Returns true when this Read input can be served natively.
 * Falls back for PDFs/images (need structured rendering), Jupyter notebooks,
 * malformed input, or the `pages` parameter (implies PDF range extraction).
 */
function isReadHandleable(input) {
  if (!input || typeof input !== 'object') return false;
  const fp = input.file_path;
  if (!fp || typeof fp !== 'string' || !fp.trim()) return false;
  if (input.pages != null) return false;
  const ext = path.extname(fp).toLowerCase();
  return !READ_SKIP_EXTENSIONS.has(ext);
}

/**
 * Read a file natively and return content formatted like `cat -n` (1-based line
 * numbers), honouring the optional offset (0-based line index) and limit fields
 * that the Claude Code Read tool sends for partial reads.
 */
function handleReadTool(input) {
  const fp  = (input?.file_path || '').trim();
  if (!fp) return { output: '(no file_path provided)', exitCode: 1 };

  const abs = path.resolve(process.cwd(), fp);
  try {
    const content = readFileNative(abs);  // already caps at MAX_OUTPUT
    const lines   = content.split('\n');
    const offset  = (typeof input.offset === 'number' && input.offset >= 0) ? input.offset : 0;
    const limit   = (typeof input.limit  === 'number' && input.limit  >  0) ? input.limit  : lines.length;
    const slice   = lines.slice(offset, offset + limit);
    // Line numbers reflect position in the file (not the slice), matching cat -n.
    const formatted = slice.map((l, i) => `${String(offset + i + 1).padStart(6)}\t${l}`).join('\n');
    return { output: formatted, exitCode: 0 };
  } catch (e) {
    const msg = e.code === 'ENOENT'
      ? `${fp}: No such file or directory`
      : `${fp}: ${e.message}`;
    return { output: `Read: ${msg}`, exitCode: 1 };
  }
}

// ── Glob tool support ──────────────────────────────────────────────────────────

// Characters that indicate shell injection in a glob pattern.
// We reject patterns containing these so handleGlobTool stays read-only.
const GLOB_INJECTION_RE = /[;&|`$<>!]/;

// Directories skipped during recursive glob walks.
const GLOB_SKIP = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', '__pycache__', '.venv', 'venv']);

// Maximum number of matches returned to avoid overwhelming the model context.
const GLOB_MAX = 500;

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
function walkGlob(dir, baseDir, regex, results) {
  if (results.length >= GLOB_MAX) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const entry of entries) {
    if (results.length >= GLOB_MAX) break;
    if (GLOB_SKIP.has(entry.name)) continue;
    const abs     = path.join(dir, entry.name);
    // Normalise to forward slashes for matching (consistent on all platforms).
    const rel     = path.relative(baseDir, abs).replace(/\\/g, '/');
    if (entry.isDirectory()) {
      walkGlob(abs, baseDir, regex, results);
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
  const pattern = (input?.pattern || '').trim();
  if (!pattern) return { output: '(no pattern provided)', exitCode: 1, matchCount: 0 };

  const baseDir = input?.path
    ? path.resolve(process.cwd(), input.path)
    : process.cwd();

  // Reject if base path escapes CWD for safety.
  const cwd = process.cwd();
  if (!baseDir.startsWith(cwd) && baseDir !== cwd) {
    // Allow absolute paths outside CWD — Glob is read-only and safe.
  }

  let regex;
  try { regex = globToRegex(pattern); }
  catch (e) { return { output: `Glob: invalid pattern: ${e.message}`, exitCode: 1, matchCount: 0 }; }

  const results = [];
  walkGlob(baseDir, baseDir, regex, results);
  results.sort();

  const truncated = results.length >= GLOB_MAX;
  const lines = results.map(r => path.join(baseDir !== cwd ? baseDir : '', r).replace(/\\/g, '/'));
  const output = lines.join('\n') + (truncated ? `\n(truncated at ${GLOB_MAX} results)` : '');
  return { output: output || '(no matches)', exitCode: 0, matchCount: results.length };
}

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
function walkGrepFiles(dir, baseDir, globRegex, globHasDir, typeExts, results) {
  if (results.length >= GREP_FILE_CAP) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }
  for (const entry of entries) {
    if (results.length >= GREP_FILE_CAP) break;
    if (GLOB_SKIP.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkGrepFiles(abs, baseDir, globRegex, globHasDir, typeExts, results);
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
  const pattern = (input?.pattern || '').trim();
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
  try {
    const stat = fs.statSync(searchRoot);
    if (stat.isFile()) {
      files.push(searchRoot);
    } else {
      walkGrepFiles(searchRoot, searchRoot, globRegex, globHasDir, typeExts, files);
      files.sort();
    }
  } catch (e) {
    return { output: `Grep: cannot access path: ${e.message}`, exitCode: 1, matchCount: 0 };
  }

  const outputLines = [];
  let totalMatches  = 0;
  let truncated     = false;
  const wantMore    = () => outputLines.length < skipLines + headLimit;
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

  const sliced = outputLines.slice(skipLines, skipLines + headLimit);
  const text   = sliced.join('\n') || '(no matches)';
  const suffix = truncated ? '\n(truncated — use head_limit/offset to paginate)' : '';
  return { output: text + suffix, exitCode: 0, matchCount: totalMatches };
}

// ── Todo tool support ──────────────────────────────────────────────────────────
// Moved to src/executor/native-handlers/todo.js as Stage-2 of the executor
// migration (see docs/ADAPTER-STAGE-2-MIGRATION.md). Re-exported here so
// existing consumers (interceptor, tests) keep working unchanged.
const {
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
} = require('./executor/native-handlers/todo');

// ── MCP execution wrapper ──────────────────────────────────────────────────────

/**
 * Execute a normalized local tool call with distillation, token estimation,
 * and secret scanning applied.  Returns a canonical result shape for MCP use.
 *
 * @param {string}   toolName        'read_file' | 'find_files' | 'grep' | 'TodoWrite' | 'TodoRead'
 * @param {object}   normalizedInput Already normalized (via mcp-normalize.js or similar)
 * @param {Array}    [todoStore=[]]  Mutable session todo list (passed through to Todo handlers)
 * @returns {{
 *   content:      string,   // final text to send to the model
 *   exitCode:     number,
 *   outputTokens: number,
 *   bytes:        number,
 *   distilled:    boolean,
 *   distillSaved: number,   // tokens saved by distillation (0 if not distilled)
 *   distillLabel: string|null,
 *   rawContent:   string|null, // original pre-distill content (null if not distilled)
 *   secrets:      Array,    // [{label, line, snippet}]
 *   matchCount?:  number,   // grep / glob only
 *   taskCount?:   number,   // todo only
 * }}
 */
function executeLocalTool(toolName, normalizedInput, todoStore = []) {
  let raw, extra = {};

  if (toolName === 'read_file') {
    raw = handleReadTool(normalizedInput);
  } else if (toolName === 'find_files') {
    raw = handleGlobTool(normalizedInput);
    extra.matchCount = raw.matchCount;
  } else if (toolName === 'grep') {
    raw = handleGrepTool(normalizedInput);
    extra.matchCount = raw.matchCount;
  } else if (toolName === 'TodoWrite') {
    raw = handleTodoWriteTool(normalizedInput, todoStore);
    extra.taskCount = raw.taskCount;
  } else if (toolName === 'TodoRead') {
    raw = handleTodoReadTool(todoStore);
    extra.taskCount = raw.taskCount;
  } else {
    return {
      content: `Unknown tool: ${toolName}`, exitCode: 1,
      outputTokens: 0, bytes: 0,
      distilled: false, distillSaved: 0, distillLabel: null, rawContent: null,
      secrets: [],
    };
  }

  const rawOutput = raw.output;
  const bytes     = Buffer.byteLength(rawOutput, 'utf8');

  // Choose synthetic cmd string so classifyCmd fires correctly.
  let distillCmd;
  if (toolName === 'grep') {
    distillCmd = 'grep ' + (normalizedInput.pattern || '');
  } else if (toolName === 'find_files') {
    distillCmd = 'find . -name ' + (normalizedInput.pattern || '');
  } else {
    // read_file and todo tools: no distillation category — pass file path so
    // classifyCmd returns null and the output passes through unchanged.
    distillCmd = normalizedInput.file_path || toolName;
  }

  const dr = distill(distillCmd, rawOutput);
  const content      = dr.content;
  const distilled    = dr.distilled || false;
  const rawContent   = distilled ? dr.rawContent : null;
  const distillSaved = distilled ? estimateTokens(rawOutput) - estimateTokens(content) : 0;
  const distillLabel = dr.label || null;
  const outputTokens = estimateTokens(content);
  const secrets      = scanSecrets(content);

  return {
    content,
    exitCode:     raw.exitCode,
    outputTokens,
    bytes,
    distilled,
    distillSaved,
    distillLabel,
    rawContent,
    secrets,
    ...extra,
  };
}

// ── Exports ────────────────────────────────────────────────────────────────────

module.exports = {
  // Shared
  MAX_OUTPUT,
  readFileNative,
  // Read
  READ_SKIP_EXTENSIONS,
  isReadHandleable,
  handleReadTool,
  // Glob
  GLOB_INJECTION_RE,
  GLOB_SKIP,
  GLOB_MAX,
  isGlobHandleable,
  globToRegex,
  walkGlob,
  handleGlobTool,
  // Grep
  GREP_MAX_RESULTS,
  GREP_FILE_CAP,
  GREP_TYPE_EXTS,
  VALID_GREP_MODES,
  isGrepHandleable,
  tryReadGrep,
  walkGrepFiles,
  handleGrepTool,
  // Todo
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
  // MCP execution wrapper
  executeLocalTool,
};
