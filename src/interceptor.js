'use strict';

/**
 * interceptor.js — Short-circuits local-safe Bash tool_use calls.
 *
 * Flow:
 *   1. Proxy receives full SSE body from Anthropic (stop_reason: tool_use)
 *   2. interceptToolUse() parses the stream, checks every tool block is safe
 *   3. Executes each command — via native JS handler when possible, else exec
 *   4. Sends one follow-up /v1/messages to Anthropic with tool_results appended
 *   5. Repeats if Anthropic responds with more tool_use (up to maxRounds)
 *   6. Returns the final non-tool response — proxy sends it to Claude Code
 *
 * Native handlers cover:
 *   cat/bat/head/tail/type, Get-Content   — file reads (cross-platform)
 *   ls/eza/exa/lsd, dir, Get-ChildItem   — directory listing
 *   find -name, where/which              — file/command search
 *   test -f/-e/-d, Test-Path             — file existence checks
 *   rg, grep, git (read-only)            — handled by exec via always_local list
 *
 * Each toolsRun entry now includes outputTokens for per-command dashboard display.
 */

const fs   = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { routeLocally } = require('./classifier');
const { distill }      = require('./distiller');
const { scanSecrets }  = require('./analyzer');

const {
  MAX_OUTPUT,
  readFileNative, READ_SKIP_EXTENSIONS,
  isReadHandleable, handleReadTool,
  isGlobHandleable, handleGlobTool, globToRegex,
  isGrepHandleable, handleGrepTool,
  isTodoHandleable, handleTodoWriteTool, handleTodoReadTool,
  executeLocalTool,
} = require('./runtime');

// Canonical pipeline modules (Stage 1 architecture).
// Production tool dispatch for Read/Glob/Grep/TodoWrite/TodoRead now flows
// through pipeline.processToolEvent; Bash/PowerShell remain on the legacy
// nativeHandle path because their exec fallback is not yet a Decision shape.
const { makeBoundaryEvent } = require('./core/boundary-event');
const pipeline  = require('./core/pipeline');
const toolNames = require('./core/tool-names');

// Maps Claude Code tool names → mcp-server names accepted by executeLocalTool
const MCP_TOOL_NAMES = { Read: 'read_file', Glob: 'find_files', Grep: 'grep' };

// ── Legacy export (kept for tests + external callers) ─────────────────────────

const LOCAL_BASH_CMDS = new Set([
  'grep', 'rg',   'find', 'ls',   'cat',   'head', 'tail',
  'wc',   'git',  'echo', 'pwd',  'which', 'stat', 'file', 'diff',
]);

const SHELL_META = /[;&|`$<>\\]/;

// Used by isNativeHandleable only: excludes backslash so that Windows absolute
// paths (C:\Users\…, Get-Content C:\…) are not rejected before the native
// handler can resolve them via path.resolve().  The full SHELL_META (with \)
// is still used in isInterceptable for non-native paths.
const SHELL_COMPOSITION = /[;&|`$<>]/;

// PowerShell-specific composition guard — same as SHELL_COMPOSITION but without
// the dollar-sign, because $env:VAR is expanded by expandPsEnvVars() before
// this check runs.  Any remaining $ after expansion (variable refs, subexpressions)
// is caught by a separate includes('$') test in isPowerShellNativeHandleable.
const PS_COMPOSITION = /[;&|`<>]/;

// Allowed display-only flags for `git log --oneline -N [flags…]`.
// Shared by isNativeHandleable, isBareGitReadOnly, and isGitCSegment.
const SAFE_GIT_LOG_FLAGS = /^(--no-color|--color|--no-decorate|--decorate(?:=\S+)?|--graph|--no-graph|--abbrev-commit|--no-abbrev-commit)$/;

// ── Fallback reason codes ──────────────────────────────────────────────────────
// Stable string constants used in log entries and coverage analysis.
// Kept in one place so analysis queries can join against them reliably.
const FALLBACK_REASONS = {
  TOOL_NOT_HANDLED:      'tool_not_handled',      // Edit, Write, Task, Skill, etc.
  READ_UNSUPPORTED_TYPE: 'read_unsupported_type',  // PDF, image, binary, pages param, bad input
  GLOB_INJECTION:        'glob_injection_or_invalid', // injection chars or missing/invalid pattern
  GREP_MULTILINE:        'grep_multiline',         // multiline: true (rg -U)
  GREP_INVALID_INPUT:    'grep_invalid_input',     // missing/invalid pattern or bad field types
  BASH_EMPTY_CMD:        'bash_empty_cmd',         // empty command string
  BASH_SHELL_META:       'bash_shell_meta',        // pipe, redirect, backtick, semicolon, etc.
  BASH_UNRECOGNIZED:     'bash_unrecognized',      // classifier returned local=false
  PS_SHELL_COMPOSITION:  'ps_shell_composition',   // | ; & ` < > found after env expansion
  PS_DOLLAR_AFTER_EXP:   'ps_dollar_after_expansion', // $ remains after $env: expansion
  PS_NOT_NATIVE:         'ps_not_native',          // expanded cmd not in native handler list
  SECRET_IN_RESULT:      'secret_in_tool_result',  // block_secrets mode + secret found
  API_ERROR:             'api_error',              // non-200 from Anthropic on follow-up
  MAX_ROUNDS:            'max_rounds_exceeded',    // hit maxRounds limit
};

// ── PowerShell env-var expansion ───────────────────────────────────────────────

/**
 * Expand $env:VARNAME references in a PowerShell command string.
 * Only expands the $env: namespace — other $ forms (variables, subexpressions)
 * are left intact so isPowerShellNativeHandleable can reject them.
 */
function expandPsEnvVars(s) {
  return s.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, (_, name) => process.env[name] || '');
}

// ── Native file-system handlers ────────────────────────────────────────────────

function stripQuotes(s) {
  return s.trim().replace(/^(['"])(.*)\1$/, '$2');
}

/**
 * Parse flags and the final positional file/dir argument from command parts.
 * Flags are parts that start with '-'; everything after the last flag is joined
 * as the file path (handles paths with spaces if not quoted).
 */
function parseFlagsAndPath(parts, startIdx = 1) {
  let i = startIdx;
  const flags = [];
  while (i < parts.length && parts[i].startsWith('-')) {
    flags.push(parts[i]);
    // Consume the next token if this flag takes a value (e.g. -n 20)
    if ((parts[i] === '-n' || parts[i] === '--lines') && i + 1 < parts.length && /^\d+$/.test(parts[i + 1])) {
      flags.push(parts[i + 1]);
      i++;
    }
    i++;
  }
  const filePart = stripQuotes(parts.slice(i).join(' '));
  return { flags, filePart };
}

// ── D-2 compound-command helpers ───────────────────────────────────────────────
// Narrow support for &&-chains (Bash) and ;-chains (PowerShell) where every
// segment is either a safe git read-only command or a pure echo/Write-Output.
// Reject-whole-if-any-unknown: a single unrecognized segment blocks the batch.

function isEchoSegment(seg) {
  if (!seg) return false;
  const m = /^(?:echo|Write-Output|Write-Host)\s*(.*)$/i.exec(seg.trim());
  if (!m) return false;
  const arg = (m[1] || '').trim();
  return !SHELL_COMPOSITION.test(arg) && !arg.includes('`');
}

// Bare git (no -C): `git status` or `git log --oneline -N [safe flags]`
function isBareGitReadOnly(seg) {
  const s = seg.trim().replace(/\s+2>&1\s*$/, '').trim();
  const parts = s.split(/\s+/);
  if (parts[0]?.toLowerCase() !== 'git') return false;
  if (parts[1] === 'status' && parts.length === 2) return true;
  if (parts[1] === 'log' && parts[2] === '--oneline' && /^-\d+$/.test(parts[3] || '')) {
    return parts.slice(4).every(f => SAFE_GIT_LOG_FLAGS.test(f));
  }
  return false;
}

// git -C <path> form (already covered by D-1)
function isGitCSegment(seg) {
  const s = seg.trim().replace(/\s+2>&1\s*$/, '').trim();
  if (SHELL_COMPOSITION.test(s)) return false;
  const parts = s.split(/\s+/);
  if (parts[0]?.toLowerCase() !== 'git') return false;
  if (parts[1] !== '-C' || !parts[2]) return false;
  const sub = parts[3];
  if (sub === 'status' && parts.length === 4) return true;
  if (sub === 'log' && parts[4] === '--oneline' && /^-\d+$/.test(parts[5] || '')) {
    return parts.slice(6).every(f => SAFE_GIT_LOG_FLAGS.test(f));
  }
  return false;
}

// cd "<absolute-path>" — Bash cwd prefix (D-3)
// Only absolute paths; no shell meta after unquoting; no relative components.
function isCdSegment(seg) {
  if (!seg) return false;
  const m = /^cd\s+(.+)$/i.exec(seg.trim());
  if (!m) return false;
  const p = m[1].trim().replace(/^(['"])(.*)\1$/, '$2');
  if (!/^(?:[A-Za-z]:\\|\\\\|\/)/.test(p)) return false; // absolute only
  return !SHELL_COMPOSITION.test(p);
}

// Set-Location "<absolute-path>" — PowerShell cwd prefix (D-3)
function isSetLocationSegment(seg) {
  if (!seg) return false;
  const m = /^Set-Location\s+(.+)$/i.exec(seg.trim());
  if (!m) return false;
  const p = m[1].trim().replace(/^(['"])(.*)\1$/, '$2');
  if (!/^(?:[A-Za-z]:\\|\\\\|\/)/.test(p)) return false; // absolute only
  return !PS_COMPOSITION.test(p) && !p.includes('$');
}

function isCompoundSegment(seg) {
  const s = seg.trim();
  return s.length > 0 && (isEchoSegment(s) || isBareGitReadOnly(s) || isGitCSegment(s) || isCdSegment(s) || isSetLocationSegment(s));
}

// Returns true only if every segment of the chain is recognized and safe.
function isCompoundHandleable(cmd, sep) {
  const segments = sep === '&&'
    ? cmd.split(' && ')
    : cmd.split(';').map(s => s.trim()).filter(Boolean);
  return segments.length >= 2 && segments.every(isCompoundSegment);
}

// Execute each segment of an already-validated compound chain in sequence.
// Returns { output: string, exitCode: 0 } — segments are all read-only.
// cwd is tracked locally; process.cwd() is never mutated.
function runCompound(segments) {
  const { execSync } = require('child_process');
  const outputs = [];
  let cwd = process.cwd(); // updated by cd/Set-Location segments
  for (const seg of segments) {
    const s = seg.trim();
    if (!s) continue;

    // cd / Set-Location — update tracked cwd, produce no output
    if (isCdSegment(s) || isSetLocationSegment(s)) {
      const m = /^(?:cd|Set-Location)\s+(.+)$/i.exec(s);
      const rawPath = (m?.[1] || '').trim();
      cwd = rawPath.replace(/^(['"])(.*)\1$/, '$2');
      continue;
    }

    if (isEchoSegment(s)) {
      const m = /^(?:echo|Write-Output|Write-Host)\s*(.*)$/i.exec(s);
      const arg = (m?.[1] || '').trim().replace(/^(['"])(.*)\1$/, '$2');
      outputs.push(arg);
      continue;
    }

    if (isBareGitReadOnly(s)) {
      const gitRaw = s.replace(/\s+2>&1\s*$/, '').trim();
      const parts  = gitRaw.split(/\s+/);
      try {
        if (parts[1] === 'status') {
          const out = execSync('git status', {
            cwd, timeout: 10000,
            stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
          });
          outputs.push(out.trimEnd());
        } else {
          const n = parseInt(parts[3].slice(1), 10);
          const out = execSync(`git log --oneline -${n}`, {
            cwd, timeout: 10000,
            stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
          });
          outputs.push(out.trimEnd());
        }
      } catch (e) {
        outputs.push(((e.stdout || '') + (e.stderr || '')).toString().trimEnd() || e.message);
      }
      continue;
    }

    if (isGitCSegment(s)) {
      const nr = nativeHandle(s);
      outputs.push(nr ? nr.output : '');
      continue;
    }
  }
  return { output: outputs.join('\n'), exitCode: 0 };
}

/**
 * Try to handle a command natively (no subprocess).
 * Returns { output: string, exitCode: number } or null if not handled.
 *
 * Placing the native check BEFORE SHELL_META is intentional: it lets us handle
 *   - 'test -f file'   (would be blocked by dangerous-flag -f in classifier)
 *   - Windows paths    (backslash in 'Get-Content C:\path' would hit SHELL_META)
 */
function nativeHandle(cmd) {
  const raw   = cmd.trim();

  // Compound &&-chains (Bash) and ;-chains (PowerShell) — validated before dispatch.
  if (raw.includes(' && ') && isCompoundHandleable(raw, '&&')) {
    return runCompound(raw.split(' && '));
  }
  if (raw.includes(';') && isCompoundHandleable(raw, ';')) {
    return runCompound(raw.split(';').map(s => s.trim()).filter(Boolean));
  }

  const parts = raw.split(/\s+/);
  const head  = parts[0];
  const headL = head.toLowerCase();
  const cwd   = process.cwd();

  // ── cat / bat / type [-n] <file> ──────────────────────────────────────────
  if (headL === 'cat' || headL === 'bat' || headL === 'type') {
    const { flags, filePart } = parseFlagsAndPath(parts);
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      let content = readFileNative(abs);
      if (flags.includes('-n')) {
        content = content.split('\n')
          .map((l, i) => `${String(i + 1).padStart(6)}\t${l}`)
          .join('\n');
      }
      return { output: content, exitCode: 0 };
    } catch {
      return { output: `${headL}: ${filePart}: No such file or directory`, exitCode: 1 };
    }
  }

  // ── Get-Content [-Path|-LiteralPath] <file> ───────────────────────────────
  if (/^get-content$/i.test(head)) {
    let idx = 1;
    if (/^-(?:path|literalpath)$/i.test(parts[1])) idx = 2;
    const filePart = stripQuotes(parts.slice(idx).join(' '));
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      return { output: readFileNative(abs), exitCode: 0 };
    } catch {
      return { output: `Get-Content: Cannot find path '${filePart}'`, exitCode: 1 };
    }
  }

  // ── head [-n N | -N] <file> ───────────────────────────────────────────────
  if (headL === 'head') {
    let n = 10;
    let fileIdx = 1;
    if (parts[1] === '-n' && /^\d+$/.test(parts[2])) { n = parseInt(parts[2]); fileIdx = 3; }
    else if (/^-(\d+)$/.test(parts[1])) { n = parseInt(parts[1].slice(1)); fileIdx = 2; }
    else if (/^-n(\d+)$/.test(parts[1])) { n = parseInt(parts[1].slice(2)); fileIdx = 2; }
    const filePart = stripQuotes(parts.slice(fileIdx).join(' '));
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      const lines = readFileNative(abs).split('\n').slice(0, n);
      return { output: lines.join('\n'), exitCode: 0 };
    } catch {
      return { output: `head: ${filePart}: No such file or directory`, exitCode: 1 };
    }
  }

  // ── tail [-n N | -N] <file> ───────────────────────────────────────────────
  if (headL === 'tail') {
    let n = 10;
    let fileIdx = 1;
    if (parts[1] === '-n' && /^\d+$/.test(parts[2])) { n = parseInt(parts[2]); fileIdx = 3; }
    else if (/^-(\d+)$/.test(parts[1])) { n = parseInt(parts[1].slice(1)); fileIdx = 2; }
    else if (/^-n(\d+)$/.test(parts[1])) { n = parseInt(parts[1].slice(2)); fileIdx = 2; }
    const filePart = stripQuotes(parts.slice(fileIdx).join(' '));
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      const lines = readFileNative(abs).split('\n');
      return { output: lines.slice(-n).join('\n'), exitCode: 0 };
    } catch {
      return { output: `tail: ${filePart}: No such file or directory`, exitCode: 1 };
    }
  }

  // ── ls / eza / exa / lsd [-flags] [dir] ──────────────────────────────────
  if (['ls', 'eza', 'exa', 'lsd'].includes(headL)) {
    let long = false, showAll = false;
    let idx = 1;
    while (idx < parts.length && parts[idx].startsWith('-')) {
      const f = parts[idx];
      if (f.includes('l')) long = true;
      if (f.includes('a') || f.includes('A')) showAll = true;
      idx++;
    }
    const dir = parts[idx] ? stripQuotes(parts.slice(idx).join(' ')) : '.';
    const abs = path.resolve(cwd, dir);
    try {
      const entries = fs.readdirSync(abs, { withFileTypes: true });
      const filtered = showAll ? entries : entries.filter(e => !e.name.startsWith('.'));
      if (long) {
        const lines = filtered.map(e => {
          try {
            const st = fs.statSync(path.join(abs, e.name));
            const size = String(st.size).padStart(8);
            const mtime = st.mtime.toISOString().slice(0, 16).replace('T', ' ');
            const d = e.isDirectory() ? 'd' : '-';
            return `${d}rw-r--r--  ${size}  ${mtime}  ${e.name}${e.isDirectory() ? '/' : ''}`;
          } catch { return e.name; }
        });
        return { output: lines.join('\n'), exitCode: 0 };
      }
      const names = filtered.map(e => e.name + (e.isDirectory() ? '/' : '')).join('  ');
      return { output: names || '(empty)', exitCode: 0 };
    } catch {
      return { output: `ls: cannot access '${dir}': No such file or directory`, exitCode: 1 };
    }
  }

  // ── dir [dir] ─────────────────────────────────────────────────────────────
  if (headL === 'dir') {
    const dir = parts[1] ? stripQuotes(parts.slice(1).join(' ')) : '.';
    const abs = path.resolve(cwd, dir);
    try {
      const entries = fs.readdirSync(abs, { withFileTypes: true });
      const lines = entries.map(e =>
        ` ${e.isDirectory() ? '<DIR>  ' : '       '} ${e.name}`
      );
      return { output: `Directory of ${abs}\n\n${lines.join('\n')}`, exitCode: 0 };
    } catch {
      return { output: 'File Not Found', exitCode: 1 };
    }
  }

  // ── Get-ChildItem [-Path|-LiteralPath] [dir] ──────────────────────────────
  if (/^get-childitem$/i.test(head)) {
    let idx = 1;
    if (/^-(?:path|literalpath)$/i.test(parts[1])) idx = 2;
    const dir = parts[idx] ? stripQuotes(parts.slice(idx).join(' ')) : '.';
    const abs = path.resolve(cwd, dir);
    try {
      const entries = fs.readdirSync(abs, { withFileTypes: true });
      const lines = entries.map(e => `${e.isDirectory() ? 'd-r--' : '-a---'}  ${e.name}`);
      return { output: lines.join('\n'), exitCode: 0 };
    } catch {
      return { output: `Get-ChildItem: Cannot find path '${dir}'`, exitCode: 1 };
    }
  }

  // ── find <dir> -name <pattern> [-type f|d] ───────────────────────────────
  if (headL === 'find') {
    const nameIdx = parts.indexOf('-name');
    if (nameIdx < 0) return null;  // Only handle -name form natively
    const searchDir = parts[1] ? stripQuotes(parts[1]) : '.';
    const pattern   = stripQuotes(parts[nameIdx + 1] || '*');
    const typeIdx   = parts.indexOf('-type');
    const typeFilter = typeIdx >= 0 ? parts[typeIdx + 1] : null;
    const abs = path.resolve(cwd, searchDir);
    const re  = new RegExp(
      '^' + pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.')
      + '$',
      'i'
    );
    const SKIP = new Set(['node_modules', '.git', '__pycache__', '.venv', 'dist', 'build']);
    const results = [];
    function walk(dir) {
      if (results.length >= 200) return;
      try {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, e.name);
          if (e.isDirectory()) {
            if (!SKIP.has(e.name)) walk(full);
          } else if (!typeFilter || typeFilter === 'f') {
            if (re.test(e.name)) {
              const rel = path.relative(cwd, full).replace(/\\/g, '/');
              results.push(rel.startsWith('.') ? rel : './' + rel);
            }
          }
        }
      } catch { /* skip unreadable dir */ }
    }
    walk(abs);
    return { output: results.join('\n') || '', exitCode: 0 };
  }

  // ── test -f|-e|-d <file> ─────────────────────────────────────────────────
  // NOTE: isNativeHandleable() catches 'test' BEFORE SHELL_META so that
  // '-f' is not blocked by the dangerous-flag check in the classifier.
  if (headL === 'test') {
    const flag = parts[1];
    if (!['-f', '-e', '-d'].includes(flag)) return null;
    const filePart = stripQuotes(parts.slice(2).join(' '));
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      const st = fs.statSync(abs);
      const ok = flag === '-d' ? st.isDirectory() : flag === '-f' ? st.isFile() : true;
      return { output: '', exitCode: ok ? 0 : 1 };
    } catch {
      return { output: '', exitCode: 1 };
    }
  }

  // ── Test-Path [-Path|-LiteralPath] <file> ─────────────────────────────────
  if (/^test-path$/i.test(head)) {
    let idx = 1;
    if (/^-(?:path|literalpath)$/i.test(parts[1])) idx = 2;
    const filePart = stripQuotes(parts.slice(idx).join(' '));
    if (!filePart) return null;
    const abs = path.resolve(cwd, filePart);
    let exists = false;
    try { fs.statSync(abs); exists = true; } catch { /* missing → exists stays false */ }
    return { output: exists ? 'True' : 'False', exitCode: exists ? 0 : 1 };
  }

  // ── Select-String [-Pattern] <pattern> [-Path] <file> ────────────────────
  // Only handles single-file paths.  Glob paths (* / ?) must fall back to
  // the cloud because we cannot expand them without walking the filesystem
  // in a way that stays consistent with how the Grep tool already handles this.
  if (/^select-string$/i.test(head)) {
    let pattern = null, filePart = null;
    for (let i = 1; i < parts.length; i++) {
      if (/^-pattern$/i.test(parts[i]) && i + 1 < parts.length) {
        pattern = stripQuotes(parts[++i]);
      } else if (/^-(?:path|literalpath)$/i.test(parts[i]) && i + 1 < parts.length) {
        filePart = stripQuotes(parts[++i]);
      } else if (!parts[i].startsWith('-')) {
        if (pattern === null) pattern = stripQuotes(parts[i]);
        else if (filePart === null) filePart = stripQuotes(parts[i]);
      }
    }
    if (!pattern || !filePart || filePart.includes('*') || filePart.includes('?')) return null;
    const abs = path.resolve(cwd, filePart);
    try {
      const content = readFileNative(abs);
      let re;
      try { re = new RegExp(pattern, 'i'); } catch { return null; }
      const matches = content.split('\n')
        .map((line, idx) => re.test(line) ? `${abs}:${idx + 1}:${line}` : null)
        .filter(Boolean);
      return { output: matches.join('\n'), exitCode: matches.length > 0 ? 0 : 1 };
    } catch {
      return { output: `Select-String: Cannot find path '${filePart}'`, exitCode: 1 };
    }
  }

  // ── git read-only forms ────────────────────────────────────────────────────
  // Handles bare forms (D-4, process.cwd()) and -C forms (D-1, explicit path).
  // Strips trailing 2>&1 before matching — isNativeHandleable does the same.
  // Extra display-only flags on log are accepted by isNativeHandleable but
  // ignored in execution — we always run the canonical form.
  if (headL === 'git') {
    const gitRaw   = raw.replace(/\s+2>&1\s*$/, '');
    const gitParts = gitRaw.trim().split(/\s+/);

    // Bare forms in current cwd (D-4)
    if (gitParts[1] === 'status' && gitParts.length === 2) {
      try {
        const { execSync } = require('child_process');
        const out = execSync('git status', {
          cwd: process.cwd(), timeout: 10000,
          stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
        });
        return { output: out.trimEnd(), exitCode: 0 };
      } catch (e) {
        const msg = ((e.stdout || '') + (e.stderr || '')).toString().trimEnd() || e.message;
        return { output: msg, exitCode: e.status ?? 1 };
      }
    }
    if (gitParts[1] === 'log' && gitParts[2] === '--oneline' && /^-\d+$/.test(gitParts[3] || '')) {
      const n = parseInt(gitParts[3].slice(1));
      try {
        const { execSync } = require('child_process');
        const out = execSync(`git log --oneline -${n}`, {
          cwd: process.cwd(), timeout: 10000,
          stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
        });
        return { output: out.trimEnd(), exitCode: 0 };
      } catch (e) {
        const msg = ((e.stdout || '') + (e.stderr || '')).toString().trimEnd() || e.message;
        return { output: msg, exitCode: e.status ?? 1 };
      }
    }

    if (gitParts[1] !== '-C' || !gitParts[2]) return null;
    const gitCwd = stripQuotes(gitParts[2]);
    const sub    = gitParts[3];

    if (sub === 'status' && gitParts.length === 4) {
      try {
        const { execSync } = require('child_process');
        const out = execSync('git status', {
          cwd: gitCwd, timeout: 10000,
          stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
        });
        return { output: out.trimEnd(), exitCode: 0 };
      } catch (e) {
        const msg = ((e.stdout || '') + (e.stderr || '')).toString().trimEnd() || e.message;
        return { output: msg, exitCode: e.status ?? 1 };
      }
    }

    if (sub === 'log' && gitParts[4] === '--oneline' && /^-\d+$/.test(gitParts[5] || '')) {
      const n = parseInt(gitParts[5].slice(1));
      try {
        const { execSync } = require('child_process');
        const out = execSync(`git log --oneline -${n}`, {
          cwd: gitCwd, timeout: 10000,
          stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
        });
        return { output: out.trimEnd(), exitCode: 0 };
      } catch (e) {
        const msg = ((e.stdout || '') + (e.stderr || '')).toString().trimEnd() || e.message;
        return { output: msg, exitCode: e.status ?? 1 };
      }
    }

    return null;
  }

  return null;
}

/**
 * Returns true when nativeHandle() will accept this command.
 * Used by isInterceptable() to short-circuit the SHELL_META + classifier checks.
 * SHELL_COMPOSITION (not SHELL_META) is checked here so that Windows absolute
 * paths containing backslashes (Get-Content C:\Users\…) are not rejected.
 * Backslash is excluded because it is a legitimate Windows path separator.
 * The full SHELL_META check (which includes backslash) lives in isInterceptable
 * and applies only to commands that the native layer cannot handle.
 */
function isNativeHandleable(cmd) {
  if (!cmd) return false;
  // &&-chains: validate every segment before SHELL_COMPOSITION blocks the &.
  if (cmd.includes(' && ')) return isCompoundHandleable(cmd.trim(), '&&');
  // For git commands: strip trailing 2>&1 before the composition check.
  // Safe because the git routing below only allows explicit read-only subcommands.
  // Non-git commands are unaffected.
  let normalized = cmd.trim();
  if (/^git\s/i.test(normalized)) normalized = normalized.replace(/\s+2>&1\s*$/, '');
  if (SHELL_COMPOSITION.test(normalized)) return false;
  const parts = normalized.split(/\s+/);
  const head  = parts[0];
  const headL = head.toLowerCase();

  if (['cat', 'bat', 'head', 'tail'].includes(headL) && parts.length >= 2) return true;
  if (/^get-content$/i.test(head)) return true;
  if (headL === 'type' && parts.length >= 2 && !parts[1].startsWith('-')) return true;
  if (['ls', 'eza', 'exa', 'lsd', 'dir'].includes(headL)) return true;
  if (/^get-childitem$/i.test(head)) return true;
  if (headL === 'find' && parts.includes('-name')) return true;
  if (headL === 'test' && ['-f', '-e', '-d'].includes(parts[1])) return true;
  if (/^test-path$/i.test(head)) return true;
  if (/^select-string$/i.test(head)) {
    // Glob paths (containing * or ?) cannot be served by the single-file handler.
    return !cmd.includes('*') && !cmd.includes('?');
  }

  // Bare git in current cwd (D-4): reuses isBareGitReadOnly — same two forms only.
  if (headL === 'git' && isBareGitReadOnly(normalized)) return true;

  // git -C <path> status | git -C <path> log --oneline -N [safe display flags]
  if (headL === 'git' && parts[1] === '-C' && parts[2]) {
    const sub = parts[3];
    if (sub === 'status' && parts.length === 4) return true;
    if (sub === 'log' && parts[4] === '--oneline' && /^-\d+$/.test(parts[5] || '')) {
      return parts.slice(6).every(f => SAFE_GIT_LOG_FLAGS.test(f));
    }
  }

  return false;
}

/**
 * Returns true when a PowerShell tool block command can be executed natively.
 * Unlike isNativeHandleable(), this function:
 *   1. Expands $env:VAR references before checking (safe — read-only expansion)
 *   2. Uses PS_COMPOSITION (no $ guard) instead of SHELL_COMPOSITION
 *   3. Rejects any remaining $ after expansion (PS variables, subexpressions)
 *
 * This is the entry point for isInterceptable() when block.name === 'PowerShell'.
 */
function isPowerShellNativeHandleable(cmd) {
  if (!cmd) return false;
  const expanded = expandPsEnvVars(cmd);
  // For git commands: strip trailing 2>&1 before composition check (same logic as isNativeHandleable).
  let normalized = expanded.trim();
  if (/^git\s/i.test(normalized)) normalized = normalized.replace(/\s+2>&1\s*$/, '');
  // ;-chains: validate every segment before PS_COMPOSITION blocks the semicolon.
  if (normalized.includes(';')) return isCompoundHandleable(normalized, ';');
  if (PS_COMPOSITION.test(normalized)) return false;
  if (normalized.includes('$')) return false;
  return isNativeHandleable(normalized);
}

// ── Routing ────────────────────────────────────────────────────────────────────

/**
 * Returns true if this tool block can safely be executed locally.
 * Read tool: handled natively when file type is supported (text, no PDF/images).
 * Glob tool: handled natively when pattern is valid and injection-free.
 * Grep tool: handled natively for all modes except multiline (rg -U).
 * TodoWrite/TodoRead: always handled natively (pure structured session state).
 * Bash tool: native handlers checked first, then safe-command classifier.
 */
function isInterceptable(block) {
  if (block.name === 'Read')      return isReadHandleable(block.input);
  if (block.name === 'Glob')      return isGlobHandleable(block.input);
  if (block.name === 'Grep')      return isGrepHandleable(block.input);
  if (block.name === 'TodoWrite') return isTodoHandleable(block.input, 'TodoWrite');
  if (block.name === 'TodoRead')  return isTodoHandleable(block.input, 'TodoRead');
  if (block.name === 'PowerShell') {
    const cmd = (typeof block.input?.command === 'string' ? block.input.command : '').trim();
    return cmd ? isPowerShellNativeHandleable(cmd) : false;
  }
  if (block.name !== 'Bash') return false;
  const cmd = (typeof block.input?.command === 'string' ? block.input.command : '').trim();
  if (!cmd) return false;
  if (isNativeHandleable(cmd)) return true;
  if (SHELL_META.test(cmd)) return false;
  return routeLocally(block.name, cmd).local;
}

/**
 * Returns { handled: boolean, reason: string } for a single tool block.
 * Mirrors isInterceptable() exactly but provides a stable reason code when
 * handled=false.  Used by interceptToolUse() to collect fallback_reasons for
 * the coverage log and by tests to verify routing decisions.
 *
 * reason is one of the FALLBACK_REASONS constants (or 'ok' when handled=true).
 */
function classifyBlock(block) {
  if (block.name === 'Read') {
    return isReadHandleable(block.input)
      ? { handled: true,  reason: 'ok' }
      : { handled: false, reason: FALLBACK_REASONS.READ_UNSUPPORTED_TYPE };
  }

  if (block.name === 'Glob') {
    return isGlobHandleable(block.input)
      ? { handled: true,  reason: 'ok' }
      : { handled: false, reason: FALLBACK_REASONS.GLOB_INJECTION };
  }

  if (block.name === 'Grep') {
    if (!isGrepHandleable(block.input)) {
      return {
        handled: false,
        reason: block.input?.multiline === true
          ? FALLBACK_REASONS.GREP_MULTILINE
          : FALLBACK_REASONS.GREP_INVALID_INPUT,
      };
    }
    return { handled: true, reason: 'ok' };
  }

  if (block.name === 'TodoWrite' || block.name === 'TodoRead') {
    return { handled: true, reason: 'ok' };
  }

  if (block.name === 'PowerShell') {
    const rawCmd = (typeof block.input?.command === 'string' ? block.input.command : '').trim();
    if (!rawCmd) return { handled: false, reason: FALLBACK_REASONS.BASH_EMPTY_CMD };
    const expanded = expandPsEnvVars(rawCmd);
    let normalized = expanded.trim();
    if (/^git\s/i.test(normalized)) normalized = normalized.replace(/\s+2>&1\s*$/, '');
    // ;-chains: validate every segment before PS_COMPOSITION blocks the semicolon.
    if (normalized.includes(';')) {
      return isCompoundHandleable(normalized, ';')
        ? { handled: true,  reason: 'ok' }
        : { handled: false, reason: FALLBACK_REASONS.PS_SHELL_COMPOSITION };
    }
    if (PS_COMPOSITION.test(normalized)) return { handled: false, reason: FALLBACK_REASONS.PS_SHELL_COMPOSITION };
    if (normalized.includes('$'))        return { handled: false, reason: FALLBACK_REASONS.PS_DOLLAR_AFTER_EXP };
    if (!isNativeHandleable(normalized)) return { handled: false, reason: FALLBACK_REASONS.PS_NOT_NATIVE };
    return { handled: true, reason: 'ok' };
  }

  if (block.name !== 'Bash') {
    return { handled: false, reason: FALLBACK_REASONS.TOOL_NOT_HANDLED };
  }

  // Bash
  const cmd = (typeof block.input?.command === 'string' ? block.input.command : '').trim();
  if (!cmd) return { handled: false, reason: FALLBACK_REASONS.BASH_EMPTY_CMD };
  if (isNativeHandleable(cmd)) return { handled: true, reason: 'ok' };
  if (SHELL_META.test(cmd)) return { handled: false, reason: FALLBACK_REASONS.BASH_SHELL_META };
  return routeLocally(block.name, cmd).local
    ? { handled: true,  reason: 'ok' }
    : { handled: false, reason: FALLBACK_REASONS.BASH_UNRECOGNIZED };
}

// ── SSE parser ─────────────────────────────────────────────────────────────────

function parseSSE(buffer) {
  const blocks = {};
  let stopReason = null;
  let message    = null;

  for (const line of buffer.toString('utf8').split('\n')) {
    if (!line.startsWith('data: ')) continue;
    let d;
    try { d = JSON.parse(line.slice(6)); } catch { continue; }

    switch (d.type) {
      case 'message_start':
        message = d.message;
        break;

      case 'content_block_start':
        blocks[d.index] = {
          type:        d.content_block.type,
          id:          d.content_block.id   || null,
          name:        d.content_block.name || null,
          text:        '',
          partialJson: '',
          input:       null,
        };
        break;

      case 'content_block_delta': {
        const blk = blocks[d.index];
        if (!blk) break;
        if (d.delta.type === 'input_json_delta') blk.partialJson += d.delta.partial_json || '';
        if (d.delta.type === 'text_delta')       blk.text        += d.delta.text        || '';
        break;
      }

      case 'content_block_stop': {
        const blk = blocks[d.index];
        if (blk?.type === 'tool_use' && blk.partialJson) {
          try { blk.input = JSON.parse(blk.partialJson); } catch { blk.input = {}; }
          delete blk.partialJson;
        }
        break;
      }

      case 'message_delta':
        if (d.delta?.stop_reason) stopReason = d.delta.stop_reason;
        break;
    }
  }

  return { blocks, stopReason, message };
}

function blocksToContent(blocks) {
  return Object.entries(blocks)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([, blk]) => {
      if (blk.type === 'text')     return { type: 'text',     text: blk.text };
      if (blk.type === 'tool_use') return { type: 'tool_use', id: blk.id, name: blk.name, input: blk.input || {} };
      return null;
    })
    .filter(Boolean);
}

// ── Local execution ────────────────────────────────────────────────────────────

function runLocally(cmd) {
  return new Promise(resolve => {
    exec(cmd, { timeout: 10_000, maxBuffer: MAX_OUTPUT, cwd: process.cwd() },
      (err, stdout, stderr) => resolve({
        stdout:   stdout || '',
        stderr:   stderr || '',
        exitCode: err?.code ?? 0,
      })
    );
  });
}

// ── Tool-result secret scanning ───────────────────────────────────────────────

/**
 * Scan all tool_result content strings for secrets.
 * Joins them with newlines before scanning so line numbers are meaningful.
 * Returns the same [{label, line, snippet}] shape as scanSecrets().
 *
 * Exported for unit testing (section 20 in test-interceptor.js).
 */
function scanToolResults(toolResults) {
  const text = toolResults
    .map(r => (typeof r.content === 'string' ? r.content : ''))
    .join('\n');
  return scanSecrets(text);
}

// ── Anthropic follow-up request ────────────────────────────────────────────────

/**
 * Build the headers for the interceptor's follow-up /v1/messages call.
 *
 * The proxy's first request forwards all incoming headers verbatim, so auth
 * always reaches Anthropic.  The follow-up is constructed manually — this
 * function ensures we forward whichever auth form Claude Code used:
 *   - x-api-key          (legacy Anthropic SDK / older Claude Code)
 *   - authorization      (Bearer token — used by newer Anthropic SDK)
 * Not setting x-api-key to '' when it is absent is the critical fix:
 * `undefined || ''` produced an empty string that caused HTTP 401.
 *
 * Exported for unit testing (see section 18 in test-interceptor.js).
 */
function buildFollowUpHeaders(authHeaders, payloadLength) {
  const h = {
    'anthropic-version': authHeaders['anthropic-version'] || '2023-06-01',
    'content-type':      'application/json',
  };
  if (payloadLength !== undefined) h['content-length'] = String(payloadLength);
  if (authHeaders['x-api-key'])      h['x-api-key']      = authHeaders['x-api-key'];
  if (authHeaders['authorization'])  h['authorization']   = authHeaders['authorization'];
  if (authHeaders['anthropic-beta']) h['anthropic-beta']  = authHeaders['anthropic-beta'];
  return h;
}

// ── Main export ────────────────────────────────────────────────────────────────

/**
 * Attempts to intercept all tool_use blocks in an Anthropic SSE response by
 * running them locally (native JS or exec) and continuing the conversation.
 *
 * Each entry in toolsRun includes:
 *   tool, cmd, exitCode, bytes, outputTokens, native
 *
 * outputTokens is the estimated token count of the command output — used by
 * the dashboard to display per-command savings (e.g. "⚡ cat auth.py (1.2k tokens saved)").
 *
 * @param {Buffer} sseBody
 * @param {object} reqBody
 * @param {object} reqHeaders
 * @param {object} [opts]
 * @param {number}  [opts.maxRounds=5]
 * @param {boolean} [opts.verbose=false]
 * @param {string}  [opts.mode='intercept']  Occasio mode — used to decide
 *   whether to abort when secrets are found in tool results.  Pass the same
 *   mode string that index.js uses ('intercept' | 'block_secrets' | 'log').
 *
 * @returns {Promise<{
 *   intercepted        : boolean,
 *   response?          : object,
 *   toolsRun?          : Array<{tool,cmd,exitCode,bytes,outputTokens,native}>,
 *   savedInputTokens?  : number,
 *   secretsInResults?  : Array<{label,line,snippet}>,
 * }>}
 */

/**
 * Dispatch every tool_use block in `toolBlocks` for one conversation round.
 *
 * Pure round-body extraction from interceptToolUse — no multi-round
 * orchestration, no follow-up calls, no SSE handling. The caller is
 * responsible for partial-batch coordination, follow-up assembly, and
 * cross-round state aggregation.
 *
 * For hardened mode (`mode === 'hardened'` and the tool is Read/Glob/Grep),
 * dispatch goes through the legacy `executeLocalTool` path (unchanged).
 * For all other supported tools, dispatch flows through the canonical
 * pipeline: BoundaryEvent → policy → executor.dispatch → audit.
 *
 * @returns {Promise<{
 *   toolResults: Array<{type, tool_use_id, content}>,
 *   toolsRun:    Array<object>,
 *   secrets:     Array<{label, line, snippet}>,   // hardened-mode-collected only
 * }>}
 */
async function runOneRound(toolBlocks, ctx) {
  const { mode, todoStore, sessionId, runId, auditor, verbose } = ctx;
  // Stage 3: agent identity is supplied by the calling adapter. Default
  // to claude-code so existing callers (and tests) keep working.
  const agent = ctx.agent || 'claude-code';
  const toolResults = [];
  const toolsRun    = [];
  const secrets     = [];

  for (const blk of toolBlocks) {

    // ── hardened: route Read/Glob/Grep through executeLocalTool ─────────────
    // executeLocalTool applies distillation with correct synthetic cmd strings
    // and secret scanning, matching the MCP server's execution quality.
    if (mode === 'hardened' && MCP_TOOL_NAMES[blk.name]) {
      const mcpName = MCP_TOOL_NAMES[blk.name];
      const r = executeLocalTool(mcpName, blk.input, todoStore);
      const cmdLabel = blk.name === 'Read'
        ? (blk.input?.file_path || '(unknown path)')
        : (blk.input?.pattern   || '(no pattern)');
      toolResults.push({ type: 'tool_result', tool_use_id: blk.id, content: r.content });
      toolsRun.push({
        tool: blk.name, tool_use_id: blk.id, cmd: cmdLabel, exitCode: r.exitCode,
        bytes:             r.bytes,
        kept_bytes:        Buffer.byteLength(r.content || ''),
        prevention_reason: r.distilled ? 'distill_clip' : null,
        outputTokens: r.outputTokens,
        native: true, mcpPath: true,
        distilled:    r.distilled,
        distillSaved: r.distillSaved,
        distillLabel: r.distillLabel,
        rawContent:   r.rawContent,
        matchCount:   r.matchCount,
        // Full raw output for Eyes content-store capture (Phase 1 of full
        // traffic visibility). Audit/ledger paths ignore this field.
        output:       r.content || null,
      });
      if (r.secrets?.length) secrets.push(...r.secrets);
      if (verbose) {
        process.stderr.write(`  [interceptor/hardened] ${blk.name}(${cmdLabel.slice(0, 60)}) → exit ${r.exitCode}\n`);
      }
      continue;
    }

    // ── Canonical pipeline path for any tool the calling agent registered ──
    // Stage 3: gate is registry-driven. The agent's name map determines
    // which tools dispatch through the pipeline; anything unregistered hits
    // the unsupported-tool fallback below.
    const canonicalName = toolNames.toCanonical(agent, blk.name);
    if (canonicalName) {
      const event = makeBoundaryEvent({
        direction: 'inbound',
        kind:      'tool_call',
        agent,
        protocol:  'anthropic-http',
        sessionId,
        runId,
        toolName:  canonicalName,
        toolInput: blk.input,
        raw:       blk,
      });
      const out = await pipeline.processToolEvent(event, {
        ctx:     { todoStore },
        auditor: auditor || undefined,
      });
      const r = out.result || {};

      if (r.passThrough) {
        toolResults.push({ type: 'tool_result', tool_use_id: blk.id,
                           content: `(not handled: ${r.reason || 'unknown'})` });
        continue;
      }

      // BLOCK from the canonical pipeline (e.g. the identity gate's deny_commands
      // / identity_approval rules). The turn stays inside Occasio's loop — the
      // command never executes and the agent never sees its output. Surface the
      // decision's syntheticResponse.message verbatim so the deny / approval
      // text reaches the agent; the whole gate UX depends on this. Carry the
      // approval metadata into toolsRun so the audit/dashboard can credit and
      // explain the blocked call.
      if (r.blocked) {
        const synth   = r.response || {};
        const message = (typeof synth.message === 'string' && synth.message)
          ? synth.message
          : `blocked by policy${r.reason ? `: ${r.reason}` : ''}`;
        const cmdLabel = (canonicalName === 'shell_bash' || canonicalName === 'shell_powershell')
          ? ((blk.input?.command || '').trim() || '(no command)')
          : (blk.input?.file_path || blk.input?.pattern || canonicalName);
        toolResults.push({ type: 'tool_result', tool_use_id: blk.id, content: message });
        toolsRun.push({
          tool:              blk.name,
          tool_use_id:       blk.id,
          cmd:               cmdLabel,
          exitCode:          1,
          bytes:             0,
          kept_bytes:        Buffer.byteLength(message || ''),
          prevention_reason: r.reason || 'policy_block',
          outputTokens:      0,
          native:            true,
          blocked:           true,
          blockReason:       r.reason || 'policy_block',
          ...(r.approval_required && { approvalRequired: true }),
          ...(r.identity_requested && { identityRequested: r.identity_requested }),
          ...(r.target_class && { targetClass: r.target_class }),
        });
        if (verbose) {
          process.stderr.write(`  [interceptor/pipeline] BLOCK ${blk.name}(${cmdLabel.slice(0, 60)}) → ${r.reason || 'policy_block'}\n`);
        }
        continue;
      }

      const rawOutput  = r.output || '';
      const exitCode   = r.exitCode;
      const matchCount = r.matchCount;
      const taskCount  = r.taskCount;
      const native     = r.native ?? true;

      // Stage 3: gate on canonical name. blk.input is expected to be in the
      // canonical input shape — the calling adapter's parseConversationTurn
      // is responsible for input translation. This keeps label extraction
      // and toolsRun construction agent-agnostic.
      const isTodo  = (canonicalName === 'todo_write' || canonicalName === 'todo_read');
      const isShell = (canonicalName === 'shell_bash' || canonicalName === 'shell_powershell');

      const label =
        canonicalName === 'read_file'        ? ((blk.input?.file_path || '').trim() || 'read') :
        canonicalName === 'find_files'       ? ((blk.input?.pattern   || '').trim() || 'glob') :
        canonicalName === 'grep'             ? ((blk.input?.pattern   || '').trim() || 'grep') :
        canonicalName === 'shell_powershell' ? (r.expandedCmd || (blk.input?.command || '').trim()) :
        canonicalName === 'shell_bash'       ? ((blk.input?.command   || '').trim() || 'bash') :
        (taskCount !== undefined ? `${taskCount} tasks` : canonicalName);

      // When the dispatcher ran a TRANSFORM action it already shaped the output
      // (redacted secrets, distilled long results). Use the dispatcher's result
      // metadata directly and skip the unconditional distill() call — the
      // transform is the authoritative shaping step for this tool call.
      // For LOCAL or non-transformed results the existing distill() path runs
      // unchanged, preserving full backward compatibility.
      const distResult = r.transformed
        ? { content:     rawOutput,
            distilled:   r.distilled   || false,
            savedTokens: r.savedTokens || 0,
            label:       r.label       || null,
            rawContent:  r.rawContent  || null }
        : isTodo
          ? { content: rawOutput, distilled: false, savedTokens: 0, label: null, rawContent: null }
          : distill(label, rawOutput);

      // Per-tool context budget (policy.tools[name].max_output_tokens): the
      // FINAL clip before re-entry. Applied after any TRANSFORM/distill so
      // the budget can further trim already-shaped output. Cap is a positive
      // integer or absent; loader.normalizeToolEntry enforces the shape.
      const policyForBudget = require('./policy/loader').load();
      const toolEntry       = (policyForBudget?.tools || {})[canonicalName] || null;
      const maxOutputTokens = toolEntry && typeof toolEntry.max_output_tokens === 'number'
        ? toolEntry.max_output_tokens
        : null;
      const beforeBudget = distResult.content;
      let budgetResult = null;
      if (maxOutputTokens !== null) {
        const { enforceContextBudget } = require('./context-budget');
        budgetResult = enforceContextBudget(beforeBudget, maxOutputTokens);
      }
      const finalContent = budgetResult ? budgetResult.content : beforeBudget;
      const output       = finalContent;
      const outputTokens = Math.ceil(Buffer.byteLength(output || '', 'utf8') / 4);

      toolResults.push({ type: 'tool_result', tool_use_id: blk.id, content: output });
      // Per-call boundary accounting: how many bytes the tool produced (raw)
      // vs how many actually re-entered the model's next request (kept), plus
      // a one-token reason code identifying what shaping prevented re-entry.
      // Drives `occasio boundary` and the public "control what re-enters
      // the model" claim.
      const rawBytes  = Buffer.byteLength(rawOutput || '');
      const keptBytes = Buffer.byteLength(output    || '');
      // Reason precedence: the *final* shaping step wins. Budget runs last,
      // so a budget clip overrides an earlier distill/redact reason in the
      // recorded prevention_reason. Bytes accounting is still correct either
      // way (kept = post-budget length).
      const preventionReason =
        (budgetResult && budgetResult.clipped)        ? 'context_budget' :
        (r.transformed && r.secretsRedacted?.length)  ? 'redact_secrets' :
        distResult.distilled                          ? 'distill_clip'   :
        null;
      toolsRun.push({
        // Keep blk.name (agent-protocol name) in toolsRun.tool for dashboard
        // continuity; canonical name is in audit log via event.toolName.
        tool:         blk.name,
        tool_use_id:  blk.id,
        cmd:          isTodo ? `${taskCount} tasks` :
                      canonicalName === 'read_file' ? (label || '(unknown path)') :
                      isShell                        ? (label || '(no command)') :
                                                       (label || '(no pattern)'),
        exitCode,
        bytes:             rawBytes,
        kept_bytes:        keptBytes,
        prevention_reason: preventionReason,
        outputTokens, native,
        distilled:    distResult.distilled,
        distillSaved: distResult.savedTokens,
        distillLabel: distResult.label,
        rawContent:   distResult.rawContent || null,
        // Full raw output of the local tool (file content, grep matches, etc.)
        // Used by Eyes capture to put the actual bytes into the content store
        // so the browser UI can show "what the agent saw". Capture-side caps
        // at 2 MB. Audit/ledger paths don't consume this field — purely Eyes.
        output:       rawOutput || null,
        ...(r.transformed && { transformed: true, transform: r.transform }),
        ...(r.secretsRedacted?.length && { secretsRedacted: r.secretsRedacted.length }),
        ...(matchCount !== undefined && { matchCount }),
        ...(taskCount  !== undefined && { taskCount  }),
      });
      if (verbose) {
        const tag = blk.name;
        const note = matchCount !== undefined ? `${matchCount} matches`
                   : taskCount  !== undefined ? `${taskCount} tasks`
                   : `exit ${exitCode}`;
        const labelShort = (label || '').slice(0, 60);
        const pathTag    = native ? 'native' : 'exec';
        process.stderr.write(`  [interceptor/pipeline] ${pathTag} ${tag}(${labelShort}) → ${note}\n`);
      }
      continue;
    }

    // Unknown tool — should not be reachable since isInterceptable gates the
    // batch upstream. Defensive emit so the pipeline cannot drop a block.
    toolResults.push({ type: 'tool_result', tool_use_id: blk.id,
                       content: `(unsupported tool: ${blk.name})` });
  }

  return { toolResults, toolsRun, secrets };
}

// Phase E: interceptToolUse and _legacyInterceptToolUse are removed.
// The canonical entry point for an Anthropic conversation containing tool_use
// turns is `adapters/claude-code.js::runToolLoop`. Callers (index.js, tests)
// import the adapter directly.

module.exports = {
  runOneRound,
  blocksToContent,
  parseSSE,
  isInterceptable,
  classifyBlock,
  FALLBACK_REASONS,
  isNativeHandleable,
  isPowerShellNativeHandleable,
  isEchoSegment,
  isBareGitReadOnly,
  isGitCSegment,
  isCdSegment,
  isSetLocationSegment,
  isCompoundSegment,
  isCompoundHandleable,
  expandPsEnvVars,
  isReadHandleable,
  isGlobHandleable,
  isGrepHandleable,
  isTodoHandleable,
  nativeHandle,
  readFileNative,
  READ_SKIP_EXTENSIONS,
  handleReadTool,
  handleGlobTool,
  globToRegex,
  handleGrepTool,
  handleTodoWriteTool,
  handleTodoReadTool,
  scanToolResults,
  runLocally,
  buildFollowUpHeaders,
  LOCAL_BASH_CMDS,
};
