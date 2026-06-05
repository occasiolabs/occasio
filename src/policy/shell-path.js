'use strict';

/**
 * Extract file-read operand paths from a shell command so the policy engine
 * can apply deny_paths / allow_paths to shell-mediated reads (cat, head, tail,
 * type, bat, Get-Content) the same way it does for the typed `read_file` tool.
 *
 * Closes the bypass where `Bash { command: "cat <denied-path>" }` and the
 * PowerShell equivalent skipped path policy because the canonical tool name
 * is `shell_bash` / `shell_powershell` and not in PATH_BEARING_TOOLS.
 *
 * Scope is intentionally narrow: only the shapes the native handler in
 * src/interceptor.js actually executes locally. Unrecognised commands return
 * an empty array — the existing classifier still gates them.
 */

const path = require('path');

// Read-content primitives that the native handler reads from disk.
// Each entry: command head (lowercased) → parser(parts) → relative file path or null.
//
// Keep these parsers byte-compatible with interceptor.nativeHandle() so we
// never block a path the native handler would not actually read.
function parseSimpleRead(parts) {
  // cat|bat|type|head|tail [-flags] <file>
  let i = 1;
  while (i < parts.length && parts[i].startsWith('-')) {
    if ((parts[i] === '-n' || parts[i] === '--lines') && /^\d+$/.test(parts[i + 1] || '')) i++;
    i++;
  }
  const file = stripQuotes(parts.slice(i).join(' '));
  return file || null;
}

function parseGetContent(parts) {
  // Get-Content [-Path|-LiteralPath] <file>
  let idx = 1;
  if (/^-(?:path|literalpath)$/i.test(parts[1] || '')) idx = 2;
  const file = stripQuotes(parts.slice(idx).join(' '));
  return file || null;
}

const READ_HEADS = new Map([
  ['cat',         parseSimpleRead],
  ['bat',         parseSimpleRead],
  ['type',        parseSimpleRead],
  ['head',        parseSimpleRead],
  ['tail',        parseSimpleRead],
  ['get-content', parseGetContent],
]);

function stripQuotes(s) {
  if (!s) return s;
  return s.trim().replace(/^(['"])(.*)\1$/, '$2');
}

/** Extract the directory operand from a `cd <dir>` / `Set-Location <dir>` segment. */
function extractCwdFromCdSegment(seg) {
  const m = /^(?:cd|Set-Location)\s+(.+)$/i.exec(seg.trim());
  if (!m) return null;
  return stripQuotes(m[1]);
}

/**
 * Try to extract a relative-or-absolute file path from a single command
 * segment that reads file content. Returns null if the segment is not a
 * recognised read shape.
 */
function readPathFromSegment(seg) {
  const trimmed = seg.trim().replace(/\s+2>&1\s*$/, '');
  if (!trimmed) return null;
  const parts = trimmed.split(/\s+/);
  const head  = parts[0];
  if (!head) return null;
  const parser = READ_HEADS.get(head.toLowerCase());
  if (!parser) return null;
  return parser(parts);
}

/**
 * Walk a shell command and return every file path the native handler would
 * actually read, resolved to absolute form. Handles three shapes:
 *
 *   1. Bare read:                   `cat <file>`
 *   2. cd-prefixed Bash chain:      `cd <dir> && cat <file>`
 *   3. Set-Location PowerShell:     `Set-Location <dir>; Get-Content <file>`
 *
 * The cwd tracked across cd/Set-Location segments only affects path
 * resolution for subsequent segments — process.cwd() is never mutated. The
 * caller (policy.engine) resolves each returned path against deny_paths /
 * allow_paths exactly like it does for a typed `read_file` tool.
 *
 * Returns an array of absolute path strings (deduplicated, order-preserving).
 */
function extractShellReadPaths(command, baseCwd) {
  if (!command || typeof command !== 'string') return [];
  const cwdStart = baseCwd || process.cwd();

  // Split into segments. Bash `&&`, PowerShell `;`. A command with neither
  // separator is a single segment.
  const segments = command.includes(' && ')
    ? command.split(' && ')
    : command.includes(';')
      ? command.split(';').map(s => s.trim()).filter(Boolean)
      : [command];

  const results = [];
  const seen    = new Set();
  let cwd = cwdStart;

  for (const seg of segments) {
    const s = seg.trim();
    if (!s) continue;

    const cdTarget = extractCwdFromCdSegment(s);
    if (cdTarget) {
      // Resolve cd target against the previously tracked cwd so chained
      // relative cd's work (mirrors interceptor.runCompound).
      cwd = path.resolve(cwd, cdTarget);
      continue;
    }

    const filePart = readPathFromSegment(s);
    if (!filePart) continue;

    const abs = path.resolve(cwd, filePart);
    if (!seen.has(abs)) {
      seen.add(abs);
      results.push(abs);
    }
  }
  return results;
}

/**
 * Verb-agnostic backstop: pull every path-like token out of a shell command,
 * resolved to absolute form. Unlike extractShellReadPaths (which only parses a
 * known allowlist of read verbs), this makes no assumption about the command —
 * `less .env`, `awk '{print}' .env`, `cp .env /tmp`, `grep '' .env`, or any
 * future verb all surface their `.env` operand here. The caller applies
 * deny_paths against the result, so a sensitive *file* is protected regardless
 * of which command tries to read it.
 *
 * Intentionally broad: a token that merely looks like a path is included, and
 * the engine only ever uses this to DENY (never to allow), so over-inclusion is
 * safe — it can only add a block, never remove one. Quotes are stripped; flags
 * (-x), operators, and non-path tokens are ignored.
 *
 * Returns absolute path strings (deduplicated, order-preserving).
 */
function extractCommandPathTokens(command, baseCwd) {
  if (!command || typeof command !== 'string') return [];
  const cwd = baseCwd || process.cwd();
  const results = [];
  const seen = new Set();

  // Track cwd across cd / Set-Location so a denied relative path resolves the
  // same way the command would actually see it.
  const segments = command.includes(' && ')
    ? command.split(' && ')
    : command.includes(';')
      ? command.split(';').map(s => s.trim()).filter(Boolean)
      : [command];

  let curCwd = cwd;
  for (const seg of segments) {
    const cdTarget = extractCwdFromCdSegment(seg.trim());
    if (cdTarget) { curCwd = path.resolve(curCwd, cdTarget); continue; }

    for (const rawTok of seg.split(/\s+/)) {
      const tok = stripQuotes(rawTok);
      if (!tok) continue;
      if (tok.startsWith('-')) continue;                 // flag
      if (/^[|&;><()$`]+$/.test(tok)) continue;          // shell operator
      // Path-like heuristic: contains a separator, starts with . or ~, or has a
      // dotted basename (foo.env, .env). Bare words (cat, ssh) are skipped.
      const looksLikePath =
        tok.includes('/') || tok.includes('\\') ||
        tok.startsWith('.') || tok.startsWith('~') ||
        /[^/\\]+\.[^/\\.]+$/.test(tok);
      if (!looksLikePath) continue;

      const expanded = tok.startsWith('~')
        ? require('os').homedir() + tok.slice(1)
        : tok;
      const abs = path.resolve(curCwd, expanded);
      if (!seen.has(abs)) { seen.add(abs); results.push(abs); }
    }
  }
  return results;
}

module.exports = { extractShellReadPaths, extractCommandPathTokens };
