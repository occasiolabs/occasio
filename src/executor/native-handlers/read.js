'use strict';

/**
 * Native handler for the Read tool.
 *
 * Pure filesystem function: takes a file_path (+ optional offset/limit) and
 * returns cat -n formatted output. No dependency on the interceptor pipeline,
 * Anthropic API, or shell execution. Safe to import in any process context.
 *
 * Extracted from src/runtime.js as Stage-2 of the executor migration
 * (see docs/ADAPTER-STAGE-2-MIGRATION.md). src/runtime.js re-exports
 * these so existing consumers (src/interceptor.js, tests) keep working
 * unchanged.
 */

const fs   = require('fs');
const path = require('path');

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
// UNC / network paths cause blocking SMB resolution on Windows (10+ s).
// Reject so the agent cannot stall the proxy via `\\server\share\file` or
// the // equivalent. Local filesystem only — a deliberate restriction.
const UNC_PREFIX_RE = /^[/\\]{2}/;

function isReadHandleable(input) {
  if (!input || typeof input !== 'object') return false;
  const fp = input.file_path;
  if (!fp || typeof fp !== 'string' || !fp.trim()) return false;
  if (UNC_PREFIX_RE.test(fp)) return false;
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
  const fp  = (typeof input?.file_path === 'string' ? input.file_path : '').trim();
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

module.exports = {
  MAX_OUTPUT,
  READ_SKIP_EXTENSIONS,
  readFileNative,
  isReadHandleable,
  handleReadTool,
};
