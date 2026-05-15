'use strict';

/**
 * repair.js — `occasio audit repair`
 *
 * Truncates the trailing partial line of an audit log so a crash mid-append
 * does not leave the file in a state where loadPrevHash() fails hard.
 *
 * Contract:
 *   - Examines only the last line. Earlier corruption is out of scope and
 *     should be investigated via `occasio audit verify`.
 *   - "Partial" means: the file does not end in '\n' AND the last
 *     non-empty line cannot be JSON.parsed. Any other shape is a no-op.
 *   - Writes a .bak alongside the original before mutating, even on dry-run
 *     the .bak is NOT created.
 *   - Returns { truncated, wouldTruncate, backupPath, removedBytes, detail }.
 */

const fs   = require('fs');
const path = require('path');

function inspect(filePath) {
  const buf = fs.readFileSync(filePath);
  if (buf.length === 0) return { partial: false, reason: 'empty file' };
  const endsWithNewline = buf[buf.length - 1] === 0x0A;
  const text = buf.toString('utf8');
  const raw  = text.split('\n');
  const lastFragment = raw[raw.length - 1];

  if (endsWithNewline && lastFragment === '') {
    return { partial: false, reason: 'file ends in newline; last line is complete' };
  }

  // Non-empty trailing fragment. Test whether it parses as JSON — a complete
  // single-line record without a trailing newline is valid (rare but legal).
  try {
    JSON.parse(lastFragment);
    return { partial: false, reason: 'trailing line parses as JSON; not partial' };
  } catch {
    // Truncate to the last preceding newline.
    const lastNewline = buf.lastIndexOf(0x0A);
    if (lastNewline === -1) {
      // Entire file is a single partial line.
      return { partial: true, truncateTo: 0, removedBytes: buf.length };
    }
    return {
      partial: true,
      truncateTo: lastNewline + 1,
      removedBytes: buf.length - (lastNewline + 1),
    };
  }
}

function repairAuditFile(filePath, opts = {}) {
  const { dryRun = false } = opts;
  if (!fs.existsSync(filePath)) {
    return { truncated: false, wouldTruncate: false, detail: `file not found: ${filePath}` };
  }

  const info = inspect(filePath);
  if (!info.partial) {
    return {
      truncated: false, wouldTruncate: false,
      detail: info.reason,
      removedBytes: 0,
    };
  }

  if (dryRun) {
    return {
      truncated: false, wouldTruncate: true,
      removedBytes: info.removedBytes,
      detail: `would truncate ${info.removedBytes} bytes from tail`,
    };
  }

  const backupPath = `${filePath}.bak`;
  fs.copyFileSync(filePath, backupPath);
  // Truncate in place.
  const fd = fs.openSync(filePath, 'r+');
  try {
    fs.ftruncateSync(fd, info.truncateTo);
  } finally {
    fs.closeSync(fd);
  }

  return {
    truncated: true,
    wouldTruncate: true,
    backupPath,
    removedBytes: info.removedBytes,
    detail: `truncated ${info.removedBytes} bytes from tail; backup at ${path.basename(backupPath)}`,
  };
}

function runRepairCli(args) {
  const fileIdx = args.indexOf('--file');
  if (fileIdx === -1 || !args[fileIdx + 1]) {
    console.error('Usage: occasio audit repair --file <path> [--dry-run]');
    process.exit(2);
  }
  const filePath = args[fileIdx + 1];
  const dryRun   = args.includes('--dry-run');

  const r = repairAuditFile(filePath, { dryRun });
  if (r.truncated) {
    console.log(`occasio audit repair: ${r.detail}`);
    return;
  }
  if (r.wouldTruncate) {
    console.log(`occasio audit repair (dry-run): ${r.detail}`);
    console.log('Re-run without --dry-run to apply.');
    return;
  }
  console.log(`occasio audit repair: nothing to do — ${r.detail}`);
}

module.exports = { repairAuditFile, runRepairCli };
