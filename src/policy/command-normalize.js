'use strict';

/**
 * command-normalize.js — the single source of truth for turning a shell command
 * into the canonical form that the identity approval store hashes, and that the
 * audit chain records as `command_hash`. Because BOTH the store (when it mints
 * and looks up an approval token) and the auditor (when it records the event)
 * use this exact function, the audit row's `command_hash` and the approval
 * token's `command_hash` always agree — a reviewer can join them.
 *
 * Normalization (quote-aware, deterministic — NOT a full shell parser):
 *   - collapse runs of whitespace *outside* quotes to a single space; whitespace
 *     *inside* single/double quotes is preserved verbatim (so a quoted remote
 *     command keeps its exact spacing);
 *   - lowercase only the leading verb (the first token);
 *   - DO NOT strip comments — a `#` can live inside a quoted remote command
 *     (`ssh host "echo #1"`), so stripping would corrupt the bound command.
 *
 * The whole command is bound, including the remote part: `ssh host "systemctl
 * restart x"` is a different token from `ssh host "systemctl restart y"` and
 * from a bare `ssh`. Least-privilege by construction.
 */

const crypto = require('crypto');

/**
 * Canonicalize a shell command for hashing. Deterministic and quote-aware.
 * @param {string} cmd
 * @returns {string}
 */
function normalizeCommand(cmd) {
  if (typeof cmd !== 'string') return '';

  let out = '';
  let inSingle = false;
  let inDouble = false;
  let prevWasSpace = false;

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];

    if (inSingle) {
      // POSIX single quotes: everything literal until the next single quote.
      out += c;
      if (c === "'") inSingle = false;
      prevWasSpace = false;
      continue;
    }
    if (inDouble) {
      // Inside double quotes a backslash escapes the next char; keep both so a
      // `\"` does not prematurely close the quote.
      if (c === '\\' && i + 1 < cmd.length) {
        out += c + cmd[i + 1];
        i++;
        prevWasSpace = false;
        continue;
      }
      out += c;
      if (c === '"') inDouble = false;
      prevWasSpace = false;
      continue;
    }

    if (c === "'") { inSingle = true; out += c; prevWasSpace = false; continue; }
    if (c === '"') { inDouble = true; out += c; prevWasSpace = false; continue; }

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') {
      if (!prevWasSpace) { out += ' '; prevWasSpace = true; }
      continue;
    }

    out += c;
    prevWasSpace = false;
  }

  out = out.trim();

  // Lowercase only the leading verb (first whitespace-delimited token).
  const sp = out.indexOf(' ');
  if (sp === -1) return out.toLowerCase();
  return out.slice(0, sp).toLowerCase() + out.slice(sp);
}

/**
 * SHA-256 hex of the normalized command. This is the approval scope key.
 * @param {string} cmd
 * @returns {string} 64-hex
 */
function commandHash(cmd) {
  return crypto.createHash('sha256').update(normalizeCommand(cmd), 'utf8').digest('hex');
}

module.exports = { normalizeCommand, commandHash };
