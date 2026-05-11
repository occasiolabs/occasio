'use strict';

/**
 * Audit input normalizer (ARCH-27).
 *
 * Produces a safe, governance-useful `tool_inputs` object for each tool call.
 * The guiding principle: log file-system metadata (what was accessed, where),
 * never log content-search strings or anything that could be a credential value.
 *
 * Per-tool scope:
 *   read_file       → { path }                           resolved absolute path
 *   find_files      → { pattern?, path? }                glob pattern only if structurally a glob
 *   grep            → { path?, glob? }                   pattern OMITTED intentionally
 *   todo_write      → { count }                          item count only, no content
 *   todo_read       → (absent)
 *   shell tools     → (absent)
 *   all others      → (absent)
 */

const os   = require('os');
const path = require('path');
const { scanSecrets, redactSecrets } = require('../analyzer');

// Glob metacharacters that distinguish structural patterns from content strings.
const GLOB_META = /[*?[{!]/;

/**
 * Normalize tool inputs to a safe, loggable shape.
 *
 * @param {string} toolName   Canonical tool name (e.g. 'read_file')
 * @param {object} toolInput  Raw tool input from the BoundaryEvent
 * @returns {object|undefined}  Safe input object, or undefined if nothing to log
 */
function normalizeToolInputsForAudit(toolName, toolInput) {
  if (!toolInput) return undefined;

  switch (toolName) {
    case 'read_file': {
      const raw = toolInput.file_path;
      if (typeof raw !== 'string' || !raw) return undefined;
      const resolved = expandAndResolve(raw);
      const { value: masked, wasMasked } = scanAndMask(resolved);
      const out = { path: masked };
      if (wasMasked) out.path_masked = true;
      return out;
    }

    case 'find_files': {
      const rawPattern = toolInput.pattern;
      const rawPath    = toolInput.path;
      const out = {};

      if (typeof rawPattern === 'string' && rawPattern) {
        // Only log if it looks like a real glob (has metacharacters) or is short enough
        // to be safe. A long string with no glob syntax is likely a content string.
        if (GLOB_META.test(rawPattern) || rawPattern.length <= 80) {
          const { value: masked, wasMasked } = scanAndMask(rawPattern);
          out.pattern = masked;
          if (wasMasked) out.pattern_masked = true;
        }
        // else: no metacharacters AND > 80 chars → omit (outside safe envelope)
      }

      if (typeof rawPath === 'string' && rawPath) {
        out.path = expandAndResolve(rawPath);
      }

      return Object.keys(out).length ? out : undefined;
    }

    case 'grep': {
      // Pattern intentionally omitted — free-form search strings can contain
      // arbitrary sensitive content the built-in scanner cannot bound.
      // Log only WHERE the agent searched (path + file-filter).
      const out = {};
      const rawPath = toolInput.path;
      const rawGlob = toolInput.glob;

      if (typeof rawPath === 'string' && rawPath) {
        out.path = expandAndResolve(rawPath);
      }
      if (typeof rawGlob === 'string' && rawGlob) {
        out.glob = rawGlob;
      }

      return Object.keys(out).length ? out : undefined;
    }

    case 'todo_write': {
      const count = Array.isArray(toolInput.todos) ? toolInput.todos.length : 0;
      return { count };
    }

    // todo_read, shell_bash, shell_powershell, unknown tools → nothing to log
    default:
      return undefined;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Expand leading ~ and path.resolve to absolute. */
function expandAndResolve(p) {
  if (typeof p !== 'string') return p;
  const expanded = p.startsWith('~') ? os.homedir() + p.slice(1) : p;
  return path.resolve(expanded);
}

/**
 * Scan a short string (path, pattern) for embedded secrets.
 * Returns the original value if clean, or a redacted version if a hit was found.
 * This is a safeguard for edge cases (e.g., a filename that IS a token); it is
 * not expected to fire under normal use.
 */
function scanAndMask(value) {
  const hits = scanSecrets(value);
  if (!hits || hits.length === 0) return { value, wasMasked: false };
  return { value: redactSecrets(value), wasMasked: true };
}

module.exports = { normalizeToolInputsForAudit };
