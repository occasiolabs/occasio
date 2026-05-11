'use strict';

/**
 * mcp-normalize.js — Input normalization shims for LocalFirst MCP tools.
 *
 * Adapts the parameter shapes Claude actually sends (matching the lao server's
 * observed schemas) to the shapes expected by handleReadTool, handleGlobTool,
 * and handleGrepTool in interceptor.js.
 *
 * All three functions are pure (no I/O) and exported for unit testing.
 *
 * Real Claude call shapes observed:
 *   read_file   — { path, start_line?, end_line? }
 *   find_files  — { pattern, path?, extension?, max_results? }
 *   grep        — { pattern, path?, case_sensitive?, file_glob?, max_results? }
 */

/**
 * Normalize read_file arguments.
 *
 * Claude sends:    { path, start_line?, end_line? }
 * Legacy accepted: { file_path, offset?, limit? }
 * handleReadTool expects: { file_path, offset?, limit? }
 *
 * start_line / end_line are 1-based line numbers (inclusive).
 * offset is 0-based; limit is a line count.
 *
 * @param {object} args
 * @returns {{ file_path: string, offset?: number, limit?: number }}
 */
function normalizeReadInput(args) {
  if (!args || typeof args !== 'object') return { file_path: '' };

  const file_path = (args.path || args.file_path || '').trim();
  const result    = { file_path };

  if (args.start_line != null) {
    // 1-based start_line → 0-based offset
    const sl    = parseInt(args.start_line, 10) || 0;
    result.offset = Math.max(0, sl - 1);
    if (args.end_line != null) {
      const el    = parseInt(args.end_line, 10) || sl;
      result.limit = Math.max(1, el - sl + 1);
    }
  } else {
    if (args.offset != null) result.offset = args.offset;
    if (args.limit  != null) result.limit  = args.limit;
  }

  return result;
}

/**
 * Normalize find_files arguments.
 *
 * Claude sends:    { pattern, path?, extension?, max_results? }
 * handleGlobTool expects: { pattern, path? }
 *
 * Conversions:
 *   plain name fragment (no glob chars) → **\/*fragment*
 *   extension only                      → **\/*<ext>
 *   name fragment + extension           → **\/*fragment*<ext>
 *   full glob passthrough               → unchanged
 *   max_results                         → ignored (handleGlobTool caps at 500)
 *
 * @param {object} args
 * @returns {{ pattern: string, path?: string }}
 */
function normalizeFindInput(args) {
  if (!args || typeof args !== 'object') return { pattern: '**/*' };

  const rawPattern = (args.pattern || '').trim();
  const ext        = args.extension
    ? (args.extension.startsWith('.') ? args.extension : '.' + args.extension)
    : '';
  const isGlob     = /[*?{[]/.test(rawPattern);

  let pattern;
  if (ext) {
    if (!rawPattern) {
      pattern = `**/*${ext}`;
    } else if (isGlob) {
      // Glob already present — append extension only when not already there
      pattern = rawPattern.endsWith(ext) ? rawPattern : `${rawPattern}${ext}`;
    } else {
      // Plain fragment + extension: "analyzer" + ".js" → "**/*analyzer*.js"
      pattern = `**/*${rawPattern}*${ext}`;
    }
  } else if (!rawPattern) {
    pattern = '**/*';
  } else if (isGlob) {
    pattern = rawPattern;
  } else {
    // Plain name fragment: "interceptor" → "**/*interceptor*"
    pattern = `**/*${rawPattern}*`;
  }

  const result = { pattern };
  if (args.path && args.path !== '.') result.path = args.path;

  return result;
}

/**
 * Normalize grep arguments.
 *
 * Claude sends:    { pattern, path?, case_sensitive?, file_glob?, max_results?, output_mode? }
 * handleGrepTool expects: { pattern, path?, glob?, '-i'?, head_limit?, output_mode? }
 *
 * lao schema default: case_sensitive = false → case-insensitive.
 * We preserve that: -i is true unless case_sensitive is explicitly true.
 *
 * @param {object} args
 * @returns {object}
 */
function normalizeGrepInput(args) {
  if (!args || typeof args !== 'object') return { pattern: '', '-i': true };

  const result = { pattern: args.pattern || '' };

  if (args.path && args.path !== '.') result.path = args.path;
  if (args.file_glob)                 result.glob = args.file_glob;
  if (args.type)                      result.type = args.type;

  // lao default: case_sensitive = false → case-insensitive search
  result['-i'] = args.case_sensitive !== true;

  if (args.max_results != null && args.max_results > 0) result.head_limit = args.max_results;
  if (args.output_mode) result.output_mode = args.output_mode;

  // Pass through context flags when present
  if (args['-C'] != null) result['-C'] = args['-C'];
  if (args['-A'] != null) result['-A'] = args['-A'];
  if (args['-B'] != null) result['-B'] = args['-B'];

  return result;
}

module.exports = { normalizeReadInput, normalizeFindInput, normalizeGrepInput };
