'use strict';

/**
 * occasio policy show — display the active policy in human-readable form.
 *
 * Shows global flags and per-tool routing/transform decisions, annotating
 * each value as either the default or a user override from policy.yml.
 *
 * Usage:
 *   occasio policy [show]         Full view of the active policy
 *   occasio policy show --diff    Only values that differ from defaults
 */

const fs   = require('fs');

// Transforms currently implemented in the dispatcher.
const KNOWN_TRANSFORMS = new Set(['redact-secrets', 'distill-output']);

// Global flag keys, in display order.
const GLOBAL_FLAG_KEYS = [
  'block_secrets_in_tool_results',
  'redact_secrets_in_tool_results',
  'distill_tool_results',
  'block_requests_over_budget',
];

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

function pad(s, n) { return String(s).padEnd(n); }

/**
 * Format one tool entry for display.
 * Returns { line: string, warn: string|null }
 */
function formatToolEntry(entry) {
  if (!entry) {
    return { line: col.y('PASS') + col.d('  (absent from tools: block → cloud only)'), warn: null };
  }
  const a = entry.action;
  if (a === 'LOCAL') {
    return { line: col.g('LOCAL'), warn: null };
  }
  if (a === 'TRANSFORM') {
    const tf = entry.transform || '(none)';
    const known = KNOWN_TRANSFORMS.has(tf);
    const tfStr = known ? col.c(tf) : col.r(tf);
    const warn  = known ? null : `unknown transform '${tf}' — not implemented in dispatcher`;
    return { line: `${col.c('TRANSFORM')} → ${tfStr}`, warn };
  }
  if (a === 'PASS') {
    return { line: col.d('PASS') + col.d('  (cloud only)'), warn: null };
  }
  return { line: col.r(`${a}  (unrecognized action)`), warn: `unrecognized action '${a}'` };
}

/**
 * Determine if an active tool entry differs from the default entry.
 */
function isToolOverride(actEntry, defEntry) {
  if (!actEntry && !defEntry) return false;
  if (!actEntry || !defEntry) return true;   // one is absent — different
  return actEntry.action !== defEntry.action || actEntry.transform !== defEntry.transform;
}

/**
 * Main display function.
 *
 * @param {string[]} args   Remaining CLI args after 'policy [show]'
 * @param {object}   [opts] { loader } — injectable for tests; defaults to real loader
 */
function runPolicyCli(args, opts = {}) {
  const loader   = opts.loader || require('./loader');
  const diffMode = (args || []).includes('--diff');

  // ── Source detection ──────────────────────────────────────────────────────
  const filePath = loader.DEFAULT_PATH;
  let fileExists = false;
  let userParsed = {};
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    fileExists = true;
    userParsed = loader.parse(text);
  } catch { /* ignore */ }

  const active   = loader.load();
  const defaults = loader.DEFAULT_POLICY;

  // ── Header ────────────────────────────────────────────────────────────────
  console.log(col.b('\n⚡ Occasio — Active Policy\n'));

  const fileStatus = fileExists
    ? `${filePath}  ${col.g('(loaded)')}`
    : `${col.d(filePath)}  ${col.d('(not found — defaults apply)')}`;
  console.log(`  File:    ${fileStatus}`);

  if (diffMode && !fileExists) {
    console.log(col.d('\n  No overrides — no policy.yml found; all defaults apply.\n'));
    return;
  }

  // ── Global flags ──────────────────────────────────────────────────────────
  const globalOverrides = GLOBAL_FLAG_KEYS.filter(k => active[k] !== defaults[k]);

  if (!diffMode || globalOverrides.length > 0) {
    console.log(col.b('\n  Global flags:'));
    const keyWidth = Math.max(...GLOBAL_FLAG_KEYS.map(k => k.length)) + 2;
    for (const k of GLOBAL_FLAG_KEYS) {
      const isOverride = active[k] !== defaults[k];
      if (diffMode && !isOverride) continue;
      const val      = active[k];
      const valStr   = String(val);
      const valCol   = val === true  ? col.g(valStr)
                     : val === false ? col.d(valStr)
                     : col.y(valStr);
      const ann = isOverride ? col.c('  ← override') : col.d('  (default)');
      console.log(`    ${pad(k, keyWidth)}  ${valCol}${ann}`);
    }
  }

  // ── Tool routing ──────────────────────────────────────────────────────────
  const defaultTools = defaults.tools || {};
  const activeTools  = active.tools   || {};

  // Unified tool name list: all default tools + any user-defined extras
  const allNames = [...new Set([
    ...Object.keys(defaultTools),
    ...Object.keys(activeTools),
  ])];

  // Detect which tools have a user-declared tools: block at all
  const userHasToolsBlock = fileExists &&
    userParsed.tools && typeof userParsed.tools === 'object' &&
    Object.keys(userParsed.tools).length > 0;

  // Tools removed by a user tools: block (default tools now absent from activeTools)
  const removedByUserBlock = userHasToolsBlock
    ? Object.keys(defaultTools).filter(k => !activeTools[k])
    : [];

  // Filter to display
  const namesToShow = allNames.filter(name => {
    if (!diffMode) return true;
    return isToolOverride(activeTools[name], defaultTools[name]);
  });

  if (!diffMode || namesToShow.length > 0 || removedByUserBlock.length > 0) {
    const userExtra = allNames.filter(n => !defaultTools[n] && activeTools[n]);
    const countNote = userExtra.length
      ? col.d(` (${Object.keys(defaultTools).length} defaults + ${userExtra.length} user-defined)`)
      : col.d(` (${allNames.length} tools)`);
    console.log(col.b('\n  Tool routing:') + countNote);

    // Warn if user's tools: block removed defaults
    if (removedByUserBlock.length > 0) {
      console.log(col.y('\n  ⚠  tools: block replaces all defaults.') +
        col.d(' Tools not listed will PASS to cloud:'));
      console.log(col.y(`       ${removedByUserBlock.join(', ')}`));
    }

    const nameWidth = Math.max(...allNames.map(n => n.length), 16) + 2;

    for (const name of allNames) {
      const actEntry = activeTools[name];
      const defEntry = defaultTools[name];
      const isOverride = isToolOverride(actEntry, defEntry);

      if (diffMode && !isOverride) continue;

      // For user tools: block — absent defaults show as override (removed)
      const entryToShow = actEntry || null;
      const { line, warn } = formatToolEntry(entryToShow);
      const ann = isOverride ? col.c('  ← override') : col.d('  (default)');
      const extra = !defEntry ? col.d('  (user-defined)') : '';
      const warnStr = warn ? col.y(`  ⚠ ${warn}`) : '';

      console.log(`    ${pad(name, nameWidth)}  ${line}${ann}${extra}${warnStr}`);
    }
  }

  if (diffMode && !globalOverrides.length && !namesToShow.length && !removedByUserBlock.length) {
    console.log(col.d('\n  No overrides — active policy matches defaults.\n'));
    return;
  }

  console.log('');
}

module.exports = { runPolicyCli, KNOWN_TRANSFORMS, formatToolEntry, isToolOverride };
