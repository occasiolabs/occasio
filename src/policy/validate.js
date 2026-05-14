'use strict';

/**
 * occasio policy validate — parse ~/.occasio/policy.yml and report
 * every issue that would cause silent failures at runtime.
 *
 * Two severity levels:
 *   error   — field will be silently dropped or mis-applied at runtime
 *   warning — field is valid but suspicious (unknown name, unused entry, etc.)
 *
 * Exit code via the caller (index.js):
 *   0  — no errors (clean or warnings-only)
 *   1  — at least one error
 *
 * Usage:
 *   occasio policy validate
 *   occasio policy validate --file /path/to/policy.yml
 */

const fs   = require('fs');
const path = require('path');

// ── Validation constants ───────────────────────────────────────────────────────

const KNOWN_TOP_LEVEL = new Set([
  'version',
  'block_secrets_in_tool_results',
  'redact_secrets_in_tool_results',
  'distill_tool_results',
  'block_requests_over_budget',
  'tools',
  'deny_paths',
  'allow_paths',
  'deny_patterns',
]);

const BOOLEAN_FLAGS = [
  'block_secrets_in_tool_results',
  'redact_secrets_in_tool_results',
  'distill_tool_results',
  'block_requests_over_budget',
];

const VALID_ACTIONS    = new Set(['PASS', 'LOCAL', 'TRANSFORM']);
const KNOWN_TRANSFORMS = new Set(['redact-secrets', 'distill-output']);

// Sourced from policy/built-in-classifiers.js — kept as a plain Set here so
// validate.js has no require-time dependency on the runtime classifier code.
const KNOWN_CLASSIFIERS = new Set([
  'read-input-validator',
  'glob-input-validator',
  'grep-input-validator',
  'todo-write-validator',
  'todo-read-validator',
  'bash-allowlist',
  'powershell-allowlist',
]);

const KNOWN_TOOL_ENTRY_KEYS = new Set(['action', 'transform', 'executor', 'classifier', 'reason', 'max_output_tokens']);

// ── ANSI colors ────────────────────────────────────────────────────────────────

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

function pad(s, n) { return String(s).padEnd(n); }

// ── Core validation ────────────────────────────────────────────────────────────

/**
 * Validate a single tool entry object. Pushes issues into the shared arrays.
 */
function validateToolEntry(toolPath, entry, errors, warnings) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    errors.push({ path: toolPath, message: 'entry must be a mapping (e.g. action: LOCAL)' });
    return;
  }

  // Unknown fields in the tool entry
  for (const key of Object.keys(entry)) {
    if (!KNOWN_TOOL_ENTRY_KEYS.has(key)) {
      warnings.push({ path: `${toolPath}.${key}`, message: 'unknown field — will be ignored at runtime' });
    }
  }

  const action = entry.action;
  if (action === undefined || action === null || action === '') {
    errors.push({ path: `${toolPath}.action`, message: 'missing required field "action"' });
    return;
  }
  if (!VALID_ACTIONS.has(action)) {
    errors.push({
      path:    `${toolPath}.action`,
      message: `"${action}" is not a valid action — must be PASS, LOCAL, or TRANSFORM`,
    });
    return;
  }

  if (action === 'TRANSFORM') {
    if (!entry.transform || typeof entry.transform !== 'string' || !entry.transform.trim()) {
      errors.push({
        path:    `${toolPath}.transform`,
        message: 'TRANSFORM requires a non-empty "transform" field (e.g. transform: distill-output)',
      });
    } else if (!KNOWN_TRANSFORMS.has(entry.transform.trim())) {
      warnings.push({
        path:    `${toolPath}.transform`,
        message: `"${entry.transform}" is not a built-in transform — ensure it is implemented in the dispatcher`,
      });
    }
  }

  if (action === 'LOCAL' && entry.classifier) {
    if (!KNOWN_CLASSIFIERS.has(entry.classifier)) {
      warnings.push({
        path:    `${toolPath}.classifier`,
        message: `"${entry.classifier}" is not a known classifier — entry will fall back to PASS at runtime`,
      });
    }
  }

  if ('max_output_tokens' in entry) {
    const v = entry.max_output_tokens;
    if (typeof v !== 'number' || !Number.isFinite(v) || !Number.isInteger(v) || v <= 0) {
      errors.push({
        path:    `${toolPath}.max_output_tokens`,
        message: `expected a positive integer (tokens), got ${JSON.stringify(v)}`,
      });
    }
  }
}

/**
 * Validate a parsed policy object (output of loader.parse()).
 *
 * @param {object} parsed  Raw parsed policy (not yet normalized)
 * @returns {{ errors: Array<{path, message}>, warnings: Array<{path, message}> }}
 */
function validatePolicy(parsed) {
  const errors   = [];
  const warnings = [];

  if (!parsed || typeof parsed !== 'object') {
    errors.push({ path: '(document)', message: 'policy must be a YAML mapping at the top level' });
    return { errors, warnings };
  }

  // Unknown top-level keys
  for (const key of Object.keys(parsed)) {
    if (!KNOWN_TOP_LEVEL.has(key)) {
      warnings.push({ path: key, message: 'unknown key — will be ignored at runtime' });
    }
  }

  // version type
  if ('version' in parsed && typeof parsed.version !== 'number') {
    errors.push({ path: 'version', message: `expected a number, got ${JSON.stringify(parsed.version)}` });
  }

  // Boolean flags
  for (const flag of BOOLEAN_FLAGS) {
    if (flag in parsed && typeof parsed[flag] !== 'boolean') {
      errors.push({
        path:    flag,
        message: `expected true or false, got ${JSON.stringify(parsed[flag])}`,
      });
    }
  }

  // deny_paths / allow_paths — error severity because a silently skipped deny
  // entry is a silent security gap, not just a misconfiguration warning.
  for (const listKey of ['deny_paths', 'allow_paths']) {
    if (listKey in parsed) {
      const val = parsed[listKey];
      if (!Array.isArray(val)) {
        errors.push({ path: listKey, message: 'must be a list (each entry on a new line starting with "- ")' });
      } else {
        val.forEach((entry, i) => {
          if (typeof entry !== 'string' || !entry.trim()) {
            errors.push({
              path:    `${listKey}[${i}]`,
              message: 'entry is not a non-empty string — will be silently skipped at runtime',
            });
          }
        });
      }
    }
  }

  // deny_patterns — error severity for invalid RegExp values
  if ('deny_patterns' in parsed) {
    const val = parsed.deny_patterns;
    if (!val || typeof val !== 'object' || Array.isArray(val)) {
      errors.push({ path: 'deny_patterns', message: 'must be a mapping of label: "regex-string" entries' });
    } else {
      for (const [label, rawPattern] of Object.entries(val)) {
        if (typeof rawPattern !== 'string') {
          errors.push({
            path:    `deny_patterns.${label}`,
            message: `value must be a regex string, got ${JSON.stringify(rawPattern)}`,
          });
        } else {
          try { new RegExp(rawPattern); } catch (e) {
            errors.push({
              path:    `deny_patterns.${label}`,
              message: `invalid RegExp "${rawPattern}" — ${e.message}`,
            });
          }
        }
      }
    }
  }

  // tools block
  if ('tools' in parsed) {
    const t = parsed.tools;
    if (!t || typeof t !== 'object' || Array.isArray(t)) {
      errors.push({ path: 'tools', message: 'must be a mapping of tool names to entries' });
    } else {
      for (const [name, entry] of Object.entries(t)) {
        validateToolEntry(`tools.${name}`, entry, errors, warnings);
      }
    }
  }

  return { errors, warnings };
}

// ── CLI display ────────────────────────────────────────────────────────────────

/**
 * @param {string[]} args  Remaining CLI args after 'policy validate'
 * @param {object}  [opts] { loader, fs } — injectable for tests
 * @returns {{ ok: boolean }}  ok=false when errors exist; caller should exit(1)
 */
function runValidateCli(args, opts = {}) {
  const loader = opts.loader || require('./loader');
  const fsMod  = opts.fs     || fs;

  // Determine file path — support --file override
  const fileArgIdx = (args || []).indexOf('--file');
  const filePath   = (fileArgIdx >= 0 && args[fileArgIdx + 1])
    ? path.resolve(args[fileArgIdx + 1])
    : loader.DEFAULT_PATH;

  // Attempt to read the file
  let text       = null;
  let fileExists = false;
  try {
    text       = fsMod.readFileSync(filePath, 'utf8');
    fileExists = true;
  } catch { /* file absent or unreadable */ }

  // Header
  console.log(col.b('\n⚡ Occasio — Policy Validate\n'));
  const fileStatus = fileExists
    ? `${filePath}  ${col.g('(loaded)')}`
    : `${col.d(filePath)}  ${col.d('(not found)')}`;
  console.log(`  File:    ${fileStatus}`);

  if (!fileExists) {
    console.log(col.g('\n  ✓  No policy file — built-in defaults apply.\n'));
    return { ok: true };
  }

  // Parse the raw text and validate
  const parsed             = loader.parse(text);
  const { errors, warnings } = validatePolicy(parsed);

  if (errors.length === 0 && warnings.length === 0) {
    console.log(col.g('\n  ✓  Policy is valid — no issues found.\n'));
    return { ok: true };
  }

  const pathWidth = (items) =>
    items.length ? Math.max(...items.map(i => i.path.length)) + 2 : 0;

  if (errors.length) {
    const pw = pathWidth(errors);
    console.log(col.r(`\n  ✗  ${errors.length} error${errors.length !== 1 ? 's' : ''}:`));
    for (const e of errors) {
      console.log(`     ${pad(e.path, pw)}  ${col.r(e.message)}`);
    }
  }

  if (warnings.length) {
    const pw = pathWidth(warnings);
    console.log(col.y(`\n  ⚠  ${warnings.length} warning${warnings.length !== 1 ? 's' : ''}:`));
    for (const w of warnings) {
      console.log(`     ${pad(w.path, pw)}  ${col.y(w.message)}`);
    }
  }

  console.log('');

  if (errors.length) {
    console.log(col.r('  Errors found — policy will not apply as written.\n'));
    return { ok: false };
  }

  console.log(col.y('  Warnings present — review the issues above.\n'));
  return { ok: true };
}

module.exports = { validatePolicy, runValidateCli, KNOWN_TOP_LEVEL, KNOWN_TRANSFORMS, KNOWN_CLASSIFIERS, VALID_ACTIONS };
