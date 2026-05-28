'use strict';

/**
 * occasio policy doctor — cross-reference live session logs with the
 * active policy and surface actionable improvement suggestions.
 *
 * Usage:
 *   occasio policy doctor              Analyse last 7 days of logs
 *   occasio policy doctor --days 14    Analyse last N days
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const ANSI_RESET = '\x1b[0m';
const col = {
  r: s => `\x1b[31m${s}${ANSI_RESET}`,
  g: s => `\x1b[32m${s}${ANSI_RESET}`,
  y: s => `\x1b[33m${s}${ANSI_RESET}`,
  c: s => `\x1b[36m${s}${ANSI_RESET}`,
  d: s => `\x1b[2m${s}${ANSI_RESET}`,
  b: s => `\x1b[1m${s}${ANSI_RESET}`,
};

// Every doctor line ends with an explicit ANSI reset so Windows Terminal (and
// other emulators that carry color state across line breaks) cannot bleed an
// in-template attribute into the next console.log call. The per-segment reset
// inside `col.X()` lands mid-line, which is fine for VT100 but insufficient
// for terminals that buffer state at line boundaries.
function safe(line) { return `${line}${ANSI_RESET}`; }

const LOG_DIR = path.join(os.homedir(), '.occasio');

// Maps agent-protocol tool names (as logged in tools[].tool) to policy
// canonical names used in policy.yml tools: blocks.
const TOOL_TO_CANONICAL = {
  Read:        'read_file',
  Glob:        'find_files',
  Grep:        'grep',
  Bash:        'shell_bash',
  PowerShell:  'shell_powershell',
  TodoWrite:   'todo_write',
  TodoRead:    'todo_read',
  // Cline names (canonical = logged name for Cline)
  read_file:   'read_file',
  find_files:  'find_files',
  grep:        'grep',
  shell_bash:  'shell_bash',
};

// Tools where distillation is not meaningful (structured outputs, tiny results).
const SKIP_DISTILL_SUGGEST = new Set(['TodoWrite', 'TodoRead', 'todo_write', 'todo_read']);

function readRecentLogs(days, logsDir) {
  const dir = logsDir || path.join(LOG_DIR, 'logs');
  const entries = [];
  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.endsWith('.jsonl'))
      .sort()
      .reverse()
      .slice(0, Math.min(days, 30));
    for (const f of files) {
      for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try { entries.push(JSON.parse(line)); } catch { /* ignore */ }
      }
    }
  } catch { /* ignore */ }
  return entries;
}

function aggregate(entries) {
  const fallbackCounts     = {};
  const toolLocalCounts    = {};  // logged tool name → # local runs
  const toolDistilledCounts= {};  // logged tool name → # with distillation
  const toolShapedCounts   = {};  // logged tool name → # with any TRANSFORM
  let totalAttempted = 0;
  let totalLocal     = 0;

  for (const e of entries) {
    totalAttempted += e.tools_attempted || 0;
    totalLocal     += (e.tools_local_count || 0) + (e.tools_mcp_count || 0);

    for (const reason of (e.fallback_reasons || [])) {
      fallbackCounts[reason] = (fallbackCounts[reason] || 0) + 1;
    }

    for (const t of (e.tools || [])) {
      const name = t.tool || 'unknown';
      toolLocalCounts[name]     = (toolLocalCounts[name]    || 0) + 1;
      if (t.distilled)   toolDistilledCounts[name] = (toolDistilledCounts[name] || 0) + 1;
      if (t.transformed) toolShapedCounts[name]    = (toolShapedCounts[name]    || 0) + 1;
    }
  }

  return { fallbackCounts, toolLocalCounts, toolDistilledCounts, toolShapedCounts,
           totalAttempted, totalLocal };
}

function buildSuggestions(agg, policy) {
  const suggestions = [];
  const { fallbackCounts, toolLocalCounts, toolDistilledCounts, toolShapedCounts } = agg;

  // ── Suggestion 1: secrets blocking local intercepts ───────────────────────
  const secretBlockCount = fallbackCounts['secret_in_tool_result'] || 0;
  if (secretBlockCount > 0 && policy.block_secrets_in_tool_results && !policy.redact_secrets_in_tool_results) {
    suggestions.push({
      severity: 'warn',
      title: `${secretBlockCount} local intercept${secretBlockCount > 1 ? 's' : ''} blocked because a tool result contained a secret`,
      detail: 'The interceptor ran the tool locally, found a secret in the output, and fell back to cloud. ' +
              'Redact mode keeps the result local with the secret replaced.',
      fix: 'redact_secrets_in_tool_results: true\nblock_secrets_in_tool_results: false',
    });
  }

  // ── Suggestion 2: local tools running without output shaping ─────────────
  if (!policy.distill_tool_results) {
    const candidates = Object.entries(toolLocalCounts)
      .filter(([name]) => !SKIP_DISTILL_SUGGEST.has(name))
      .map(([name, count]) => {
        const shaped   = (toolDistilledCounts[name] || 0) + (toolShapedCounts[name] || 0);
        const unshaped = count - shaped;
        return { name, count, unshaped };
      })
      .filter(t => t.unshaped > 2)
      .sort((a, b) => b.unshaped - a.unshaped);

    if (candidates.length > 0) {
      const totalUnshaped = candidates.reduce((s, t) => s + t.unshaped, 0);
      const top = candidates[0];
      const canonicalHint = TOOL_TO_CANONICAL[top.name] || top.name.toLowerCase();
      suggestions.push({
        severity: 'info',
        title: `${totalUnshaped} local tool result${totalUnshaped > 1 ? 's' : ''} sent to the model without output shaping`,
        detail: `Heaviest: ${top.name} (${top.unshaped} unshaped runs). Full output is forwarded to the model — distillation removes boilerplate and saves tokens.`,
        fix: candidates.length >= 2
          ? `Global (all tools):\n  distill_tool_results: true\n\nOr per-tool:\n  tools:\n    ${canonicalHint}:\n      action: TRANSFORM\n      transform: distill-output`
          : `tools:\n  ${canonicalHint}:\n    action: TRANSFORM\n    transform: distill-output`,
      });
    }
  }

  // ── Suggestion 3: shell commands with complex syntax (informational) ──────
  const shellFallbacks = (fallbackCounts['ps_shell_composition'] || 0)
                       + (fallbackCounts['bash_shell_meta']       || 0)
                       + (fallbackCounts['ps_not_native']         || 0)
                       + (fallbackCounts['bash_unrecognized']     || 0);
  if (shellFallbacks > 5) {
    suggestions.push({
      severity: 'info',
      title: `${shellFallbacks} shell command${shellFallbacks > 1 ? 's' : ''} passed to cloud (complex syntax)`,
      detail: 'Piped commands, redirects, and non-native executables cannot run locally — this is expected. No policy change needed.',
      fix: null,
    });
  }

  // ── Suggestion 4: max rounds exceeded (informational) ────────────────────
  const maxRounds = fallbackCounts['max_rounds_exceeded'] || 0;
  if (maxRounds > 2) {
    suggestions.push({
      severity: 'info',
      title: `${maxRounds} session${maxRounds > 1 ? 's' : ''} hit the interceptor round limit`,
      detail: 'Long tool chains can exhaust the interceptor\'s multi-round budget. The agent falls back to cloud for the remaining rounds — this is expected for complex tasks.',
      fix: null,
    });
  }

  if (suggestions.length === 0) {
    suggestions.push({ severity: 'ok', title: 'No policy improvements found', detail: null, fix: null });
  }

  return suggestions;
}

function runDoctorCli(args, opts = {}) {
  const loader   = opts.loader   || require('./loader');
  const logsDir  = opts.logsDir  || null;

  const daysArg  = (args || []).indexOf('--days');
  const days     = daysArg >= 0 && args[daysArg + 1] ? (parseInt(args[daysArg + 1], 10) || 7) : 7;

  console.log(safe(col.b('\n⚡ Occasio — Policy Doctor\n')));

  const entries = readRecentLogs(days, logsDir);
  if (!entries.length) {
    console.log(safe(col.d(`  No session logs found (last ${days} day${days > 1 ? 's' : ''}).`)));
    console.log(safe(col.d('  Run a session first, then re-run occasio policy doctor.\n')));
    return { ok: true, suggestions: [] };
  }

  const policy      = loader.load();
  const agg         = aggregate(entries);
  const suggestions = buildSuggestions(agg, policy);

  // ── Summary line ───────────────────────────────────────────────────────────
  const { totalAttempted, totalLocal } = agg;
  const denom    = Math.max(totalAttempted, totalLocal);
  const localPct = denom > 0 ? Math.round((totalLocal / denom) * 100) : 0;

  console.log(safe(
    `  Analysed ${col.b(entries.length)} log entr${entries.length > 1 ? 'ies' : 'y'}` +
    `  ·  ${col.b(totalAttempted)} tool call${totalAttempted !== 1 ? 's' : ''}` +
    `  ·  ${col.b(localPct + '%')} handled locally\n`,
  ));

  // ── Suggestions ────────────────────────────────────────────────────────────
  for (const s of suggestions) {
    if (s.severity === 'ok') {
      console.log(safe(`  ${col.g('✓')}  ${s.title}\n`));
      continue;
    }
    const icon = s.severity === 'warn' ? col.y('⚠') : col.c('ℹ');
    console.log(safe(`  ${icon}  ${col.b(s.title)}`));
    if (s.detail) console.log(safe(`     ${col.d(s.detail)}`));
    if (s.fix) {
      console.log(safe(`\n     ${col.c('Suggested fix (policy.yml):')}`));
      for (const line of s.fix.split('\n')) {
        console.log(safe(`       ${col.c(line)}`));
      }
    }
    console.log('');
  }

  const hasActionable = suggestions.some(s => s.fix);
  if (hasActionable) {
    console.log(safe(col.d('  Edit ~/.occasio/policy.yml, then run occasio policy validate\n')));
  }

  return { ok: true, suggestions };
}

module.exports = { runDoctorCli, readRecentLogs, aggregate, buildSuggestions };
