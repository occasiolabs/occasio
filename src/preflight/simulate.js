'use strict';

/**
 * occasio preflight simulate — forward dry-run of candidate actions against the
 * active policy, BEFORE the agent runs. Each action is evaluated through the
 * real policy engine (deterministic, not a guess), and blocks are explained
 * with the matched rule + how to unblock (reusing #9's resolveBlockedRule).
 *
 * Simulates concrete candidate actions (not a natural-language task — that
 * would need an LLM). Read-only; zero dependencies.
 */

const fs     = require('fs');
const engine = require('../policy/engine');
const loader = require('../policy/loader');
const { resolveBlockedRule } = require('../policy/explain-rule');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

// probe name → canonical tool (path enforcement only fires on canonical names)
const CANON = {
  read: 'read_file', read_file: 'read_file', Read: 'read_file',
  glob: 'find_files', find_files: 'find_files', Glob: 'find_files',
  grep: 'grep', Grep: 'grep',
  bash: 'shell_bash', shell_bash: 'shell_bash', Bash: 'shell_bash',
  ps: 'shell_powershell', powershell: 'shell_powershell', shell_powershell: 'shell_powershell', PowerShell: 'shell_powershell',
};

function toCanonicalAction({ tool, target }) {
  const canonical = CANON[tool] || CANON[String(tool || '').toLowerCase()] || null;
  if (!canonical || !target) return null;
  let input, verb;
  if (canonical === 'read_file')        { input = { file_path: target }; verb = 'read'; }
  else if (canonical === 'find_files')  { input = { path: target };      verb = 'glob'; }
  else if (canonical === 'grep')        { input = { path: target };      verb = 'grep'; }
  else if (canonical === 'shell_bash')  { input = { command: target };   verb = 'bash'; }
  else                                  { input = { command: target };   verb = 'ps';   }
  return { tool: canonical, input, target, label: `${verb} ${target}` };
}

/**
 * Run candidate actions through the policy engine.
 * @param {Array<{tool,input,target,label}>} actions  (canonical, from toCanonicalAction)
 * @param {{rawText,parsed,policyPath}} ctx  policy text for block explanation
 * @returns {{results:Array, summary:{total,allowed,blocked}}}
 */
function simulate(actions, ctx = {}) {
  const results = [];
  let allowed = 0, blocked = 0;
  for (const a of (actions || [])) {
    if (!a) continue;
    const decision = engine.evaluate({ kind: 'tool_call', toolName: a.tool, toolInput: a.input });
    const isBlock = decision.action === 'BLOCK';
    let rule = null;
    if (isBlock) {
      rule = resolveBlockedRule(
        { kind: 'tool_call', tool_name: a.tool, reason: decision.reason,
          tool_inputs: { path: a.input.file_path || a.input.path, command: a.input.command } },
        { rawText: ctx.rawText || '', parsed: ctx.parsed || {} }
      );
    }
    if (isBlock) blocked++; else allowed++;
    results.push({
      label: a.label, tool: a.tool, target: a.target,
      verdict: isBlock ? 'block' : 'allow',
      decision_action: decision.action, reason: decision.reason, rule,
    });
  }
  return { results, summary: { total: results.length, allowed, blocked } };
}

/** Fold the project's mined READ opening-moves (paths) into read_file actions. */
function minedReadActions(opts = {}) {
  const { mine } = require('./miner');
  const out = [];
  for (const proj of mine({ days: opts.days || 30, logsDir: opts.logsDir, filterCwd: opts.cwd })) {
    for (const t of (proj.tools || [])) {
      if (t.tool === 'read' && t.cmd) {
        const a = toCanonicalAction({ tool: 'read', target: t.cmd });
        if (a) { a.label = `read ${t.cmd}  ${col.d(Math.round(t.confidence * 100) + '%')}`; out.push(a); }
      }
    }
  }
  return out;
}

// ── CLI ────────────────────────────────────────────────────────────────────

function collect(args, name) {
  const out = [];
  for (let i = 0; i < args.length; i++) if (args[i] === name && args[i + 1] !== undefined) out.push(args[i + 1]);
  return out;
}
function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }

function usage() {
  return [
    'occasio preflight simulate — predict allow/block for candidate actions before running',
    '',
    'usage: occasio preflight simulate [--read <path>]... [--grep <path>]... [--glob <path>]...',
    '                                  [--bash <cmd>]... [--ps <cmd>]... [--from <file>] [--mined] [--strict]',
    '',
    'Each action is evaluated through the active policy.yml. Blocks show the matched',
    'rule and how to unblock. --mined folds in this project\'s frequent read targets.',
    '--strict exits 1 if any action would be blocked (CI gate).',
    '',
  ].join('\n');
}

function runSimulateCli(args, opts = {}) {
  args = args || [];
  if (has(args, '--help') || has(args, '-h')) { process.stdout.write(usage()); return 0; }

  const actions = [];
  for (const p of collect(args, '--read')) actions.push(toCanonicalAction({ tool: 'read', target: p }));
  for (const p of collect(args, '--grep')) actions.push(toCanonicalAction({ tool: 'grep', target: p }));
  for (const p of collect(args, '--glob')) actions.push(toCanonicalAction({ tool: 'glob', target: p }));
  for (const c of collect(args, '--bash')) actions.push(toCanonicalAction({ tool: 'bash', target: c }));
  for (const c of collect(args, '--ps'))   actions.push(toCanonicalAction({ tool: 'ps',   target: c }));

  const fromFile = flag(args, '--from');
  if (fromFile) {
    try {
      for (const line of fs.readFileSync(fromFile, 'utf8').split('\n')) {
        const s = line.trim();
        if (!s) continue;
        const o = JSON.parse(s);
        const target = o.target || (o.input && (o.input.file_path || o.input.path || o.input.command));
        actions.push(toCanonicalAction({ tool: o.tool, target }));
      }
    } catch (e) {
      process.stderr.write(`[Occasio] preflight simulate: cannot read --from ${fromFile}: ${e.message}\n`);
      return 2;
    }
  }

  if (has(args, '--mined')) {
    const daysIdx = args.indexOf('--days');
    actions.push(...minedReadActions({ days: daysIdx >= 0 ? parseInt(args[daysIdx + 1], 10) || 30 : 30, cwd: opts.cwd, logsDir: opts.logsDir }));
  }

  const valid = actions.filter(Boolean);
  if (!valid.length) {
    process.stderr.write('[Occasio] preflight simulate: no actions. Pass --read/--grep/--glob/--bash/--ps/--from/--mined.\n');
    return 2;
  }

  const policyPath = loader.DEFAULT_PATH;
  let rawText = '';
  try { rawText = fs.readFileSync(policyPath, 'utf8'); } catch { /* defaults */ }
  const ctx = { rawText, parsed: loader.parse(rawText), policyPath };

  const { results, summary } = simulate(valid, ctx);

  process.stdout.write(col.b('\n⚡ Occasio — preflight simulate') + col.d(`  (active policy: ${policyPath})\n\n`));
  for (const r of results) {
    if (r.verdict === 'allow') {
      process.stdout.write(`  ${col.g('✓ allow')}  ${r.label}  ${col.d('(' + r.decision_action + ')')}\n`);
    } else {
      process.stdout.write(`  ${col.r('⛔ block')}  ${r.label}  ${col.d('· ' + r.reason)}\n`);
      if (r.rule) {
        const loc = r.rule.line != null ? `  ${col.d('(' + policyPath + ':' + r.rule.line + ')')}` : '';
        process.stdout.write(`      ${col.d('rule')} ${r.rule.rule_id}${r.rule.matched_value ? ' = ' + r.rule.matched_value : ''}${loc}\n`);
        for (const alt of (r.rule.alternatives || [])) process.stdout.write(`      ${col.c('→')} ${col.d(alt)}\n`);
      }
    }
  }
  const sumColor = summary.blocked ? col.y : col.g;
  process.stdout.write('\n  ' + sumColor(`${summary.allowed} allowed · ${summary.blocked} blocked`) + col.d(` of ${summary.total}\n\n`));

  if (has(args, '--strict') && summary.blocked > 0) return 1;
  return 0;
}

module.exports = { simulate, toCanonicalAction, minedReadActions, runSimulateCli };
