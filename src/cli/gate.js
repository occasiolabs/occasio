'use strict';

/**
 * occasio gate <command> [--file <policy.yml>] [--json]
 *
 * Preview the identity-gate decision for a single shell command, exactly as the
 * live proxy would decide it. This is the standalone entrypoint a CI step or a
 * future PreToolUse hook calls to decide whether an agent may run a command.
 *
 * Exit codes (stable — the hook depends on them):
 *   0  allow             — no identity rule fired
 *   2  deny              — a deny_commands / path rule fired (hard block)
 *   3  approval-pending  — an identity_approval rule fired (needs a human)
 *   1  usage / read error
 *
 * The command is classified for context, but the EXIT CODE reflects the active
 * policy's actual decision (engine.gateShellCommand), so preview and
 * enforcement never disagree.
 */

const path   = require('path');
const engine = require('../policy/engine');
const loader = require('../policy/loader');
const { classify } = require('../policy/identity-classifier');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }

function usage() {
  return [
    'occasio gate — preview the identity-gate decision for a shell command',
    '',
    'usage: occasio gate "<command>" [--file <policy.yml>] [--json]',
    '',
    'exit 0 allow · 2 deny · 3 approval-pending · 1 usage/error',
    '',
  ].join('\n');
}

/**
 * @param {string[]} args  args after 'gate'
 * @returns {number} exit code
 */
function run(args) {
  args = args || [];
  if (has(args, '--help') || has(args, '-h')) { process.stdout.write(usage()); return 0; }

  const json = has(args, '--json');
  const file = flag(args, '--file');

  // The command is every positional arg (anything not a flag or a flag value).
  const consumed = new Set();
  if (file) { consumed.add(args.indexOf('--file')); consumed.add(args.indexOf('--file') + 1); }
  const positional = args.filter((a, i) => !consumed.has(i) && a !== '--json' && a !== '--help' && a !== '-h');
  const command = positional.join(' ').trim();

  if (!command) {
    process.stderr.write('[Occasio] gate: no command given\n\n' + usage());
    return 1;
  }

  let policy;
  try {
    policy = file ? loader.load(path.resolve(file)) : loader.load();
  } catch (e) {
    process.stderr.write(`[Occasio] gate: cannot load policy: ${e.message}\n`);
    return 1;
  }

  const decision = engine.gateShellCommand(command, policy);
  const cls      = classify(command);

  // Map the decision to a stable verdict + exit code.
  let verdict, code;
  if (decision.action !== 'BLOCK') {
    verdict = 'allow'; code = 0;
  } else if (decision.reason === 'approval_required') {
    verdict = 'approval-pending'; code = 3;
  } else {
    verdict = 'deny'; code = 2;
  }

  if (json) {
    process.stdout.write(JSON.stringify({
      command,
      verdict,
      exit_code: code,
      reason: decision.reason,
      identity: cls ? {
        action:       cls.action,
        identity_type: cls.identity_type,
        target_class: cls.target_class,
        risk:         cls.risk,
      } : null,
    }, null, 2) + '\n');
    return code;
  }

  const label = verdict === 'allow' ? col.g('ALLOW')
              : verdict === 'deny'  ? col.r('DENY')
              :                       col.y('APPROVAL REQUIRED');

  process.stdout.write(col.b('\n⚡ Occasio — Gate\n\n'));
  process.stdout.write(`  Command:  ${command}\n`);
  process.stdout.write(`  Decision: ${label} ${col.d(`(exit ${code})`)}\n`);
  process.stdout.write(`  Reason:   ${decision.reason}\n`);
  if (cls) {
    process.stdout.write(`  Identity: ${cls.identity_type} ${col.d(`(${cls.target_class}, risk ${cls.risk})`)}\n`);
  }
  if (verdict === 'approval-pending') {
    process.stdout.write('\n' + col.d('  An AI agent may request this identity, not assume it. A human must approve.\n'));
  } else if (verdict === 'deny') {
    process.stdout.write('\n' + col.d('  Blocked by policy — the command will not run and its output never reaches the agent.\n'));
  }
  process.stdout.write('\n');
  return code;
}

module.exports = { run, usage };
