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
    'usage: occasio gate "<command>" [--file <policy.yml>] [--json] [--enforce]',
    '',
    '  --enforce   consume a granted token + audit (the PreToolUse hook uses this)',
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

  const json    = has(args, '--json');
  const enforce = has(args, '--enforce');
  const file = flag(args, '--file');

  // The command is every positional arg (anything not a flag or a flag value).
  const consumed = new Set();
  if (file) { consumed.add(args.indexOf('--file')); consumed.add(args.indexOf('--file') + 1); }
  const positional = args.filter((a, i) => !consumed.has(i) && a !== '--json' && a !== '--enforce' && a !== '--help' && a !== '-h');
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

  // --enforce: the PreToolUse hook path. Consume a granted one-time token and
  // audit the decision (enforcement_point:'hook'); emit the deny/approval message
  // on stderr so the hook relays it to the agent. Same exit codes as preview.
  if (enforce) return runEnforce(command, decision, code);

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

// Write one identity audit row for a hook decision (enforcement_point:'hook').
function recordHook(command, decision, result) {
  if (!decision.identity) return;
  const { createAuditor } = require('../audit/jsonl-auditor');
  const { makeBoundaryEvent } = require('../core/boundary-event');
  const auditor = createAuditor();
  const dec = { ...decision, identity: { ...decision.identity, enforcement_point: 'hook' } };
  const ev = makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call', agent: 'claude-code', protocol: 'hook',
    toolName: 'shell_bash', toolInput: { command },
  });
  const status = auditor.record(ev, dec, result);
  if (status && status.ok === false) {
    const { AuditWriteError } = require('../audit/errors');
    throw new AuditWriteError(status.error, status.droppedRow);
  }
}

/**
 * Enforcement path (the PreToolUse hook). Consumes a granted one-time token and
 * audits; emits the deny/approval message on stderr. Returns the same exit codes
 * as preview (0 allow / 2 deny / 3 approval-pending). The hook maps 2 and 3 to a
 * block.
 */
function runEnforce(command, decision, code) {
  if (decision.identityApprovalGranted) {
    const store = require('../policy/identity-store').getStore();
    const r = store.consume(decision.approval_id);
    if (!r || !r.ok) {
      // Race: the token was denied/expired since the read-only lookup. Fail closed.
      process.stderr.write('Occasio: approval token no longer valid — re-request approval.\n');
      return 3;
    }
    recordHook(command, decision, { passThrough: true, approval_id: decision.approval_id });
    return 0;
  }
  if (decision.action === 'BLOCK') {
    recordHook(command, decision, { blocked: true });
    const msg = (decision.syntheticResponse && decision.syntheticResponse.message) || `denied: ${decision.reason}`;
    process.stderr.write('Occasio: ' + msg + '\n');
    return code; // 2 deny / control-plane, 3 approval-pending
  }
  return 0; // plain allow — no audit
}

module.exports = { run, usage };
