'use strict';

/**
 * occasio approvals list|show|approve|deny
 *
 * The human side of the identity handshake — run from YOUR terminal (which is
 * not proxied), never reachable by the agent (the engine's control-plane guard
 * hard-BLOCKs an agent that tries to call this). `approve` mints a single-use,
 * short-TTL, HMAC-signed token bound to the exact command; `deny` rejects a
 * pending request. Both write a lifecycle row into the tamper-evident chain.
 *
 *   occasio approvals list [--state pending]
 *   occasio approvals show <id>
 *   occasio approvals approve <id> [--once] [--ttl <seconds>]
 *   occasio approvals deny <id>
 */

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};
function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }
function clip(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

function usage() {
  return [
    'occasio approvals — authorize a blocked identity borrow (run from your terminal)',
    '',
    'usage:',
    '  occasio approvals list [--state pending|approved|consumed|denied|expired]',
    '  occasio approvals show <id>',
    '  occasio approvals approve <id> [--once] [--ttl <seconds>]',
    '  occasio approvals deny <id>',
    '',
  ].join('\n');
}

// One auditor per invocation, default chain. Lifecycle rows are written here.
function makeAuditor() {
  const { createAuditor } = require('../audit/jsonl-auditor');
  return createAuditor();
}

// Record an approval lifecycle event into the tamper-evident chain.
function recordLifecycle(auditor, rec, identity) {
  const { makeBoundaryEvent } = require('../core/boundary-event');
  const ev = makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call', agent: 'human-cli', protocol: 'cli',
    runId: rec.id, toolName: 'shell_bash', toolInput: { command: rec.normalized_command || '' },
  });
  const decision = { action: 'INFO', reason: identity.event_type, policySource: 'user', identity };
  const status = auditor.record(ev, decision, {});
  if (status && status.ok === false) {
    const { AuditWriteError } = require('../audit/errors');
    throw new AuditWriteError(status.error, status.droppedRow);
  }
}

function run(args) {
  args = args || [];
  if (has(args, '--help') || has(args, '-h')) { process.stdout.write(usage()); return 0; }
  const store = require('../policy/identity-store').getStore();
  const sub = args[0];

  // sweep stale records first so list/show reflect reality; audit each approved-
  // but-unused token that just expired (the tuning signal: was the TTL too short?).
  try {
    const { expired } = store.sweep();
    const unused = (expired || []).filter(r => r._kind === 'approved_unused');
    if (unused.length) {
      const auditor = makeAuditor();
      for (const r of unused) {
        recordLifecycle(auditor, r, {
          event_type: 'identity_borrow_expired', identity_type: r.identity_type, target_class: r.target_class,
          risk: r.risk, matched_rule: r.identity_type, classification: 'identity_borrow', classify_reason: 'ttl_expired',
          approval_id: r.id, approval_state: 'expired', approved_by: r.approved_by, identity_source: r.identity_source,
          enforcement_point: 'cli', coverage: 'n/a', severity: 'low',
        });
      }
    }
  } catch { /* best effort */ }

  if (!sub || sub === 'list') {
    const state = flag(args, '--state');
    const rows = store.list(state ? { state } : {});
    process.stdout.write(col.b('\n⚡ Occasio — Approvals\n\n'));
    if (rows.length === 0) { process.stdout.write(col.d('  (none)\n\n')); return 0; }
    const now = Math.floor(Date.now() / 1000);
    for (const r of rows) {
      const st = r.state === 'pending' ? col.y(r.state) : r.state === 'approved' ? col.g(r.state) : col.d(r.state);
      const exp = r.state === 'approved' && r.expires_at ? col.d(`  expires in ${Math.max(0, r.expires_at - now)}s`) : '';
      process.stdout.write(`  ${col.c(r.id)}  ${st.padEnd(18)} ${col.d((r.identity_type || '?') + '/' + (r.target_class || '?'))}  ${clip(r.normalized_command, 44)}${exp}\n`);
    }
    process.stdout.write('\n' + col.d('  approve: occasio approvals approve <id> --once\n\n'));
    return 0;
  }

  if (sub === 'show') {
    const id = args[1];
    const rec = id && store.get(id);
    if (!rec) { process.stderr.write(`[Occasio] approvals show: no such id "${id}"\n`); return 1; }
    process.stdout.write(col.b('\n⚡ Occasio — Approval\n\n') + JSON.stringify(rec, null, 2) + '\n\n');
    return 0;
  }

  if (sub === 'approve' || sub === 'deny') {
    const id = args[1];
    const rec = id && store.get(id);
    if (!rec) { process.stderr.write(`[Occasio] approvals ${sub}: no such id "${id}"\n`); return 1; }

    if (sub === 'deny') {
      store.deny(id, { decided_by: 'human' });
      recordLifecycle(makeAuditor(), { ...rec, state: 'denied' }, {
        event_type: 'identity_borrow_denied', identity_type: rec.identity_type, target_class: rec.target_class,
        risk: rec.risk, matched_rule: rec.identity_type, classification: 'identity_borrow', classify_reason: 'human_deny',
        approval_id: rec.id, approval_state: 'denied', decided_by: 'human',
        enforcement_point: 'cli', coverage: 'n/a', severity: 'high',
      });
      process.stdout.write(col.b('\n⚡ Occasio — Approvals\n\n') + `  ${col.r('✗')} denied ${col.c(id)}\n\n`);
      return 0;
    }

    // approve
    const ttlArg = flag(args, '--ttl');
    const ttl_seconds = ttlArg !== undefined ? parseInt(ttlArg, 10) : store.DEFAULT_TTL;
    const { currentIdentity } = require('./identity');
    const who = currentIdentity();
    const res = store.approve(id, { ttl_seconds, max_uses: store.DEFAULT_MAX_USES, approved_by: who.id, identity_source: who.source });
    if (!res.ok) { process.stderr.write(`[Occasio] approvals approve: ${res.error}\n`); return 1; }
    const r = res.record;
    recordLifecycle(makeAuditor(), r, {
      event_type: 'identity_borrow_approved', identity_type: r.identity_type, target_class: r.target_class,
      risk: r.risk, matched_rule: r.identity_type, classification: 'identity_borrow', classify_reason: 'human_approve',
      approval_id: r.id, approval_state: 'approved', approved_by: r.approved_by, identity_source: r.identity_source,
      decided_by: 'human', enforcement_point: 'cli', coverage: 'n/a', severity: 'high',
    });
    process.stdout.write(col.b('\n⚡ Occasio — Approvals\n\n'));
    process.stdout.write(`  ${col.g('✓')} approved ${col.c(id)} — once, ${r.ttl_seconds}s, by ${col.c(r.approved_by)}\n`);
    if (who.source === 'os_fallback') {
      process.stdout.write('\n' + col.y('  ⚠ approved_by is your OS user (os_fallback). For attributable approvals:\n    occasio identity set --id <name>\n'));
    }
    process.stdout.write('\n');
    return 0;
  }

  process.stderr.write(`[Occasio] approvals: unknown subcommand "${sub}"\n\n` + usage());
  return 1;
}

module.exports = { run, usage };
