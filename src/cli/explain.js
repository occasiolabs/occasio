'use strict';

/**
 * occasio explain <event_id|prefix>
 *
 * Locate a single chain event by id (full or prefix match) and render a
 * readable explanation of what it records and, for BLOCK/TRANSFORM actions,
 * which policy rule produced the decision. This bridges the gap from
 * "I see a row in the chain" to "I understand why".
 *
 * Read-only. Uses src/models/events.js facade. No chain writes.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { loadEvents } = require('../models/events');
const loader = require('../policy/loader');
const { resolveBlockedRule } = require('../policy/explain-rule');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function findEvent(query) {
  const all = loadEvents({});
  // Exact match first, then unique prefix match.
  const exact = all.find(e => e.event_id === query);
  if (exact) return { event: exact, all, ambiguous: false };
  const prefix = all.filter(e => typeof e.event_id === 'string' && e.event_id.startsWith(query));
  if (prefix.length === 1) return { event: prefix[0], all, ambiguous: false };
  if (prefix.length > 1) return { event: null, all, ambiguous: true, candidates: prefix };
  return { event: null, all, ambiguous: false };
}

function fmtPolicySource(src) {
  if (!src) return col.d('(unknown)');
  if (src === 'user')     return col.c('user policy.yml');
  if (src === 'default')  return col.d('built-in default');
  if (src === 'inferred') return col.y('inferred (no policy_loaded in run)');
  return src;
}

function actionColor(action) {
  if (action === 'BLOCK')     return col.r;
  if (action === 'TRANSFORM') return col.c;
  if (action === 'LOCAL')     return col.g;
  if (action === 'PASS')      return col.d;
  return col.d;
}

function explainToolCall(e, all) {
  const lines = [];
  const colour = actionColor(e.action);
  lines.push(col.b('\n⚡ Occasio explain'));
  lines.push('');
  lines.push(`  ${col.d('event_id   ')} ${e.event_id}`);
  lines.push(`  ${col.d('ts         ')} ${e.ts || '(none)'}`);
  lines.push(`  ${col.d('run_id     ')} ${e.run_id || '(none)'}`);
  lines.push(`  ${col.d('kind       ')} ${e.kind}`);
  lines.push(`  ${col.d('tool       ')} ${e.tool_name || '(none)'}`);
  lines.push(`  ${col.d('action     ')} ${colour(e.action || '(none)')}`);
  if (e.reason)        lines.push(`  ${col.d('reason     ')} ${e.reason}`);
  if (e.policy_source) lines.push(`  ${col.d('policy     ')} ${fmtPolicySource(e.policy_source)}`);
  if (e.executor)      lines.push(`  ${col.d('executor   ')} ${e.executor}`);
  if (e.transform)     lines.push(`  ${col.d('transform  ')} ${e.transform}`);
  if (e.result_kind)   lines.push(`  ${col.d('result     ')} ${e.result_kind}`);
  if (e.secrets_redacted) lines.push(`  ${col.d('redacted   ')} ${e.secrets_redacted} secret(s)`);

  if (e.tool_inputs && typeof e.tool_inputs === 'object') {
    lines.push('');
    lines.push(col.b('  Inputs (normalised)'));
    for (const k of Object.keys(e.tool_inputs)) {
      const v = e.tool_inputs[k];
      const s = typeof v === 'string' ? v : JSON.stringify(v);
      lines.push(`    ${col.d(k)}  ${s.length > 120 ? s.slice(0, 117) + '...' : s}`);
    }
  }

  // Active policy at the moment of this event: the most recent
  // policy_loaded event in the run that precedes this one.
  let policySnapshot = null;
  if (e.run_id) {
    const policyEvents = all.filter(p =>
      p.kind === 'policy_loaded' &&
      p.run_id === e.run_id &&
      (!p.ts || !e.ts || p.ts <= e.ts));
    policySnapshot = policyEvents[policyEvents.length - 1] || null;
  }
  if (policySnapshot) {
    lines.push('');
    lines.push(col.b('  Active policy at decision time'));
    const ti = policySnapshot.tool_inputs || {};
    if (ti.policy_path) lines.push(`    ${col.d('path       ')} ${ti.policy_path}`);
    if (ti.policy_hash) lines.push(`    ${col.d('hash       ')} ${ti.policy_hash}`);
    if (ti.version != null) lines.push(`    ${col.d('version    ')} ${ti.version}`);
  } else if (e.run_id) {
    lines.push('');
    lines.push(col.d('  (no policy_loaded event found in this run; ' +
      'decision was made under whatever policy was active in-process)'));
  }

  // Matched policy rule + how to unblock. Re-derive the concrete rule from the
  // event's inputs against the policy file (the audit row stores only the
  // reason code). Read-only; best-effort against the CURRENT policy.yml.
  {
    const polPath = (policySnapshot && policySnapshot.tool_inputs && policySnapshot.tool_inputs.policy_path)
      || loader.DEFAULT_PATH;
    let ctx = null;
    try {
      const rawText = fs.readFileSync(polPath, 'utf8');
      ctx = {
        rawText,
        parsed:      loader.parse(rawText),
        policyPath:  polPath,
        currentHash: loader.computePolicyHash(polPath),
        eventHash:   policySnapshot && policySnapshot.tool_inputs ? policySnapshot.tool_inputs.policy_hash : null,
      };
    } catch {
      // policy file unreadable → derive from inputs only (no line/parse)
      ctx = { rawText: '', parsed: {}, policyPath: polPath, currentHash: null,
              eventHash: policySnapshot && policySnapshot.tool_inputs ? policySnapshot.tool_inputs.policy_hash : null };
    }

    const rule = resolveBlockedRule(e, ctx);
    if (rule) {
      lines.push('');
      lines.push(col.b('  Matched policy rule'));
      lines.push(`    ${col.d('section    ')} ${rule.section}`);
      lines.push(`    ${col.d('rule       ')} ${rule.rule_id}`);
      if (rule.matched_value != null) lines.push(`    ${col.d('matched    ')} ${rule.matched_value}`);
      lines.push(`    ${col.d('location   ')} ${rule.line != null ? `${ctx.policyPath}:${rule.line}` : col.d('(line not located in current policy.yml)')}`);
      if (rule.provenance === 'policy-changed') {
        lines.push(`    ${col.y('⚠ policy.yml changed since this decision (current hash ≠ policy_loaded hash) — rule derived from the current file, best-effort')}`);
      }
      if (Array.isArray(rule.alternatives) && rule.alternatives.length) {
        lines.push('');
        lines.push(col.b('  Suggested next actions'));
        for (const a of rule.alternatives) lines.push(`    ${col.g('→')} ${a}`);
      }
    }
  }

  // Verify and chain pointer
  lines.push('');
  lines.push(col.b('  Chain context'));
  lines.push(`    ${col.d('prev_hash  ')} ${e.prev_hash || '(none)'}`);
  lines.push(`    ${col.d('hash       ')} ${e.hash || '(none)'}`);
  lines.push('');
  lines.push(col.d('  To verify this row independently:'));
  lines.push(col.d('    occasio audit verify'));
  lines.push(col.d('  or with the Python walker:'));
  lines.push(col.d('    python docs/audit_walker.py'));
  lines.push('');

  return lines.join('\n');
}

function usage() {
  return [
    'occasio explain — show what a single chain event records and why',
    '',
    'usage: occasio explain <event_id|prefix>',
    '',
    'arguments:',
    '  <event_id|prefix>  the event_id from a pipeline-events.jsonl row,',
    '                     or a unique hex prefix',
    '',
    'example:',
    '  occasio explain 040a934c',
    '',
  ].join('\n');
}

function run(args) {
  if (!args || !args[0] || args[0] === '--help' || args[0] === '-h') {
    process.stdout.write(usage());
    return args && (args[0] === '--help' || args[0] === '-h') ? 0 : 2;
  }
  const query = args[0];
  const r = findEvent(query);
  if (r.ambiguous) {
    process.stderr.write(`Ambiguous prefix "${query}". Candidates:\n`);
    for (const c of r.candidates) process.stderr.write(`  ${c.event_id}  (${c.kind}/${c.action || '-'})\n`);
    return 2;
  }
  if (!r.event) {
    process.stderr.write(`No event with id or prefix "${query}" in the chain.\n`);
    return 1;
  }
  process.stdout.write(explainToolCall(r.event, r.all));
  return 0;
}

module.exports = { run, findEvent, explainToolCall, usage };
