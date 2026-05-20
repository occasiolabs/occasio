'use strict';

/**
 * eyes/demo-script.js — deterministic 15-second event loop for marketing GIFs
 * and zero-setup demos. No real claude run required.
 *
 * Each entry is { delayMs, row } where row is shaped exactly like a
 * pipeline-events.jsonl row. Beats are timed so the BLOCK lands at ~7s and the
 * savings counter ticks to ~$0.04 by ~14s.
 */

const RUN_ID = '0demo-a3f1c-b2d4-9e10-f00d-cafebabef00d';

function row(over) {
  return Object.assign({
    audit_schema: 1,
    ts: new Date().toISOString(),
    run_id: RUN_ID,
    agent: 'occasio',
    protocol: 'anthropic',
    direction: 'outbound',
    kind: 'tool_call',
    policy_source: 'user',
    executor: 'local',
  }, over);
}

const SCRIPT = [
  { delayMs: 400, row: row({
      kind: 'policy_loaded', tool_name: 'policy_loaded',
      tool_inputs: { policy_hash: '7c9a3e1f4b2d8a6c0e5d', policy_path: '~/.occasio/policy.yml', version: 1 },
      action: 'INFO', reason: 'policy-loaded',
    }) },
  { delayMs: 800, row: row({
      tool_name: 'Read', tool_inputs: { path: 'src/interceptor.js', bytes: 4218 },
      action: 'PASS', executor: 'local', tokens_saved: 1240,
    }) },
  { delayMs: 1100, row: row({
      tool_name: 'Glob', tool_inputs: { pattern: '**/*.test.js' },
      action: 'PASS', executor: 'local', tokens_saved: 320,
    }) },
  { delayMs: 1300, row: row({
      tool_name: 'Read', tool_inputs: { path: 'package.json', bytes: 412 },
      action: 'PASS', executor: 'local', tokens_saved: 180,
    }) },
  { delayMs: 1500, row: row({
      tool_name: 'Bash', tool_inputs: { command: 'git status' },
      action: 'PASS', executor: 'local', exit_code: 0,
    }) },
  { delayMs: 1400, row: row({
      tool_name: 'Grep', tool_inputs: { pattern: 'API_KEY=sk-' },
      action: 'TRANSFORM', executor: 'local', secrets_redacted: 2, tokens_saved: 220,
      transform: 'redact_secrets',
    }) },
  { delayMs: 1500, row: row({
      tool_name: 'Read', tool_inputs: { path: '/etc/passwd' },
      action: 'BLOCK', reason: 'deny_paths', executor: 'local',
    }) },
  { delayMs: 1200, row: row({
      tool_name: 'Read', tool_inputs: { path: 'src/eyes/render.js', bytes: 6850 },
      action: 'PASS', executor: 'local', tokens_saved: 1820,
    }) },
  { delayMs: 1300, row: row({
      tool_name: 'Edit', tool_inputs: { file_path: 'src/eyes/render.js' },
      action: 'PASS', executor: 'cloud', tokens_saved: 0,
    }) },
  { delayMs: 1100, row: row({
      tool_name: 'Bash', tool_inputs: { command: 'node test-eyes.js' },
      action: 'PASS', executor: 'local', exit_code: 0,
    }) },
  { delayMs: 1400, row: row({
      tool_name: 'Read', tool_inputs: { path: 'src/audit/jsonl-auditor.js', bytes: 9120 },
      action: 'PASS', executor: 'local', tokens_saved: 2310,
    }) },
];

module.exports = { SCRIPT, RUN_ID };
