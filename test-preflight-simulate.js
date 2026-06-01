#!/usr/bin/env node
'use strict';

/**
 * test-preflight-simulate.js — forward policy dry-run (Idea #6).
 *
 * Drives src/preflight/simulate.js against controlled policies via
 * loader._setOverrideForTests, with a matching ctx.rawText so blocked actions
 * resolve their rule + line (reuses #9's resolveBlockedRule). No network.
 */

const { simulate, toCanonicalAction, minedReadActions } = require('./src/preflight/simulate');
const loader = require('./src/policy/loader');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

// Set the active policy (engine.evaluate reads loader.load()) + return ctx.
function setPolicy(text) {
  loader._setOverrideForTests(loader.parse(text));
  return { rawText: text, parsed: loader.parse(text), policyPath: '/tmp/policy.yml' };
}
const A = (tool, target) => toCanonicalAction({ tool, target });

// ── 1. allowed action ────────────────────────────────────────────────────────
console.log('\n1. allowed action');
{
  const ctx = setPolicy('version: 1\n');
  const { results, summary } = simulate([A('read', '/tmp/notes.txt')], ctx);
  assert('read of unlisted path → allow', results[0].verdict === 'allow');
  assert('decision is LOCAL (not block)', results[0].decision_action === 'LOCAL');
  assert('no rule on allow', results[0].rule === null);
  assert('summary 1 allowed', summary.allowed === 1 && summary.blocked === 0);
}

// ── 2. deny_paths block + matched rule ───────────────────────────────────────
console.log('\n2. deny_paths block');
{
  const ctx = setPolicy('version: 1\ndeny_paths:\n  - ~/.ssh\n');
  const { results } = simulate([A('read', '~/.ssh/id_rsa')], ctx);
  const r = results[0];
  assert('verdict block', r.verdict === 'block');
  assert('reason path-denied', r.reason === 'path-denied');
  assert('rule_id deny_paths[0]', r.rule && r.rule.rule_id === 'deny_paths[0]');
  assert('matched_value ~/.ssh', r.rule.matched_value === '~/.ssh');
  assert('policy line located (line 3)', r.rule.line === 3, `got ${r.rule && r.rule.line}`);
  assert('alternatives present', r.rule.alternatives.length >= 1);
}

// ── 3. allow_paths block ─────────────────────────────────────────────────────
console.log('\n3. allow_paths block');
{
  const ctx = setPolicy('version: 1\nallow_paths:\n  - /work\n');
  const { results } = simulate([A('read', '/tmp/x')], ctx);
  assert('verdict block', results[0].verdict === 'block');
  assert('reason path-not-allowed', results[0].reason === 'path-not-allowed');
  assert('rule section allow_paths', results[0].rule && results[0].rule.section === 'allow_paths');
}

// ── 4. shell-mediated read block ─────────────────────────────────────────────
console.log('\n4. shell-mediated read block');
{
  // NB: shell-path enforcement resolves operands with path.resolve (no ~
  // expansion), unlike read_file — so use an absolute deny path here, matching
  // real engine behaviour.
  const ctx = setPolicy('version: 1\ndeny_paths:\n  - /etc/secret\n');
  const { results } = simulate([A('bash', 'cat /etc/secret/db.conf')], ctx);
  assert('bash cat of denied path → block', results[0].verdict === 'block' && results[0].reason === 'path-denied');
}

// ── 5. summary counts + canonicalization ─────────────────────────────────────
console.log('\n5. summary + canonicalization');
{
  assert('read alias → read_file', A('read', '/x').tool === 'read_file');
  assert('Read alias → read_file', A('Read', '/x').tool === 'read_file');
  assert('bash alias → shell_bash', A('bash', 'ls').tool === 'shell_bash');
  assert('grep alias → grep input.path', A('grep', '/dir').tool === 'grep' && A('grep', '/dir').input.path === '/dir');
  assert('unknown tool → null', A('frobnicate', 'x') === null);

  const ctx = setPolicy('version: 1\ndeny_paths:\n  - /etc/secret\n');
  const { summary } = simulate([A('read', '/tmp/ok'), A('read', '/etc/secret/db')], ctx);
  assert('mixed batch → 1 allowed, 1 blocked', summary.allowed === 1 && summary.blocked === 1 && summary.total === 2);
}

// ── 6. minedReadActions mapping ──────────────────────────────────────────────
console.log('\n6. minedReadActions');
{
  // core transform a mined read entry undergoes:
  const a = toCanonicalAction({ tool: 'read', target: '/repo/src/app.js' });
  assert('mined read → read_file action with file_path', a.tool === 'read_file' && a.input.file_path === '/repo/src/app.js');
  // real call returns an array without throwing (no logs in test env → empty)
  assert('minedReadActions returns an array', Array.isArray(minedReadActions({ days: 1 })));
}

loader._setOverrideForTests(null);
loader._resetCache();
console.log(`\n${failed === 0 ? '✓' : '✗'} preflight-simulate: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
