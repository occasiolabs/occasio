'use strict';
/**
 * test-smoke.js — Live integration smoke test for the LocalFirst interceptor.
 *
 * Exercises interceptToolUse end-to-end for git read-only commands using a
 * partial-batch SSE fixture.  No Anthropic dependency — the git block runs
 * locally and the early-return partialIntercept path fires before any follow-up
 * call would be needed.
 *
 * Usage:
 *   node test-smoke.js
 *   npm run smoke
 *
 * Run after any change to interceptor.js (especially routing changes) to confirm
 * git commands still intercept.  Complements the unit tests in test-interceptor.js
 * by exercising the full interceptToolUse execution path, not just routing helpers.
 */

const path = require('path');
const adapter = require('./src/adapters/claude-code');

// Test-local convenience over the canonical adapter.runToolLoop. Keeps existing
// test call sites readable without re-introducing a public shim in production.
const interceptToolUse = (sseBody, reqBody, reqHeaders, opts = {}) =>
  adapter.runToolLoop({
    initialSse: sseBody,
    reqBody,
    reqHeaders,
    ...opts,
  });

// ── helpers ────────────────────────────────────────────────────────────────────

let passed = 0, failed = 0;

function assert(label, condition) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${label}`);
    failed++;
  }
}

function buildSSE(blocks) {
  const lines = [
    'data: {"type":"message_start","message":{"id":"msg_smoke","usage":{"input_tokens":200,"output_tokens":10}}}',
  ];
  blocks.forEach((b, i) => {
    lines.push(`data: {"type":"content_block_start","index":${i},"content_block":{"type":"tool_use","id":"${b.id}","name":"${b.name}","input":{}}}`);
    lines.push(`data: {"type":"content_block_delta","index":${i},"delta":{"type":"input_json_delta","partial_json":${JSON.stringify(JSON.stringify(b.input))}}}`);
    lines.push(`data: {"type":"content_block_stop","index":${i}}`);
  });
  lines.push('data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}');
  lines.push('data: {"type":"message_stop"}');
  return Buffer.from(lines.join('\n'));
}

const minReqBody = { model: 'claude-sonnet-4-6', messages: [{ role: 'user', content: 'Check git.' }] };
const emptyHeaders = {};
const opts = { verbose: false, mode: 'intercept', todoStore: [] };

// Project root is the localfirst git repo (this directory).
// It is a real git repo used for live execution assertions.
const PROJECT_ROOT = __dirname;

// ── smoke tests ────────────────────────────────────────────────────────────────

async function run() {
  console.log('LocalFirst interceptor smoke test\n');

  // ── 1. git status — plain form ────────────────────────────────────────────
  console.log('1. [Edit, Bash(git -C <root> status)] — plain form');
  {
    const sse = buildSSE([
      { id: 'edit_01', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_01', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} status` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',      r.partialIntercept === true);
    assert('intercepted=false',          r.intercepted      === false);
    assert('toolsRun length=1',          r.toolsRun.length  === 1);
    assert('toolsRun[0].tool=Bash',      r.toolsRun[0].tool === 'Bash');
    assert('toolsRun[0].native=true',    r.toolsRun[0].native === true);
    assert('toolsRun[0].exitCode=0',     r.toolsRun[0].exitCode === 0);
    assert('partialResults length=1',    r.partialResults.length === 1);
    assert('partialResults[0] non-empty',
      typeof r.partialResults[0].content === 'string' && r.partialResults[0].content.length > 0);
    assert('output contains branch info',
      r.partialResults[0].content.toLowerCase().includes('branch') ||
      r.partialResults[0].content.toLowerCase().includes('on branch') ||
      r.partialResults[0].content.toLowerCase().includes('detached'));
  }

  // ── 2. git status — trailing 2>&1 form (real-world Claude Code shape) ─────
  console.log('\n2. [Edit, Bash(git -C <root> status 2>&1)] — 2>&1 form');
  {
    const sse = buildSSE([
      { id: 'edit_02', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_02', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} status 2>&1` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',   r.partialIntercept === true);
    assert('toolsRun[0].native=true', r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',  r.toolsRun[0]?.exitCode === 0);
    assert('output non-empty',
      typeof r.partialResults[0]?.content === 'string' && r.partialResults[0].content.length > 0);
  }

  // ── 3. git log --oneline -10 ──────────────────────────────────────────────
  console.log('\n3. [Edit, Bash(git -C <root> log --oneline -10)] — log form');
  {
    const sse = buildSSE([
      { id: 'edit_03', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_03', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} log --oneline -10` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',   r.partialIntercept === true);
    assert('toolsRun[0].native=true', r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',  r.toolsRun[0]?.exitCode === 0);
    assert('output has commit lines',
      typeof r.partialResults[0]?.content === 'string' &&
      /^[0-9a-f]{7}/m.test(r.partialResults[0].content));
  }

  // ── 4. git log --oneline -10 2>&1 — combined real-world shape ────────────
  console.log('\n4. [Edit, Bash(git -C <root> log --oneline -10 2>&1)] — log + 2>&1');
  {
    const sse = buildSSE([
      { id: 'edit_04', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_04', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} log --oneline -10 2>&1` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',   r.partialIntercept === true);
    assert('toolsRun[0].native=true', r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',  r.toolsRun[0]?.exitCode === 0);
    assert('output has commit lines',
      /^[0-9a-f]{7}/m.test(r.partialResults[0]?.content || ''));
  }

  // ── 5. PowerShell git status 2>&1 ────────────────────────────────────────
  console.log('\n5. [Edit, PowerShell(git -C <root> status 2>&1)] — PS form');
  {
    const sse = buildSSE([
      { id: 'edit_05', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'ps_01', name: 'PowerShell',
        input: { command: `git -C ${PROJECT_ROOT} status 2>&1` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',      r.partialIntercept === true);
    assert('toolsRun[0].tool=PowerShell', r.toolsRun[0]?.tool === 'PowerShell');
    assert('toolsRun[0].native=true',    r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',     r.toolsRun[0]?.exitCode === 0);
    assert('output non-empty',
      typeof r.partialResults[0]?.content === 'string' && r.partialResults[0].content.length > 0);
  }

  // ── 6. Safety: write-capable form must NOT intercept ─────────────────────
  console.log('\n6. [Edit, Bash(git -C <root> push)] — write-capable must fall through');
  {
    const sse = buildSSE([
      { id: 'edit_06', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_05', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} push` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('intercepted=false',        r.intercepted      === false);
    assert('partialIntercept=false',   !r.partialIntercept);
    assert('toolsRun is empty',        (r.toolsRun?.length ?? 0) === 0);
  }

  // ── 7. Compound Bash &&-chain ────────────────────────────────────────────
  console.log('\n7. [Edit, Bash(git -C <root> status && echo --- && git -C <root> log --oneline -3)]');
  {
    const sse = buildSSE([
      { id: 'edit_07', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_06', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} status && echo "---" && git -C ${PROJECT_ROOT} log --oneline -3` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',      r.partialIntercept === true);
    assert('toolsRun[0].native=true',    r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',     r.toolsRun[0]?.exitCode === 0);
    assert('output contains branch info',
      r.partialResults[0]?.content?.toLowerCase().includes('branch') ||
      r.partialResults[0]?.content?.toLowerCase().includes('detached'));
    assert('output contains echo separator',
      (r.partialResults[0]?.content || '').includes('---'));
    assert('output contains commit hash',
      /[0-9a-f]{7}/i.test(r.partialResults[0]?.content || ''));
  }

  // ── 8. Compound PowerShell ;-chain ───────────────────────────────────────
  console.log('\n8. [Edit, PowerShell(git -C <root> status; echo ---; git -C <root> log --oneline -3)]');
  {
    const sse = buildSSE([
      { id: 'edit_08', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'ps_02', name: 'PowerShell',
        input: { command: `git -C ${PROJECT_ROOT} status; echo "---"; git -C ${PROJECT_ROOT} log --oneline -3` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',        r.partialIntercept === true);
    assert('toolsRun[0].tool=PowerShell',  r.toolsRun[0]?.tool === 'PowerShell');
    assert('toolsRun[0].native=true',      r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',       r.toolsRun[0]?.exitCode === 0);
    assert('output non-empty',
      typeof r.partialResults[0]?.content === 'string' && r.partialResults[0].content.length > 0);
    assert('output contains echo separator',
      (r.partialResults[0]?.content || '').includes('---'));
  }

  // ── 9. Compound &&-chain with write-capable must NOT intercept ────────────
  console.log('\n9. [Edit, Bash(git status && git push)] — write-capable must fall through');
  {
    const sse = buildSSE([
      { id: 'edit_09', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_07', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} status && git push` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('intercepted=false',        r.intercepted      === false);
    assert('partialIntercept=false',   !r.partialIntercept);
    assert('toolsRun is empty',        (r.toolsRun?.length ?? 0) === 0);
  }

  // ── 10. Bash cd-prefix chain (real-world D-3 shape) ─────────────────────
  console.log(`\n10. [Edit, Bash(cd "${PROJECT_ROOT}" && git status)] — cd-prefix chain`);
  {
    const sse = buildSSE([
      { id: 'edit_10', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_08', name: 'Bash',
        input: { command: `cd "${PROJECT_ROOT}" && git status` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',      r.partialIntercept === true);
    assert('toolsRun[0].tool=Bash',      r.toolsRun[0]?.tool === 'Bash');
    assert('toolsRun[0].native=true',    r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',     r.toolsRun[0]?.exitCode === 0);
    assert('output contains branch info',
      r.partialResults[0]?.content?.toLowerCase().includes('branch') ||
      r.partialResults[0]?.content?.toLowerCase().includes('detached'));
  }

  // ── 11. PowerShell Set-Location ;-chain (real-world D-3 shape) ───────────
  console.log(`\n11. [Edit, PowerShell(Set-Location "${PROJECT_ROOT}"; git status; Write-Host "---"; git log --oneline -3)]`);
  {
    const sse = buildSSE([
      { id: 'edit_11', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'ps_03', name: 'PowerShell',
        input: { command: `Set-Location "${PROJECT_ROOT}"; git status; Write-Host "---"; git log --oneline -3` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',        r.partialIntercept === true);
    assert('toolsRun[0].tool=PowerShell',  r.toolsRun[0]?.tool === 'PowerShell');
    assert('toolsRun[0].native=true',      r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',       r.toolsRun[0]?.exitCode === 0);
    assert('output contains branch info',
      r.partialResults[0]?.content?.toLowerCase().includes('branch') ||
      r.partialResults[0]?.content?.toLowerCase().includes('detached'));
    assert('output contains Write-Host separator',
      (r.partialResults[0]?.content || '').includes('---'));
    assert('output contains commit lines',
      /[0-9a-f]{7}/i.test(r.partialResults[0]?.content || ''));
  }

  // ── 12. Bare git status (D-4) ────────────────────────────────────────────
  console.log('\n12. [Edit, Bash(git status)] — bare status in cwd');
  {
    const sse = buildSSE([
      { id: 'edit_12', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_09', name: 'Bash',
        input: { command: 'git status' } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',   r.partialIntercept === true);
    assert('toolsRun[0].tool=Bash',   r.toolsRun[0]?.tool === 'Bash');
    assert('toolsRun[0].native=true', r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',  r.toolsRun[0]?.exitCode === 0);
    assert('output contains branch info',
      r.partialResults[0]?.content?.toLowerCase().includes('branch') ||
      r.partialResults[0]?.content?.toLowerCase().includes('detached'));
  }

  // ── 13. Bare git log --oneline -5 (D-4) ──────────────────────────────────
  console.log('\n13. [Edit, Bash(git log --oneline -5)] — bare log in cwd');
  {
    const sse = buildSSE([
      { id: 'edit_13', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_10', name: 'Bash',
        input: { command: 'git log --oneline -5' } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, opts);

    assert('partialIntercept=true',   r.partialIntercept === true);
    assert('toolsRun[0].native=true', r.toolsRun[0]?.native === true);
    assert('toolsRun[0].exitCode=0',  r.toolsRun[0]?.exitCode === 0);
    assert('output has commit lines',
      /^[0-9a-f]{7}/m.test(r.partialResults[0]?.content || ''));
  }

  // ── 14. Pipeline auditor: production path emits audit rows ───────────────
  console.log('\n14. [Read tool with auditor] — pipeline emits one audit row per tool call');
  {
    const fs = require('fs');
    const os = require('os');
    const auditPath = path.join(os.tmpdir(), `localfirst-smoke-audit-${Date.now()}.jsonl`);
    const { createAuditor } = require('./src/audit/jsonl-auditor');
    const auditor = createAuditor(auditPath);

    const projectFile = path.join(PROJECT_ROOT, 'package.json');
    const sse = buildSSE([
      { id: 'edit_14', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'read_01', name: 'Read',
        input: { file_path: projectFile } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
      ...opts,
      auditor,
      sessionId: 's-smoke-14',
      runId:     'r-smoke-14',
    });

    assert('partial intercept ran Read',  r.toolsRun?.[0]?.tool === 'Read');
    assert('audit file exists',           fs.existsSync(auditPath));

    const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
    assert('exactly one audit row written',     lines.length === 1);
    const row = JSON.parse(lines[0]);
    assert('audit row agent claude-code',       row.agent === 'claude-code');
    assert('audit row protocol anthropic-http', row.protocol === 'anthropic-http');
    assert('audit row tool_name read_file (canonical)',
      row.tool_name === 'read_file');
    assert('audit row action LOCAL',            row.action === 'LOCAL');
    assert('audit row session_id propagated',   row.session_id === 's-smoke-14');
    assert('audit row run_id propagated',       row.run_id === 'r-smoke-14');
    assert('audit row result_kind local',       row.result_kind === 'local');
    assert('audit row exit_code 0',             row.exit_code === 0);

    fs.unlinkSync(auditPath);
  }

  // ── 15. Pipeline auditor — Bash dispatch records a LOCAL audit row ───────
  console.log('\n15. [Bash(git -C <root> status) with auditor] — Bash now flows through dispatcher');
  {
    const fs = require('fs');
    const os = require('os');
    const auditPath = path.join(os.tmpdir(), `localfirst-smoke-bash-audit-${Date.now()}.jsonl`);
    const { createAuditor } = require('./src/audit/jsonl-auditor');
    const auditor = createAuditor(auditPath);

    const sse = buildSSE([
      { id: 'edit_15', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'bash_15', name: 'Bash',
        input: { command: `git -C ${PROJECT_ROOT} status` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
      ...opts,
      auditor,
      sessionId: 's-smoke-15',
      runId:     'r-smoke-15',
    });

    assert('partial intercept ran Bash',          r.toolsRun?.[0]?.tool === 'Bash');
    assert('Bash result via pipeline native=true', r.toolsRun?.[0]?.native === true);
    assert('Bash result exitCode=0',               r.toolsRun?.[0]?.exitCode === 0);

    const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
    assert('Bash dispatch wrote one audit row', lines.length === 1);
    const row = JSON.parse(lines[0]);
    assert('Bash audit row tool_name shell_bash (canonical)',
      row.tool_name === 'shell_bash');
    assert('Bash audit row action LOCAL',       row.action === 'LOCAL');
    assert('Bash audit row result_kind local',  row.result_kind === 'local');
    assert('Bash audit row session propagated', row.session_id === 's-smoke-15');
    fs.unlinkSync(auditPath);
  }

  // ── 16. Pipeline auditor — PowerShell dispatch records a LOCAL audit row ──
  console.log('\n16. [PowerShell(git -C <root> status) with auditor] — PS now flows through dispatcher');
  {
    const fs = require('fs');
    const os = require('os');
    const auditPath = path.join(os.tmpdir(), `localfirst-smoke-ps-audit-${Date.now()}.jsonl`);
    const { createAuditor } = require('./src/audit/jsonl-auditor');
    const auditor = createAuditor(auditPath);

    const sse = buildSSE([
      { id: 'edit_16', name: 'Edit',
        input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
      { id: 'ps_16', name: 'PowerShell',
        input: { command: `git -C ${PROJECT_ROOT} status` } },
    ]);
    const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
      ...opts,
      auditor,
      sessionId: 's-smoke-16',
      runId:     'r-smoke-16',
    });

    assert('partial intercept ran PowerShell',          r.toolsRun?.[0]?.tool === 'PowerShell');
    assert('PowerShell result via pipeline native=true', r.toolsRun?.[0]?.native === true);
    assert('PowerShell result exitCode=0',               r.toolsRun?.[0]?.exitCode === 0);

    const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
    assert('PowerShell dispatch wrote one audit row',    lines.length === 1);
    const row = JSON.parse(lines[0]);
    assert('PowerShell audit row tool_name shell_powershell (canonical)',
      row.tool_name === 'shell_powershell');
    assert('PowerShell audit row action LOCAL',          row.action === 'LOCAL');
    assert('PowerShell audit row result_kind local',     row.result_kind === 'local');
    fs.unlinkSync(auditPath);
  }

  // ── 17. deny_paths via shell read — end-to-end BLOCK + no bytes leak ──────
  // Regression smoke for the closed bypass: `Bash { cat <denied-file> }` must
  // be denied by deny_paths the same way `Read { file_path: <denied-file> }`
  // is. Exercise the full pipeline (engine → dispatcher → audit) and assert
  // the audit row shape AND that the agent never receives the file bytes.
  console.log('\n17. [Edit, Bash(cat <denied-file>)] — deny_paths blocks shell-mediated read');
  {
    const fs   = require('fs');
    const os   = require('os');
    const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-smoke-deny-'));
    const denyDir  = path.join(tmp, 'denied');
    fs.mkdirSync(denyDir);
    const denyFile = path.join(denyDir, 'secret.txt');
    const SECRET   = 'TOP-SECRET-MARKER-' + Date.now();
    fs.writeFileSync(denyFile, SECRET + '\n');

    const loader = require('./src/policy/loader');
    loader._setOverrideForTests({ deny_paths: [denyDir] });

    try {
      const auditPath = path.join(os.tmpdir(), `localfirst-smoke-deny-${Date.now()}.jsonl`);
      const { createAuditor } = require('./src/audit/jsonl-auditor');
      const auditor = createAuditor(auditPath);

      const sse = buildSSE([
        { id: 'edit_17', name: 'Edit',
          input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
        { id: 'bash_17', name: 'Bash',
          input: { command: `cat ${denyFile}` } },
      ]);
      const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
        ...opts, auditor,
        sessionId: 's-smoke-17', runId: 'r-smoke-17',
      });

      // Governance contract for shell-mediated denied reads: the file bytes
      // must never appear in any synthetic tool_result returned to the model,
      // and a BLOCK row must be written to the audit chain. The exact shape
      // of toolsRun for BLOCK is an internal detail and not asserted here.
      assert('partial result content does not leak secret',
        !(r.partialResults || []).some(p => typeof p.content === 'string' && p.content.includes(SECRET)));
      assert('no toolsRun entry leaks secret content',
        !(r.toolsRun || []).some(t => typeof t.output === 'string' && t.output.includes(SECRET)));

      const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
      const blockRow = lines.find(l => l.action === 'BLOCK');
      assert('audit row with action=BLOCK written',        !!blockRow);
      assert('BLOCK row tool_name shell_bash',             blockRow?.tool_name === 'shell_bash');
      assert('BLOCK row reason=path-denied',               blockRow?.reason === 'path-denied');
      assert('BLOCK row result_kind=block',                blockRow?.result_kind === 'block');

      fs.unlinkSync(auditPath);
    } finally {
      loader._resetCache();
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }

  // ── 18. boundary accounting — tool runs carry kept_bytes + prevention_reason
  // End-to-end smoke for the boundary feature: a tool that actually runs
  // through the canonical pipeline must surface raw `bytes`, post-shaping
  // `kept_bytes`, and a `prevention_reason` field so `localfirst boundary`
  // can render the three-column view from the live log.
  console.log('\n18. [Read tool, real file] — toolsRun carries kept_bytes + prevention_reason');
  {
    const fs   = require('fs');
    const os   = require('os');
    const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-smoke-boundary-'));
    const file = path.join(tmp, 'README.md');
    const body = '# header\n' + 'lorem ipsum '.repeat(40) + '\n';
    fs.writeFileSync(file, body);

    try {
      const sse = buildSSE([
        { id: 'edit_18', name: 'Edit',
          input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
        { id: 'read_18', name: 'Read',
          input: { file_path: file } },
      ]);
      const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
        ...opts, sessionId: 's-smoke-18', runId: 'r-smoke-18',
      });

      const tr = r.toolsRun?.find(t => t.tool === 'Read');
      assert('Read recorded in toolsRun',                  !!tr);
      assert('tr.bytes is a positive number',              typeof tr?.bytes === 'number' && tr.bytes > 0);
      assert('tr.kept_bytes is a number',                  typeof tr?.kept_bytes === 'number');
      assert('tr.kept_bytes ≤ tr.bytes',                   tr.kept_bytes <= tr.bytes);
      assert('tr has prevention_reason field',             'prevention_reason' in tr);
      // For a small clean Read, no shaping → kept fully, reason null
      assert('clean Read: kept_bytes equals bytes',        tr.kept_bytes === tr.bytes);
      assert('clean Read: prevention_reason null',         tr.prevention_reason === null);
      assert('tool_use_id propagated from blk.id',         tr.tool_use_id === 'read_18');

      // The boundary view builder consumes the same shape and reports zero prevention.
      const { buildBoundaryView } = require('./src/boundary');
      const view = buildBoundaryView({
        iso: new Date().toISOString(), model: 'opus-4-7',
        event_type: 'cloud_sent', tools: [tr],
      });
      assert('boundary view: 1 tool',                      view.tools.length === 1);
      assert('boundary view: prevented_bytes=0',           view.tools[0].prevented_bytes === 0);
      assert('boundary view: prevention_label null',       view.tools[0].prevention_label === null);
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }

  // ── 19. Context budget — end-to-end clip on a real Read ─────────────────
  // policy.tools.read_file.max_output_tokens caps a large file's content
  // before re-entry. Verifies: tool ran, output was clipped, marker present,
  // toolsRun records bytes/kept_bytes/prevention_reason=context_budget.
  console.log('\n19. [Read tool, large file, max_output_tokens=50] — final clip kicks in');
  {
    const fsM  = require('fs');
    const osM  = require('os');
    const tmp  = fsM.mkdtempSync(path.join(osM.tmpdir(), 'lf-smoke-budget-'));
    const file = path.join(tmp, 'big.txt');
    // ~10kt of input (40k chars) so the cap definitely fires
    fsM.writeFileSync(file, 'lorem ipsum '.repeat(4000));

    const loader = require('./src/policy/loader');
    loader._setOverrideForTests({
      tools: {
        read_file: { action: 'LOCAL', max_output_tokens: 50 },
      },
    });

    try {
      const sse = buildSSE([
        { id: 'edit_19', name: 'Edit',
          input: { file_path: 'README.md', old_string: 'x', new_string: 'y' } },
        { id: 'read_19', name: 'Read',
          input: { file_path: file } },
      ]);
      const r = await interceptToolUse(sse, minReqBody, emptyHeaders, {
        ...opts, sessionId: 's-smoke-19', runId: 'r-smoke-19',
      });

      const tr = r.toolsRun?.find(t => t.tool === 'Read');
      assert('Read recorded',                                !!tr);
      assert('budget: kept_bytes < bytes',                   tr.kept_bytes < tr.bytes);
      assert('budget: prevention_reason=context_budget',     tr.prevention_reason === 'context_budget');

      const sent = r.partialResults?.find(p => p.tool_use_id === 'read_19');
      assert('budget: tool_result content contains marker',
        sent && /context_budget/.test(sent.content || ''));
      assert('budget: tool_result much shorter than raw input',
        sent && (sent.content.length < 1000));
    } finally {
      loader._resetCache();
      try { fsM.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }

  // ── summary ───────────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(40));
  if (failed === 0) {
    console.log(`✓ All ${passed} smoke tests passed`);
    process.exit(0);
  } else {
    console.error(`✗ ${failed} of ${passed + failed} smoke tests FAILED`);
    process.exit(1);
  }
}

run().catch(err => { console.error(err); process.exit(1); });
