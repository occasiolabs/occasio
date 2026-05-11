'use strict';

/**
 * localfirst selftest — exercise the highest-risk governance claims against a
 * scratch temp setup. Never touches the user's real ~/.localfirst chain.
 *
 * Scope (deliberately small):
 *   1. read_file vs deny_paths           → BLOCK path-denied
 *   2. shell_bash cat vs deny_paths      → BLOCK path-denied
 *   3. shell_powershell Get-Content vs deny_paths → BLOCK path-denied
 *   4. read_file allowed path            → LOCAL, bytes returned
 *   5. secret in tool_result (block mode) → BLOCK secret-in-tool-result
 *   6. redact-secrets TRANSFORM          → bytes returned, secret absent
 *   7. audit verify on the scratch chain → ok=true
 *   8. scratch chain shape               → ≥1 BLOCK + ≥1 TRANSFORM rows
 *
 * Exit codes (via runSelfTestCli): 0 = all pass, 1 = any fail.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { makeBoundaryEvent }    = require('./core/boundary-event');
const { processToolEvent }     = require('./core/pipeline');
const loader                   = require('./policy/loader');
const engine                   = require('./policy/engine');
const { createAuditor }        = require('./audit/jsonl-auditor');
const { verifyFile }           = require('./audit/verifier');

const AKIA_FIXTURE = 'AKIA' + 'ABCDEFGHIJKLMNOP'; // 20 chars; matches scanner pattern

function mkScratch() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-selftest-'));
  const denyDir  = path.join(root, 'denied');
  const allowDir = path.join(root, 'allowed');
  fs.mkdirSync(denyDir);
  fs.mkdirSync(allowDir);
  const denyFile     = path.join(denyDir,  'secret.txt');
  const allowFile    = path.join(allowDir, 'public.txt');
  const akiaFile     = path.join(allowDir, 'with-akia.txt');
  fs.writeFileSync(denyFile,  'TOP-SECRET-DO-NOT-LEAK\n');
  fs.writeFileSync(allowFile, 'public content\n');
  fs.writeFileSync(akiaFile,  `header\n${AKIA_FIXTURE}\nfooter\n`);
  return { root, denyDir, allowDir, denyFile, allowFile, akiaFile };
}

function mkEvent(toolName, toolInput) {
  return makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http',
    sessionId: 'selftest', runId: 'selftest',
    toolName, toolInput,
  });
}

async function runSelfTest(opts = {}) {
  const silent = !!opts.silent;
  const log = silent ? () => {} : (s) => process.stdout.write(s + '\n');

  const fixtures = mkScratch();
  const auditPath = path.join(fixtures.root, 'events.jsonl');
  const auditor   = createAuditor(auditPath);

  const scenarios = [];
  const record = (id, name, ok, detail) => {
    scenarios.push({ id, name, status: ok ? 'pass' : 'fail', detail: detail || null });
    log(`  ${ok ? '✓' : '✗'}  ${String(id).padStart(2)}. ${name}${ok ? '' : `   — ${detail}`}`);
  };

  log('LocalFirst self-test');
  log(`  scratch root: ${fixtures.root}`);
  log(`  audit file:   ${auditPath}`);
  log('');

  try {
    // Policy A: deny_paths covers the denied directory.
    loader._setOverrideForTests({
      deny_paths:  [fixtures.denyDir],
      allow_paths: [],
    });

    // 1. read_file vs deny_paths
    {
      const r = await processToolEvent(
        mkEvent('read_file', { file_path: fixtures.denyFile }),
        { auditor });
      const ok = r.decision.action === 'BLOCK' && r.decision.reason === 'path-denied';
      record(1, 'read_file <denied> → BLOCK path-denied', ok,
        ok ? null : `got ${r.decision.action} / ${r.decision.reason}`);
    }

    // 2. shell_bash cat vs deny_paths
    {
      const r = await processToolEvent(
        mkEvent('shell_bash', { command: `cat ${fixtures.denyFile}` }),
        { auditor });
      const ok = r.decision.action === 'BLOCK' && r.decision.reason === 'path-denied';
      record(2, 'shell_bash cat <denied> → BLOCK path-denied', ok,
        ok ? null : `got ${r.decision.action} / ${r.decision.reason}`);
    }

    // 3. shell_powershell Get-Content vs deny_paths
    {
      const r = await processToolEvent(
        mkEvent('shell_powershell', { command: `Get-Content ${fixtures.denyFile}` }),
        { auditor });
      const ok = r.decision.action === 'BLOCK' && r.decision.reason === 'path-denied';
      record(3, 'shell_powershell Get-Content <denied> → BLOCK path-denied', ok,
        ok ? null : `got ${r.decision.action} / ${r.decision.reason}`);
    }

    // 4. read_file on an allowed path runs LOCAL and returns bytes
    {
      const r = await processToolEvent(
        mkEvent('read_file', { file_path: fixtures.allowFile }),
        { auditor });
      const okAct = r.decision.action === 'LOCAL';
      const bytes = typeof r.result?.output === 'string' ? r.result.output : '';
      const okBytes = bytes.includes('public content');
      record(4, 'read_file <allowed> → LOCAL with bytes', okAct && okBytes,
        !okAct ? `decision=${r.decision.action}` : (!okBytes ? 'bytes missing' : null));
    }

    // 5. Secret in tool_result under block mode → BLOCK
    {
      const decision = engine.evaluateToolResults(
        [{ tool_use_id: 'sst-5', content: `noise\n${AKIA_FIXTURE}\nmore noise\n` }],
        { mode: 'block_secrets' });
      const ok = decision.action === 'BLOCK' && /secret in tool result/.test(decision.reason || '');
      record(5, 'secret in tool_result (block_secrets) → BLOCK', ok,
        ok ? null : `got ${decision.action} / ${decision.reason}`);
    }

    // 6. redact-secrets TRANSFORM: same file, but policy redacts. Secret bytes
    //    must be absent from the returned output.
    loader._setOverrideForTests({
      deny_paths:  [],
      allow_paths: [],
      redact_secrets_in_tool_results: true,
    });
    {
      const r = await processToolEvent(
        mkEvent('read_file', { file_path: fixtures.akiaFile }),
        { auditor });
      const out  = typeof r.result?.output === 'string' ? r.result.output : '';
      const okAct  = r.decision.action === 'TRANSFORM' && r.result?.transformed === true;
      const okHide = out.length > 0 && !out.includes(AKIA_FIXTURE);
      record(6, 'redact-secrets TRANSFORM → secret absent from output', okAct && okHide,
        !okAct ? `decision=${r.decision.action}` : (!okHide ? 'secret leaked in output' : null));
    }

    // 7. Audit verify on the scratch chain
    {
      const v = verifyFile(auditPath);
      const ok = v.ok === true && v.chained >= 5;
      record(7, `audit verify on scratch chain → ok (${v.chained} chained rows)`, ok,
        ok ? null : `ok=${v.ok} chained=${v.chained} errors=${(v.errors || []).length}`);
    }

    // 8. Scratch chain shape: at least one BLOCK row and one TRANSFORM row
    {
      const rows = fs.readFileSync(auditPath, 'utf8')
        .split('\n').filter(Boolean).map(JSON.parse);
      const nBlock     = rows.filter(r => r.action === 'BLOCK').length;
      const nTransform = rows.filter(r => r.action === 'TRANSFORM').length;
      const ok = nBlock >= 3 && nTransform >= 1;
      record(8, `scratch chain rows: ${nBlock} BLOCK + ${nTransform} TRANSFORM`, ok,
        ok ? null : `expected ≥3 BLOCK + ≥1 TRANSFORM`);
    }

  } finally {
    loader._resetCache();
    try { fs.rmSync(fixtures.root, { recursive: true, force: true }); } catch {}
  }

  const failed = scenarios.filter(s => s.status === 'fail').length;
  const ok     = failed === 0;
  log('');
  log(ok
    ? `All ${scenarios.length} self-tests passed.`
    : `${failed} of ${scenarios.length} self-tests FAILED.`);

  return { ok, scenarios };
}

async function runSelfTestCli() {
  const result = await runSelfTest({});
  process.exit(result.ok ? 0 : 1);
}

module.exports = { runSelfTest, runSelfTestCli };
