'use strict';

/**
 * demo/audit-demo.js — `occasio demo audit`
 *
 * Hero demo: the auditor scenario. Shows the actual moat — a signed,
 * offline-verifiable attestation of agent behavior that any third
 * party can re-check with two independent verifiers (Node + Python).
 *
 * Flow:
 *   1. Auditor question framed
 *   2. Build richer synthetic chain (~12 rows: PASS + BLOCKs on the
 *      asked-about path + TRANSFORM + LOCAL)
 *   3. Verify chain integrity (Node SHA-256 walker)
 *   4. Build unsigned attestation
 *   5. Answer the auditor's question from the chain
 *   6. Re-verify with the independent Python verifier (docs/attest_verify.py)
 *      on the same artifact → byte-identical result
 *   7. Show what --sign would add in real CI
 *   8. CTA + spec link
 *
 * No API key, no network, no touching the user's real ~/.occasio chain.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const { buildAttestation } = require('../attest');
const { verifyFile }       = require('../audit/verifier');
const { canonicalize }     = require('../attest/canonicalize');

const C = {
  r:  s => `\x1b[31m${s}\x1b[0m`,
  g:  s => `\x1b[32m${s}\x1b[0m`,
  y:  s => `\x1b[33m${s}\x1b[0m`,
  c:  s => `\x1b[36m${s}\x1b[0m`,
  d:  s => `\x1b[2m${s}\x1b[0m`,
  b:  s => `\x1b[1m${s}\x1b[0m`,
  rb: s => `\x1b[31;1m${s}\x1b[0m`,
  gb: s => `\x1b[32;1m${s}\x1b[0m`,
};

const GENESIS = '0'.repeat(64);
const DENIED_PATH = '/etc/secrets/db.yml';

// Strip the OS temp prefix so demo output is screen-recording-safe
// (Windows TEMP contains the username; macOS/Linux less so but still
// machine-specific). Internal use still uses the real path.
function displayPath(p) {
  const tmp = os.tmpdir();
  if (p && p.startsWith(tmp)) {
    const suffix = p.slice(tmp.length).replace(/^[\\/]+/, '');
    return process.platform === 'win32' ? `%TEMP%\\${suffix}` : `$TMPDIR/${suffix}`;
  }
  return p;
}

function appendRow(file, prevHash, row) {
  const withPrev = { ...row, prev_hash: prevHash };
  const hash = crypto.createHash('sha256').update(JSON.stringify(withPrev), 'utf8').digest('hex');
  const full = { ...withPrev, hash };
  fs.appendFileSync(file, JSON.stringify(full) + '\n');
  return { hash, full };
}

function buildAuditScenarioChain(chainFile, policyFile) {
  fs.writeFileSync(chainFile, '');
  fs.writeFileSync(policyFile, [
    'version: 1',
    'deny_paths:',
    '  - "/etc/secrets/**"',
    '  - "**/.env"',
    '  - "**/.ssh/**"',
    'deny_patterns:',
    '  api_key: "(?i)api[_-]?key\\\\s*[:=]\\\\s*\\\\S+"',
    'block_secrets_in_tool_results: true',
    '',
  ].join('\n'));

  const RUN = crypto.randomBytes(16).toString('hex');
  const RUN_ID = `${RUN.slice(0,8)}-${RUN.slice(8,12)}-${RUN.slice(12,16)}-${RUN.slice(16,20)}-${RUN.slice(20,32)}`;
  const policyHash = crypto.createHash('sha256').update(fs.readFileSync(policyFile)).digest('hex');

  let prev = GENESIS;
  const ts = (sec) => new Date(Date.UTC(2026, 4, 16, 9, 30, sec)).toISOString();

  const blockedHashes = [];

  // 1. policy_loaded
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(0), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'occasio',
    kind: 'policy_loaded', tool_name: 'policy_loaded', action: 'INFO',
    tool_inputs: { policy_hash: policyHash, policy_path: policyFile, version: 1 },
    policy_source: 'user', reason: 'policy-loaded',
  }));

  // 2-4. Three normal PASS reads of source files
  for (const [i, p] of [[5, 'src/server.js'], [8, 'src/db.js'], [12, 'package.json']]) {
    ({ hash: prev } = appendRow(chainFile, prev, {
      ts: ts(i), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
      kind: 'tool_call', tool_name: 'Read', action: 'PASS',
      tool_inputs: { path: p },
    }));
  }

  // 5. LOCAL Glob discovery
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(15), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Glob', action: 'LOCAL',
    tool_inputs: { pattern: 'src/**/*.js' },
  }));

  // 6-8. THREE attempts to read the denied path — all BLOCKED
  //      (this is what the auditor will ask about)
  for (const [i, attempt] of [
    [18, DENIED_PATH],
    [22, '/etc/secrets/../secrets/db.yml'],     // traversal attempt
    [27, DENIED_PATH],                          // retry
  ].entries()) {
    const r = appendRow(chainFile, prev, {
      ts: ts(attempt[0]), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
      kind: 'tool_call', tool_name: 'Read', action: 'BLOCK',
      tool_inputs: { path: attempt[1] },
      reason: 'path-denied',
    });
    prev = r.hash;
    blockedHashes.push({ ts: ts(attempt[0]), hash: r.hash, path: attempt[1] });
  }

  // 9. TRANSFORM — Grep result had an API key, redacted before forward
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(32), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Grep', action: 'TRANSFORM',
    tool_inputs: { pattern: 'config', path: 'src/' },
    secrets_redacted: 1,
    transform: 'redact-secrets',
  }));

  // 10-11. Two more PASS reads
  for (const [i, p] of [[36, 'src/auth.js'], [40, 'src/routes.js']]) {
    ({ hash: prev } = appendRow(chainFile, prev, {
      ts: ts(i), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
      kind: 'tool_call', tool_name: 'Read', action: 'PASS',
      tool_inputs: { path: p },
    }));
  }

  // 12. LOCAL grep
  ({ hash: prev } = appendRow(chainFile, prev, {
    ts: ts(45), event_id: crypto.randomUUID(), run_id: RUN_ID, agent: 'claude-code',
    kind: 'tool_call', tool_name: 'Grep', action: 'LOCAL',
    tool_inputs: { pattern: 'TODO', path: 'src/' },
  }));

  return { runId: RUN_ID, blockedHashes };
}

function tryPython(att, chainFile, attFile) {
  const candidates = process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python'];
  for (const cmd of candidates) {
    const probe = spawnSync(cmd, ['--version'], { stdio: 'pipe', shell: false });
    if (probe.status === 0) {
      const verifierPath = path.join(__dirname, '..', '..', 'docs', 'attest_verify.py');
      if (!fs.existsSync(verifierPath)) {
        return { ran: false, reason: `verifier script not found at ${verifierPath}` };
      }
      const result = spawnSync(cmd, [verifierPath, attFile, '--chain', chainFile], {
        stdio: 'pipe', shell: false, encoding: 'utf8',
      });
      const out = (result.stdout || '') + (result.stderr || '');
      // Parse the verifier's "[STATUS] check name" lines. For an unsigned
      // attestation, sigstore steps SKIP and the chain step OKs — that is
      // the success shape for the demo. Real failure = any FAIL line.
      const lines = out.split('\n');
      const checks = [];
      for (const line of lines) {
        const m = line.match(/\[\s*(OK|FAIL|SKIP)\s*\]\s+(.+?)\s*$/);
        if (m) checks.push({ status: m[1], name: m[2] });
      }
      const anyFail = checks.some(c => c.status === 'FAIL');
      const chainOk = checks.some(c => c.status === 'OK' && /chain/i.test(c.name));
      return {
        ran: true,
        cmd,
        exitCode: result.status,
        checks,
        anyFail,
        chainOk,
        stdout: result.stdout || '',
      };
    }
  }
  return { ran: false, reason: 'no python3/python on PATH' };
}

async function runAuditDemoCli(_args = []) {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-demo-audit-'));
  const chainFile  = path.join(tmpDir, 'pipeline-events.jsonl');
  const policyFile = path.join(tmpDir, 'policy.yml');
  const attFile    = path.join(tmpDir, 'occasio-attestation.json');

  console.log(C.b('\n⚡ Occasio — auditor demo  ') + C.d('(no API key, no network, ~10s)\n'));

  // ── Scene ──────────────────────────────────────────────────────────────
  console.log(C.b('━━━ The question ━━━\n'));
  console.log('  ' + C.y('Auditor:') + ' "Your CI merged 47 AI-authored PRs last month. Prove the');
  console.log('           agent in build #2849 never read ' + C.c(DENIED_PATH) + '."');
  console.log('');
  console.log('  ' + C.d('Without Occasio: you grep through stderr logs, hope nothing was'));
  console.log('  ' + C.d('rotated, and email Anthropic for server-side traces.'));
  console.log('  ' + C.d('With Occasio: you hand the auditor one JSON file. They verify it offline.'));
  console.log('');

  // ── Step 1: chain ──────────────────────────────────────────────────────
  console.log(C.b('1.') + ' Synthesizing the CI-run audit chain  ' + C.d('(12 rows, hash-linked)'));
  const { runId, blockedHashes } = buildAuditScenarioChain(chainFile, policyFile);
  console.log('   ' + C.g('✓') + ' run_id: ' + C.c(runId));
  console.log('   ' + C.d('chain: ' + displayPath(chainFile)));
  console.log('');

  // ── Step 2: verify ─────────────────────────────────────────────────────
  console.log(C.b('2.') + ' Verifying chain integrity  ' + C.d('(SHA-256 walk: prev_hash → hash, GENESIS → HEAD)'));
  const ver = verifyFile(chainFile);
  if (!ver.ok) {
    console.error('   ' + C.r('✗') + ' chain broken — demo bug');
    return 1;
  }
  console.log('   ' + C.g('✓') + ' all ' + ver.chained + ' rows chained, no tamper gap');
  console.log('');

  // ── Step 3: build attestation ──────────────────────────────────────────
  console.log(C.b('3.') + ' Building behavioral attestation  ' + C.d('(unsigned; --sign needs OIDC)'));
  const att = buildAttestation({ runId, logFile: chainFile, policyFile });
  if (!att) {
    console.error('   ' + C.r('✗') + ' buildAttestation returned null');
    return 1;
  }
  fs.writeFileSync(attFile, JSON.stringify(att, null, 2));
  console.log('   ' + C.g('✓') + ' ' + C.d(displayPath(attFile)));
  console.log('   ' + C.d('tool_calls: ' + att.execution_summary.tool_calls
    + '  blocked: ' + att.execution_summary.blocked
    + '  transformed: ' + att.execution_summary.transformed
    + '  secrets_redacted: ' + att.execution_summary.secrets_redacted));
  console.log('');

  // ── Step 4: ANSWER THE AUDITOR ─────────────────────────────────────────
  console.log(C.b('━━━ Answer to the auditor ━━━\n'));
  console.log('  ' + C.y('Q:') + ' "Did the agent read ' + C.c(DENIED_PATH) + '?"');
  console.log('  ' + C.gb('A: NO.') + ' ' + blockedHashes.length + ' attempts, all denied by policy. Evidence:');
  console.log('');
  for (const b of blockedHashes) {
    console.log('     ' + C.d(b.ts) + '  ' + C.rb('BLOCK') + '  '
      + b.path.padEnd(38) + '  ' + C.d('hash=' + b.hash.slice(0, 16) + '…'));
  }
  console.log('');
  console.log('  ' + C.d('These row hashes are linked into the chain. Tampering with any'));
  console.log('  ' + C.d('one of them breaks the SHA-256 walk and the attestation fails verify.'));
  console.log('');

  // ── Step 5: Node verifier (canonical round-trip) ───────────────────────
  console.log(C.b('4.') + ' Re-verifying with the Node verifier  ' + C.d('(canonical JSON round-trip)'));
  const reparsed = JSON.parse(fs.readFileSync(attFile, 'utf8'));
  const { signature: _o1, ...expected } = att;
  const { signature: _o2, ...observed } = reparsed;
  if (canonicalize(expected) !== canonicalize(observed)) {
    console.error('   ' + C.r('✗') + ' canonical bytes diverged');
    return 1;
  }
  console.log('   ' + C.g('✓') + ' predicate canonical-stable across reparse');
  console.log('');

  // ── Step 6: Python cross-verifier ──────────────────────────────────────
  console.log(C.b('5.') + ' Re-verifying with the independent Python verifier  ' + C.d('(docs/attest_verify.py)'));
  const py = tryPython(att, chainFile, attFile);
  if (!py.ran) {
    console.log('   ' + C.y('○') + ' Python verifier skipped — ' + py.reason);
    console.log('   ' + C.d('  install python3 to run the cross-verifier; the Node check above already passed'));
  } else if (py.anyFail) {
    console.log('   ' + C.r('✗') + ' Python verifier reported FAIL  ' + C.d('(' + py.cmd + ' exit ' + py.exitCode + ')'));
    for (const c of py.checks) {
      const tag = c.status === 'OK' ? C.g('OK  ') : c.status === 'FAIL' ? C.r('FAIL') : C.y('SKIP');
      console.log('     [' + tag + '] ' + c.name);
    }
  } else if (py.chainOk) {
    console.log('   ' + C.g('✓') + ' independent Python verifier agrees on the audit chain');
    for (const c of py.checks) {
      const tag = c.status === 'OK' ? C.g('OK  ') : C.y('SKIP');
      console.log('     [' + tag + '] ' + c.name);
    }
    console.log('   ' + C.d('  (sigstore steps SKIP because the demo attestation is unsigned;'));
    console.log('   ' + C.d('   in real CI with --sign, all three rows would show OK)'));
  } else {
    console.log('   ' + C.y('○') + ' Python verifier ran but did not produce the expected check lines');
    console.log('   ' + C.d('  exit ' + py.exitCode + ' — see ' + displayPath(attFile) + ' for the artifact'));
  }
  console.log('');

  // ── Step 7: what --sign adds in CI ─────────────────────────────────────
  console.log(C.b('━━━ In real CI: --sign adds the third check ━━━\n'));
  console.log('  ' + C.c('occasio attest --run-id ' + runId.slice(0, 8) + '… --sign'));
  console.log('  ' + C.d('  → signs via Sigstore keyless using GitHub Actions OIDC (no key mgmt)'));
  console.log('  ' + C.d('  → emits .json attestation + .bundle.json Sigstore bundle'));
  console.log('  ' + C.d('  → workflow posts a Check Run on the PR with the verify summary'));
  console.log('');
  console.log('  ' + C.b('Auditor verifies offline with three independent paths:'));
  console.log('  ' + C.d('  • ') + C.c('occasio attest verify <file>') + C.d('       (Node)'));
  console.log('  ' + C.d('  • ') + C.c('python3 docs/attest_verify.py <file>') + C.d(' (stdlib + sigstore-python)'));
  console.log('  ' + C.d('  • ') + C.c('cosign verify-blob …') + C.d('                (any sigstore-conformant tool)'));
  console.log('');
  console.log('  ' + C.d('All three must agree. None of them trust Occasio\'s own verifier.'));
  console.log('');

  // ── CTA ────────────────────────────────────────────────────────────────
  console.log(C.b('━━━ Try it on your own CI ━━━\n'));
  console.log('  ' + C.c('npm install -g @occasiolabs/occasio'));
  console.log('  ' + C.c('occasio policy init                     ') + C.d('# write ~/.occasio/policy.yml'));
  console.log('  ' + C.c('occasio register                        ') + C.d('# alias `claude` through the proxy'));
  console.log('  ' + C.d('Add .github/workflows/attest-on-pr.yml from docs/reference-pipeline.md'));
  console.log('');
  console.log('  ' + C.b('Spec:') + ' https://github.com/occasiolabs/occasio/tree/main/spec/agent-attestation/v1');
  console.log('  ' + C.b('Scratch artifacts kept at:') + ' ' + C.d(displayPath(tmpDir)));
  console.log('');

  return 0;
}

module.exports = { runAuditDemoCli, buildAuditScenarioChain };
