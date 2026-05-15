'use strict';

/**
 * test-attest-e2e.js — CI-gated end-to-end Sigstore round-trip.
 *
 * Skipped by default. Runs only when OCCASIO_E2E_SIGSTORE=1 AND the
 * GitHub Actions OIDC env (ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN) is set.
 *
 * Scope decision (documented in CHANGELOG): we sign against **prod**
 * Sigstore — Fulcio + the public Rekor transparency log. The dedicated
 * staging instance is intermittently available and changes shape between
 * sigstore-js releases; relying on it produces a flaky gate.  The cost is
 * one public Rekor entry per CI run, which is the same overhead any
 * Sigstore-using project (npm, PyPI, sigstore-go) pays continuously.
 *
 * The workflow that triggers this test (.github/workflows/attest-e2e.yml)
 * runs only on workflow_dispatch and on main-branch pushes — never on PR
 * pushes from forks — so the Rekor footprint is bounded to ~ once per
 * release-readiness check.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

const { createAuditor } = require('./src/audit/jsonl-auditor');
const { buildAttestation } = require('./src/attest');
const { signAttestation, buildInTotoStatement } = require('./src/attest/sign');
const { canonicalize } = require('./src/attest/canonicalize');
const { verifyAttestation } = require('./src/attest/verify');

function isEnabled() {
  if (process.env.OCCASIO_E2E_SIGSTORE !== '1') return false;
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL)  return false;
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) return false;
  return true;
}

if (!isEnabled()) {
  console.log('test-attest-e2e: SKIP — set OCCASIO_E2E_SIGSTORE=1 inside a GitHub Actions job with `permissions: id-token: write`');
  process.exit(0);
}

let passed = 0, failed = 0;
function assert(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else      { console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); failed++; }
}

(async () => {
  console.log('\nE2E. real Sigstore round-trip\n');

  // Build a tiny chain with a real run-id slice.
  const chainFile = path.join(os.tmpdir(), `occasio-e2e-chain-${process.pid}.jsonl`);
  if (fs.existsSync(chainFile)) fs.unlinkSync(chainFile);
  const a = createAuditor(chainFile);
  const runId = 'e2e-' + crypto.randomBytes(6).toString('hex');
  for (let i = 0; i < 3; i++) {
    a.record(
      { timestamp: new Date(Date.now() - (3 - i) * 1000).toISOString(),
        id: `evt-${i}`, sessionId: 'sess-e2e', runId,
        agent: 'claude-code', protocol: 'anthropic', direction: 'outbound',
        kind: 'tool_call', toolName: 'Read', toolInput: { file_path: `/repo/f${i}` } },
      { action: 'LOCAL', reason: 'e2e', policySource: 'default' },
      { exitCode: 0 });
  }

  const att = buildAttestation({
    runId, logFile: chainFile,
    policyFile: path.join(os.tmpdir(), 'nope.yml'),
  });
  assert('attestation built',        !!att);
  assert('event_count = 3',          att.audit_chain.event_count === 3);
  assert('last_hash present',        typeof att.audit_chain.last_hash === 'string'
                                     && att.audit_chain.last_hash.length === 64);

  // Sign against real prod Sigstore via GitHub Actions OIDC.
  console.log('\n  signing against prod Fulcio + Rekor (this writes one public transparency entry)…');
  const { bundle, signatureBlock, statementJSON } =
    await signAttestation(att, { signMode: 'ci' });

  assert('bundle has mediaType',                 typeof bundle.mediaType === 'string');
  assert('bundle has verificationMaterial',      !!bundle.verificationMaterial);
  assert('bundle.dsseEnvelope present',          !!bundle.dsseEnvelope);
  assert('Rekor tlog entry present',
         !!bundle.verificationMaterial?.tlogEntries?.[0]?.logIndex);
  assert('signatureBlock has identity',          typeof signatureBlock.identity === 'string');
  assert('signatureBlock has rekor_entry',       /sigstore\.dev/.test(signatureBlock.rekor_entry || ''));
  assert('envelope_sha256 64 hex',
         /^[a-f0-9]{64}$/.test(signatureBlock.envelope_sha256));
  assert('statementJSON is canonicalized',
         statementJSON === canonicalize(buildInTotoStatement(att)));

  // Persist + verify round-trip.
  const attPath    = path.join(os.tmpdir(), `occasio-e2e-att-${process.pid}.json`);
  const bundlePath = path.join(os.tmpdir(), `occasio-e2e-bundle-${process.pid}.json`);
  const attWithSig = { ...att, signature: signatureBlock };
  fs.writeFileSync(attPath, JSON.stringify(attWithSig, null, 2));
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));

  const result = await verifyAttestation(attPath, bundlePath);
  assert('verifier ok=true',                  result.ok === true,
         result.checks.find(c => !c.ok)?.detail);
  for (const c of result.checks) {
    assert(`verify check: ${c.name}`,         c.ok === true, c.detail);
  }

  // Tamper test: change one byte in the persisted attestation predicate
  // (not signature/bundle). The verifier should refuse.
  const tampered = JSON.parse(fs.readFileSync(attPath, 'utf8'));
  tampered.audit_chain.event_count = 999;
  fs.writeFileSync(attPath, JSON.stringify(tampered, null, 2));
  const bad = await verifyAttestation(attPath, bundlePath);
  assert('verifier rejects tampered predicate', bad.ok === false);

  console.log('\n────────────────────────────────────────');
  if (failed === 0) {
    console.log(`✓ All ${passed} e2e checks passed\n`);
    process.exit(0);
  } else {
    console.log(`✗ ${failed}/${passed + failed} e2e checks failed\n`);
    process.exit(1);
  }
})().catch(err => {
  console.error('e2e crashed:', err && (err.stack || err.message || err));
  process.exit(2);
});
