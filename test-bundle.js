#!/usr/bin/env node
'use strict';

/**
 * test-bundle.js — portable evidence bundle (Idea #2).
 *
 * Covers:
 *   - src/bundle/index.js   buildBundle (structure + manifest)
 *   - src/bundle/verify.js  verifyBundle (6 checks, fail-stop)
 *   - src/audit/verifier.js verifySlice (mid-chain slice mode)
 *
 * No network, no real API keys: the signed round-trip uses a stub sigstore
 * module (matching test-attest.js). All temp files live in os.tmpdir().
 *
 * Tamper philosophy: a bundle's manifest is NOT signed, so an attacker can
 * recompute it. The real protection is the hash chain (slice content hashes)
 * and the attestation's commitments. The "sophisticated" tamper tests below
 * recompute the manifest to match the edit and prove the deeper checks still
 * catch it.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const { buildBundle }  = require('./src/bundle');
const { verifyBundle } = require('./src/bundle/verify');
const { verifySlice }  = require('./src/audit/verifier');
const { buildAttestation } = require('./src/attest');
const { signAttestation, buildInTotoStatement } = require('./src/attest/sign');
const { canonicalize } = require('./src/attest/canonicalize');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

function sha256hex(str) { return crypto.createHash('sha256').update(str, 'utf8').digest('hex'); }

const tmps = [];
function mkTmp(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmps.push(d);
  return d;
}

// Recompute a bundle's manifest exactly as src/bundle/index.js does — used by
// "sophisticated" tamper tests that fix up the manifest after an edit.
function recomputeManifest(bundle) {
  const attSha   = sha256hex(JSON.stringify(bundle.attestation));
  const sliceSha = sha256hex(JSON.stringify(bundle.chain_slice));
  const text     = bundle.policy_snapshot.text;
  const polSha   = (text === null || text === undefined) ? null : sha256hex(text);
  bundle.manifest = {
    attestation_sha256: attSha,
    chain_slice_sha256: sliceSha,
    policy_sha256:      polSha,
    bundle_digest: sha256hex(JSON.stringify({
      schema: 'occasio-bundle/v1', run_id: bundle.run_id,
      attestation_sha256: attSha, chain_slice_sha256: sliceSha, policy_sha256: polSha,
    })),
  };
  return bundle;
}

// ── synthetic chain (hand-built, full control over run_id + policy_hash) ─────
const RUN = '55555555-5555-5555-5555-555555555555';
const dir = mkTmp('lf-bundle-');
const chainFile = path.join(dir, 'pipeline-events.jsonl');
const polFile   = path.join(dir, 'policy.yml');
const POLICY_TEXT = 'block_secrets_in_tool_results: true\ndeny_paths:\n  - /etc/secret\n';
fs.writeFileSync(polFile, POLICY_TEXT);
const POLHASH = sha256hex(POLICY_TEXT);

let prev = '0'.repeat(64);
function appendRow(row) {
  const withPrev = { ...row, prev_hash: prev };
  const hash = sha256hex(JSON.stringify(withPrev));
  const full = { ...withPrev, hash };
  fs.appendFileSync(chainFile, JSON.stringify(full) + '\n');
  prev = hash;
  return full;
}

const START = { is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: false,
  changed_files: [], untracked_files: [], diff_hash: null, digest: 'a'.repeat(64) };
const END   = { is_repo: true, head: '1'.repeat(40), branch: 'main', dirty: true,
  changed_files: ['src/app.js'], untracked_files: ['notes.md'], diff_hash: '2'.repeat(64), digest: 'b'.repeat(64) };

appendRow({ audit_schema: 1, ts: '2026-05-12T10:00:00.000Z', run_id: RUN, agent: 'occasio',
  protocol: 'internal', direction: 'inbound', kind: 'policy_loaded', tool_name: 'policy_loaded',
  tool_inputs: { policy_hash: POLHASH, policy_path: polFile, version: 1 },
  action: 'INFO', reason: 'policy-loaded', policy_source: 'user' });
appendRow({ audit_schema: 1, ts: '2026-05-12T10:00:01.000Z', run_id: RUN, agent: 'occasio',
  protocol: 'internal', direction: 'inbound', kind: 'git_state', tool_name: 'git_state',
  tool_inputs: { phase: 'run_start', cwd: '/tmp', ...START }, action: 'INFO', reason: 'git-state' });
appendRow({ audit_schema: 1, ts: '2026-05-12T10:00:05.000Z', run_id: RUN, agent: 'claude-code',
  protocol: 'anthropic-http', direction: 'outbound', kind: 'tool_call', tool_name: 'read_file',
  tool_inputs: { path: '/tmp/x' }, action: 'LOCAL', reason: 'native-handleable' });
appendRow({ audit_schema: 1, ts: '2026-05-12T10:00:09.000Z', run_id: RUN, agent: 'occasio',
  protocol: 'internal', direction: 'inbound', kind: 'git_state', tool_name: 'git_state',
  tool_inputs: { phase: 'run_end', cwd: '/tmp', ...END }, action: 'INFO', reason: 'git-state' });

// ── 1. buildBundle — structure ───────────────────────────────────────────────
console.log('\n1. buildBundle — structure');
const baseBundle = buildBundle({ runId: RUN, logFile: chainFile, policyFile: polFile });
{
  assert('bundle built', !!baseBundle);
  assert('schema tag', baseBundle.schema === 'occasio-bundle/v1');
  assert('embeds attestation', !!baseBundle.attestation && baseBundle.attestation.subject.run_id === RUN);
  assert('chain_slice has 4 rows', baseBundle.chain_slice.length === 4);
  assert('policy_snapshot carries exact bytes', baseBundle.policy_snapshot.text === POLICY_TEXT);
  assert('manifest has all hashes',
    /^[0-9a-f]{64}$/.test(baseBundle.manifest.attestation_sha256) &&
    /^[0-9a-f]{64}$/.test(baseBundle.manifest.chain_slice_sha256) &&
    baseBundle.manifest.policy_sha256 === POLHASH &&
    /^[0-9a-f]{64}$/.test(baseBundle.manifest.bundle_digest));
  assert('attestation pulled git_state from chain',
    baseBundle.attestation.subject.git_state &&
    baseBundle.attestation.subject.git_state.provenance === 'chain');
  assert('unsigned by default', baseBundle.sigstore_bundle === null);
}

// ── 2. verifyBundle — honest bundle passes ───────────────────────────────────
console.log('\n2. verifyBundle — honest');
(async () => {
  const f = path.join(dir, 'honest.occasio.json');
  fs.writeFileSync(f, JSON.stringify(baseBundle, null, 2));
  const r = await verifyBundle(f);
  assert('honest bundle verifies ok', r.ok === true, JSON.stringify(r.checks));
  assert('all six check names present',
    ['schema', 'manifest integrity', 'chain slice integrity', 'policy binding', 'git state matches chain', 'signature']
      .every(n => r.checks.find(c => c.name === n && c.ok)));

  // ── 3. tamper: naive chain-row edit → manifest catches it ──────────────────
  console.log('\n3. tamper — naive chain-row edit (manifest catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    b.chain_slice[1].tool_inputs.head = '0'.repeat(40);   // edit, do NOT fix manifest
    const ff = path.join(dir, 'tamper-naive.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('naive edit fails verification', rr.ok === false);
    assert('manifest integrity check is the one that fails',
      rr.checks.find(c => c.name === 'manifest integrity' && c.ok === false) !== undefined);
  }

  // ── 4. tamper: sophisticated chain-row edit + fixed manifest → slice catches ─
  console.log('\n4. tamper — chain-row edit with recomputed manifest (hash chain catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    b.chain_slice[1].tool_inputs.head = '0'.repeat(40);   // edit a row's content
    recomputeManifest(b);                                  // attacker fixes the manifest
    const ff = path.join(dir, 'tamper-slice.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('manifest now passes', rr.checks.find(c => c.name === 'manifest integrity' && c.ok) !== undefined);
    assert('slice integrity catches the edited row',
      rr.checks.find(c => c.name === 'chain slice integrity' && c.ok === false) !== undefined);
    assert('overall fails', rr.ok === false);
  }

  // ── 5. tamper: forged git_state in attestation + fixed manifest → cross-check ─
  console.log('\n5. tamper — forged subject.git_state (git cross-check catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    b.attestation.subject.git_state.run_end.head = 'f'.repeat(40);
    recomputeManifest(b);
    const ff = path.join(dir, 'tamper-git.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('git cross-check catches forged head',
      rr.checks.find(c => c.name === 'git state matches chain' && c.ok === false) !== undefined);
    assert('overall fails', rr.ok === false);
  }

  // ── 6. tamper: swapped policy snapshot + fixed manifest → policy binding ────
  console.log('\n6. tamper — swapped policy snapshot (policy binding catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    b.policy_snapshot.text = 'block_secrets_in_tool_results: false\n';   // attacker lies about policy
    recomputeManifest(b);
    const ff = path.join(dir, 'tamper-policy.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('policy binding catches swapped policy',
      rr.checks.find(c => c.name === 'policy binding' && c.ok === false) !== undefined);
    assert('overall fails', rr.ok === false);
  }

  // ── 7. tamper: dropped last slice row + fixed manifest → last_hash anchor ───
  console.log('\n7. tamper — dropped last slice row (attestation anchor catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    b.chain_slice.pop();                                   // drop run_end row
    recomputeManifest(b);
    const ff = path.join(dir, 'tamper-truncate.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('slice integrity catches last_hash mismatch',
      rr.checks.find(c => c.name === 'chain slice integrity' && c.ok === false) !== undefined);
    assert('overall fails', rr.ok === false);
  }

  // ── 8. tamper: missing required key → schema check ─────────────────────────
  console.log('\n8. tamper — missing required key (schema catches)');
  {
    const b = JSON.parse(JSON.stringify(baseBundle));
    delete b.manifest;
    const ff = path.join(dir, 'tamper-schema.json');
    fs.writeFileSync(ff, JSON.stringify(b));
    const rr = await verifyBundle(ff);
    assert('schema check fails on missing key',
      rr.checks.find(c => c.name === 'schema' && c.ok === false) !== undefined);
    assert('overall fails', rr.ok === false);
  }

  // ── 9. verifySlice unit — mid-chain slice + content tamper ─────────────────
  console.log('\n9. verifySlice — mid-chain slice mode');
  {
    const rows = JSON.parse(JSON.stringify(baseBundle.chain_slice));
    assert('first slice row is mid-chain (prev_hash != GENESIS not required)',
      rows[0].prev_hash === '0'.repeat(64));   // here it happens to be genesis, but...
    // Force a genuinely mid-chain slice: drop the first row so row0.prev_hash != GENESIS.
    const midSlice = rows.slice(1);
    const okRes = verifySlice(midSlice);
    assert('mid-chain slice (row0.prev_hash != GENESIS) verifies ok', okRes.ok === true);
    // Content tamper: flip a field without fixing the hash.
    const bad = JSON.parse(JSON.stringify(midSlice));
    bad[0].tool_inputs.head = '9'.repeat(40);
    const badRes = verifySlice(bad);
    assert('content-tampered slice fails', badRes.ok === false && badRes.errors.length > 0);
  }

  // ── 10. signed round-trip with stub sigstore ───────────────────────────────
  console.log('\n10. signed bundle — sign + verify (stub sigstore)');
  {
    function jwt(claims) {
      const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
      return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
    }
    const att = buildAttestation({ runId: RUN, logFile: chainFile, policyFile: polFile });
    // Stub returns a bundle whose DSSE payload IS the canonical statement bytes
    // it was handed — so verify's predicate comparison is exercised for real.
    const signStub = {
      attest(payload, payloadType) {
        return Promise.resolve({
          mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
          verificationMaterial: { tlogEntries: [{ logIndex: '7' }] },
          dsseEnvelope: { payload: payload.toString('base64'), payloadType },
        });
      },
    };
    const out = await signAttestation(att, { oidcToken: jwt({ sub: 'repo:o/r:ref:refs/heads/main' }), sigstoreModule: signStub });
    att.signature = out.signatureBlock;
    const signed = buildBundle({ runId: RUN, logFile: chainFile, policyFile: polFile, attestation: att, sigstoreBundle: out.bundle });
    assert('signed bundle embeds sigstore_bundle', !!signed.sigstore_bundle);

    const verifyStub = { verify: async () => true };
    const f1 = path.join(dir, 'signed.occasio.json');
    fs.writeFileSync(f1, JSON.stringify(signed));
    // verifyBundle reads from file; inject stub via verifyBundle(path, ctx)
    const okR = await verifyBundle(f1, { sigstoreModule: verifyStub });
    assert('signed bundle verifies with stub', okR.ok === true, JSON.stringify(okR.checks));
    assert('signature check passed',
      okR.checks.find(c => c.name === 'signature' && c.ok) !== undefined);

    // Forge the signed payload: swap in a statement with a different predicate.
    const forged = JSON.parse(JSON.stringify(signed));
    const fakeStmt = buildInTotoStatement(Object.assign({}, att, { subject: { run_id: 'OTHER' } }));
    forged.sigstore_bundle.dsseEnvelope.payload = Buffer.from(canonicalize(fakeStmt), 'utf8').toString('base64');
    const f2 = path.join(dir, 'signed-forged.json');
    fs.writeFileSync(f2, JSON.stringify(forged));
    const badR = await verifyBundle(f2, { sigstoreModule: verifyStub });
    assert('signature check catches predicate swap',
      badR.checks.find(c => c.name === 'signature' && c.ok === false) !== undefined);
    assert('forged signed bundle fails overall', badR.ok === false);
  }

  // ── 11. strict mode — required checks fail-closed ──────────────────────────
  console.log('\n11. strict mode — --strict / --require-* fail-closed');
  {
    // (a) lenient default: unsigned bundle still passes, signature marked unsigned
    const fLenient = path.join(dir, 'strict-lenient.json');
    fs.writeFileSync(fLenient, JSON.stringify(baseBundle));
    const rLenient = await verifyBundle(fLenient);          // no requirements
    assert('lenient default: unsigned bundle passes', rLenient.ok === true);
    assert('lenient default: signature check notes unsigned',
      rLenient.checks.find(c => c.name === 'signature' && c.ok && /unsigned/.test(c.detail)) !== undefined);

    // (b) unsigned + requireSignature → fail on signature
    const rSig = await verifyBundle(fLenient, { requireSignature: true });
    assert('requireSignature: unsigned bundle fails', rSig.ok === false);
    assert('requireSignature: signature is the failing check',
      rSig.checks.find(c => c.name === 'signature' && c.ok === false) !== undefined);

    // (c) inferred policy + requirePolicyBinding → fail on policy binding
    const bInf = JSON.parse(JSON.stringify(baseBundle));
    bInf.attestation.policy.source = 'inferred';
    recomputeManifest(bInf);
    const fInf = path.join(dir, 'strict-inferred.json');
    fs.writeFileSync(fInf, JSON.stringify(bInf));
    assert('lenient: inferred policy still passes', (await verifyBundle(fInf)).ok === true);
    const rPol = await verifyBundle(fInf, { requirePolicyBinding: true });
    assert('requirePolicyBinding: inferred policy fails', rPol.ok === false);
    assert('requirePolicyBinding: policy binding is the failing check',
      rPol.checks.find(c => c.name === 'policy binding' && c.ok === false) !== undefined);

    // (d) missing git_state + requireGitState → fail on git state
    const bNoGit = JSON.parse(JSON.stringify(baseBundle));
    delete bNoGit.attestation.subject.git_state;
    recomputeManifest(bNoGit);
    const fNoGit = path.join(dir, 'strict-nogit.json');
    fs.writeFileSync(fNoGit, JSON.stringify(bNoGit));
    assert('lenient: missing git_state still passes', (await verifyBundle(fNoGit)).ok === true);
    const rGit = await verifyBundle(fNoGit, { requireGitState: true });
    assert('requireGitState: missing git_state fails', rGit.ok === false);
    assert('requireGitState: git state is the failing check',
      rGit.checks.find(c => c.name === 'git state matches chain' && c.ok === false) !== undefined);

    // (e) a fully signed, bound, git-stamped bundle passes the strict trifecta
    function jwt(claims) {
      const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
      return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
    }
    const attS = buildAttestation({ runId: RUN, logFile: chainFile, policyFile: polFile });
    const signStub = {
      attest(payload, payloadType) {
        return Promise.resolve({
          mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
          verificationMaterial: { tlogEntries: [{ logIndex: '7' }] },
          dsseEnvelope: { payload: payload.toString('base64'), payloadType },
        });
      },
    };
    const outS = await signAttestation(attS, { oidcToken: jwt({ sub: 'repo:o/r:ref:refs/heads/main' }), sigstoreModule: signStub });
    attS.signature = outS.signatureBlock;
    const signedStrict = buildBundle({ runId: RUN, logFile: chainFile, policyFile: polFile, attestation: attS, sigstoreBundle: outS.bundle });
    const fStrict = path.join(dir, 'strict-signed.json');
    fs.writeFileSync(fStrict, JSON.stringify(signedStrict));
    const rStrict = await verifyBundle(fStrict, {
      sigstoreModule: { verify: async () => true },
      requireSignature: true, requirePolicyBinding: true, requireGitState: true,
    });
    assert('strict: fully signed+bound+git bundle passes all requirements', rStrict.ok === true, JSON.stringify(rStrict.checks));
  }

  // cleanup + summary
  for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
  console.log(`\n${failed === 0 ? '✓' : '✗'} bundle: ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
