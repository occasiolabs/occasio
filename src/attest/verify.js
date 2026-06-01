'use strict';

/**
 * verify.js — re-verify a signed Occasio Agent Attestation end-to-end.
 *
 * Three independent checks, in order — each must pass:
 *   1. Sigstore bundle is cryptographically valid against Fulcio/Rekor.
 *   2. The DSSE payload inside the bundle parses as an in-toto Statement v1
 *      whose `predicate` field, when re-stringified, matches the attestation
 *      JSON we hold (modulo the `signature` field, which is metadata-only and
 *      excluded before comparison).
 *   3. The audit chain (`chain_file` in the attestation) verifies via the
 *      same walker that `occasio audit verify` uses, AND the
 *      `first_hash`/`last_hash` claimed in the attestation exist in that
 *      chain in the correct order.
 *
 * Returns:
 *   { ok, checks: [{ name, ok, detail }], identity, rekor_entry }
 *
 * Phase 1 keeps the verifier strict: any failure → ok:false. Callers (CLI,
 * View-Evidence page) render the `checks` list verbatim — no aggregation.
 */

const fs   = require('fs');
const path = require('path');

const { verifyFile } = require('../audit/verifier');
const { DSSE_PAYLOAD_TYPE, PREDICATE_TYPE } = require('./sign');
const { canonicalize } = require('./canonicalize');
const { loadRunSlice } = require('./run-slice');
const { deriveGitState } = require('./index');

/**
 * Verify a saved attestation pair.
 *
 *   attestationPath — path to the predicate JSON (Phase-0 / Phase-1 shape)
 *   bundlePath      — path to the Sigstore Bundle sidecar
 *   ctx.sigstoreModule  — DI for tests
 */
async function verifyAttestation(attestationPath, bundlePath, ctx = {}) {
  const checks = [];
  let identity = null, rekor_entry = null;

  // Load both files up front; surface any I/O failure as the first check.
  let attestation, bundle;
  try {
    attestation = JSON.parse(fs.readFileSync(attestationPath, 'utf8'));
  } catch (e) {
    checks.push({ name: 'read attestation', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  } catch (e) {
    checks.push({ name: 'read bundle', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }

  // ── 1. Sigstore signature ───────────────────────────────────────────────
  try {
    const sigstore = ctx.sigstoreModule || require('sigstore');
    // sigstore.verify with no data arg verifies the bundle's embedded payload.
    await sigstore.verify(bundle);
    checks.push({ name: 'sigstore signature', ok: true });
    // Surface the Fulcio identity for human display (not for trust decisions —
    // sigstore.verify already enforced the cert chain).
    rekor_entry = (() => {
      try { return bundle.verificationMaterial?.tlogEntries?.[0]?.logIndex || null; }
      catch { return null; }
    })();
    identity = attestation?.signature?.identity || null;
  } catch (e) {
    checks.push({ name: 'sigstore signature', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }

  // ── 2. DSSE payload ↔ attestation predicate equivalence ────────────────
  try {
    const env = bundle.dsseEnvelope;
    if (!env || !env.payload) throw new Error('bundle missing dsseEnvelope.payload');
    if (env.payloadType !== DSSE_PAYLOAD_TYPE) {
      throw new Error(`unexpected payloadType: ${env.payloadType}`);
    }
    const stmtJson = Buffer.from(env.payload, 'base64').toString('utf8');
    const stmt = JSON.parse(stmtJson);

    if (stmt.predicateType !== PREDICATE_TYPE) {
      throw new Error(`unexpected predicateType: ${stmt.predicateType}`);
    }
    // Recompute what we WOULD have signed for this attestation, ignoring the
    // signature metadata field. Canonical JSON on both sides — any key-order
    // or whitespace divergence between runtimes/versions becomes invisible,
    // and only real semantic mismatches surface.
    const { signature: _omit, ...predicateExpected } = attestation;
    if (canonicalize(stmt.predicate) !== canonicalize(predicateExpected)) {
      throw new Error('attestation predicate differs from DSSE payload predicate');
    }
    checks.push({ name: 'bundle payload matches attestation', ok: true });
  } catch (e) {
    checks.push({ name: 'bundle payload matches attestation', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }

  // ── 3. Audit chain integrity + hash commitments ─────────────────────────
  try {
    const chainFile = attestation?.audit_chain?.chain_file;
    if (!chainFile) throw new Error('attestation missing audit_chain.chain_file');
    if (!fs.existsSync(chainFile)) throw new Error(`chain file not found: ${chainFile}`);

    const ver = verifyFile(chainFile);
    if (!ver.ok) {
      throw new Error(`chain broken at line(s): ${(ver.errors || []).map(e => e.line).join(', ')}`);
    }

    // Confirm the claimed first/last hashes actually appear in the chain in
    // the right relative order. Walk lines once; reuse existing readJsonl path.
    const lines = fs.readFileSync(chainFile, 'utf8').split('\n').filter(Boolean);
    let firstIdx = -1, lastIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      let row;
      try { row = JSON.parse(lines[i]); } catch { continue; }
      if (row.hash === attestation.audit_chain.first_hash && firstIdx === -1) firstIdx = i;
      if (row.hash === attestation.audit_chain.last_hash) lastIdx = i;
    }
    if (firstIdx === -1) throw new Error(`first_hash not found in chain`);
    if (lastIdx  === -1) throw new Error(`last_hash not found in chain`);
    if (lastIdx < firstIdx) throw new Error(`last_hash precedes first_hash in chain`);

    checks.push({ name: 'audit chain integrity', ok: true,
      detail: `chain_length=${ver.chained}, slice rows ${firstIdx + 1}..${lastIdx + 1}` });
  } catch (e) {
    checks.push({ name: 'audit chain integrity', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }

  // ── 4. git state matches chain (only when chain-sourced git_state claimed) ─
  // Binds the attestation's repo claim to the hash-protected git_state rows:
  // re-derive git_state straight from the chain and require byte-equality with
  // what the attestation declares. Skipped entirely for attestations that
  // carry no chain-sourced subject.git_state (backward compatible).
  try {
    const claimed = attestation?.subject?.git_state;
    if (claimed && claimed.provenance === 'chain') {
      const chainFile = attestation?.audit_chain?.chain_file;
      const runId     = attestation?.subject?.run_id;
      if (!chainFile || !runId) {
        throw new Error('missing chain_file or run_id for git-state cross-check');
      }
      const slice = loadRunSlice(chainFile, runId);
      const rederived = deriveGitState(slice.events);
      if (!rederived) {
        throw new Error('attestation claims chain-sourced git_state but chain has no git_state rows');
      }
      if (canonicalize(rederived) !== canonicalize(claimed)) {
        throw new Error('subject.git_state differs from the git_state recorded in the chain');
      }
      const fp = (s) => (s && s.head) ? s.head.slice(0, 12) : (s ? 'no-head' : '—');
      checks.push({ name: 'git state matches chain', ok: true,
        detail: `run_start ${fp(rederived.run_start)} · run_end ${fp(rederived.run_end)}` });
    }
  } catch (e) {
    checks.push({ name: 'git state matches chain', ok: false, detail: e.message });
    return { ok: false, checks, identity, rekor_entry };
  }

  return {
    ok: checks.every(c => c.ok),
    checks, identity, rekor_entry,
  };
}

// ── CLI ──────────────────────────────────────────────────────────────────────

async function runAttestVerifyCli(args) {
  args = args || [];
  if (args.length === 0 || args[0].startsWith('-') && args[0] !== '--help') {
    process.stderr.write('Usage: occasio attest verify <attestation.json> [--bundle <path>]\n');
    process.exit(2);
  }
  if (args[0] === '--help' || args[0] === '-h') {
    process.stdout.write(
      'Usage: occasio attest verify <attestation.json> [--bundle <path>]\n' +
      '\n' +
      'Default bundle path: <attestation>.sigstore.json (sidecar convention).\n'
    );
    return;
  }
  const attestationPath = path.resolve(args[0]);
  const bundleIdx = args.indexOf('--bundle');
  const bundlePath = bundleIdx >= 0
    ? path.resolve(args[bundleIdx + 1])
    : attestationPath.replace(/\.json$/i, '') + '.sigstore.json';

  const col = {
    g: s => `\x1b[32m${s}\x1b[0m`,
    r: s => `\x1b[31m${s}\x1b[0m`,
    d: s => `\x1b[2m${s}\x1b[0m`,
    b: s => `\x1b[1m${s}\x1b[0m`,
  };

  process.stdout.write(`${col.b('Verifying')} ${attestationPath}\n`);
  process.stdout.write(`  bundle: ${bundlePath}\n\n`);

  let result;
  try {
    result = await verifyAttestation(attestationPath, bundlePath);
  } catch (e) {
    process.stderr.write(`${col.r('✗')} verify crashed: ${e.message}\n`);
    process.exit(2);
  }

  for (const c of result.checks) {
    const mark = c.ok ? col.g('✓') : col.r('✗');
    process.stdout.write(`  ${mark} ${c.name}`);
    if (c.detail) process.stdout.write(`  ${col.d(c.detail)}`);
    process.stdout.write('\n');
  }
  if (result.identity)    process.stdout.write(`\n  ${col.d('identity:')}    ${result.identity}\n`);
  if (result.rekor_entry) process.stdout.write(`  ${col.d('rekor index:')} ${result.rekor_entry}\n`);

  process.exit(result.ok ? 0 : 1);
}

module.exports = { verifyAttestation, runAttestVerifyCli };
