'use strict';

/**
 * occasio verify <bundle> — verify a portable evidence bundle offline.
 *
 * Six independent checks, in order — each must pass (fail-stop). Everything is
 * verified against data embedded IN the bundle; the producer's absolute
 * chain_file path is never read.
 *
 *   1. read + schema           parses, schema tag + required keys present
 *   2. manifest integrity      embedded artifacts hash to the manifest
 *   3. chain slice integrity   slice-mode chain walk, anchored to attestation
 *   4. policy binding          policy snapshot bytes == attestation.policy.file_hash
 *   5. git state vs chain      attestation.subject.git_state == deriveGitState(slice)  (#1, portable)
 *   6. signature (optional)    Sigstore bundle valid + DSSE predicate matches attestation
 *
 * Returns { ok, checks:[{name,ok,detail}] }. CLI exits non-zero on failure, so
 * `occasio verify bundle.occasio.json` is a drop-in CI gate.
 *
 * Strictness (lenient by default; opt in via ctx for audit-grade evidence):
 *   ctx.requireSignature      — an unsigned bundle fails instead of passing #6
 *   ctx.requirePolicyBinding  — policy.source=inferred / no snapshot fails #4
 *   ctx.requireGitState       — a missing chain-sourced git_state fails #5
 * The CLI maps --strict to all three (plus granular --require-* flags).
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const { verifySlice }      = require('../audit/verifier');
const { deriveGitState }   = require('../attest');
const { canonicalize }     = require('../attest/canonicalize');
const { DSSE_PAYLOAD_TYPE, PREDICATE_TYPE } = require('../attest/sign');

const BUNDLE_SCHEMA = 'occasio-bundle/v1';

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

async function verifyBundle(bundlePath, ctx = {}) {
  const checks = [];
  const fail = (name, detail) => {
    checks.push({ name, ok: false, detail });
    return { ok: false, checks };
  };

  // ── 1. read + schema ────────────────────────────────────────────────────
  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  } catch (e) {
    return fail('read bundle', e.message);
  }
  {
    if (bundle.schema !== BUNDLE_SCHEMA) {
      return fail('schema', `unexpected schema (want ${BUNDLE_SCHEMA}, got ${bundle.schema})`);
    }
    const required = ['run_id', 'attestation', 'chain_slice', 'policy_snapshot', 'manifest'];
    const missing = required.filter(k => !Object.prototype.hasOwnProperty.call(bundle, k));
    if (missing.length) return fail('schema', `missing keys: ${missing.join(', ')}`);
    if (!Array.isArray(bundle.chain_slice) || bundle.chain_slice.length === 0) {
      return fail('schema', 'chain_slice is empty');
    }
    checks.push({ name: 'schema', ok: true, detail: BUNDLE_SCHEMA });
  }

  const att = bundle.attestation;
  const man = bundle.manifest || {};

  // ── 2. manifest integrity ───────────────────────────────────────────────
  try {
    const attSha   = sha256hex(JSON.stringify(att));
    const sliceSha = sha256hex(JSON.stringify(bundle.chain_slice));
    const polText  = bundle.policy_snapshot && bundle.policy_snapshot.text;
    const polSha   = (polText === null || polText === undefined) ? null : sha256hex(polText);

    if (attSha !== man.attestation_sha256)   throw new Error('attestation hash mismatch (bundle was modified)');
    if (sliceSha !== man.chain_slice_sha256)  throw new Error('chain_slice hash mismatch (bundle was modified)');
    if (polSha !== man.policy_sha256)         throw new Error('policy_snapshot hash mismatch (bundle was modified)');

    const expectDigest = sha256hex(JSON.stringify({
      schema: BUNDLE_SCHEMA, run_id: bundle.run_id,
      attestation_sha256: man.attestation_sha256,
      chain_slice_sha256: man.chain_slice_sha256,
      policy_sha256:      man.policy_sha256,
    }));
    if (expectDigest !== man.bundle_digest)   throw new Error('bundle_digest mismatch');
    checks.push({ name: 'manifest integrity', ok: true, detail: `digest ${man.bundle_digest.slice(0, 16)}…` });
  } catch (e) {
    return fail('manifest integrity', e.message);
  }

  // ── 3. chain slice integrity (slice mode) ───────────────────────────────
  try {
    const res = verifySlice(bundle.chain_slice);
    if (!res.ok) {
      throw new Error(`slice broken: ${(res.errors || []).map(x => `row ${x.index}: ${x.detail}`).join('; ')}`);
    }
    const ac = att && att.audit_chain;
    if (!ac) throw new Error('attestation missing audit_chain');
    if (res.firstHash !== ac.first_hash) throw new Error('slice first_hash does not match attestation');
    if (res.lastHash  !== ac.last_hash)  throw new Error('slice last_hash does not match attestation');
    checks.push({ name: 'chain slice integrity', ok: true, detail: `${res.chained} rows, anchored to attestation` });
  } catch (e) {
    return fail('chain slice integrity', e.message);
  }

  // ── 4. policy binding ────────────────────────────────────────────────────
  try {
    const pol = att && att.policy;
    const snap = bundle.policy_snapshot;
    if (pol && pol.source !== 'inferred' && snap && snap.text !== null && snap.text !== undefined) {
      const snapSha = sha256hex(snap.text);
      if (snapSha !== pol.file_hash) {
        throw new Error('policy snapshot bytes do not match attestation.policy.file_hash (policy swap)');
      }
      checks.push({ name: 'policy binding', ok: true, detail: `policy ${snapSha.slice(0, 12)}…` });
    } else if (ctx.requirePolicyBinding) {
      return fail('policy binding',
        pol && pol.source === 'inferred'
          ? 'required (--require-policy-binding) but policy.source=inferred — no committed policy bytes to bind'
          : 'required (--require-policy-binding) but bundle carries no policy snapshot');
    } else {
      checks.push({ name: 'policy binding', ok: true,
        detail: pol && pol.source === 'inferred' ? 'skipped (policy.source=inferred — weaker evidence)' : 'skipped (no policy snapshot)' });
    }
  } catch (e) {
    return fail('policy binding', e.message);
  }

  // ── 5. git state vs chain (reuses #1, now portable) ──────────────────────
  try {
    const claimed = att && att.subject && att.subject.git_state;
    if (claimed && claimed.provenance === 'chain') {
      const rederived = deriveGitState(bundle.chain_slice);
      if (!rederived) throw new Error('attestation claims chain-sourced git_state but slice has no git_state rows');
      if (canonicalize(rederived) !== canonicalize(claimed)) {
        throw new Error('subject.git_state differs from git_state recorded in the embedded slice');
      }
      const fp = (s) => (s && s.head) ? s.head.slice(0, 12) : (s ? 'no-head' : '—');
      checks.push({ name: 'git state matches chain', ok: true,
        detail: `run_start ${fp(rederived.run_start)} · run_end ${fp(rederived.run_end)}` });
    } else if (ctx.requireGitState) {
      return fail('git state matches chain',
        'required (--require-git-state) but attestation carries no chain-sourced git_state');
    }
  } catch (e) {
    return fail('git state matches chain', e.message);
  }

  // ── 6. signature (optional) ──────────────────────────────────────────────
  if (bundle.sigstore_bundle) {
    try {
      const sigstore = ctx.sigstoreModule || require('sigstore');
      await sigstore.verify(bundle.sigstore_bundle);

      const env = bundle.sigstore_bundle.dsseEnvelope;
      if (!env || !env.payload) throw new Error('sigstore_bundle missing dsseEnvelope.payload');
      if (env.payloadType !== DSSE_PAYLOAD_TYPE) {
        throw new Error(`unexpected payloadType: ${env.payloadType}`);
      }
      const stmt = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
      if (stmt.predicateType !== PREDICATE_TYPE) {
        throw new Error(`unexpected predicateType: ${stmt.predicateType}`);
      }
      const { signature: _omit, ...predicateExpected } = att;
      if (canonicalize(stmt.predicate) !== canonicalize(predicateExpected)) {
        throw new Error('signed predicate differs from embedded attestation');
      }
      checks.push({ name: 'signature', ok: true, detail: att.signature && att.signature.identity ? att.signature.identity : 'sigstore-verified' });
    } catch (e) {
      return fail('signature', e.message);
    }
  } else if (ctx.requireSignature) {
    return fail('signature', 'required (--require-signature) but bundle is unsigned');
  } else {
    checks.push({ name: 'signature', ok: true, detail: 'unsigned bundle (no signature to verify)' });
  }

  return { ok: checks.every(c => c.ok), checks };
}

// ── CLI ──────────────────────────────────────────────────────────────────────

async function runCli(args) {
  args = args || [];
  const wantsHelp  = args.includes('--help') || args.includes('-h');
  const flags      = new Set(args.filter(a => a.startsWith('-')));
  const positional = args.filter(a => !a.startsWith('-'));

  if (wantsHelp || positional.length === 0) {
    process.stdout.write(
      'Usage: occasio verify <bundle.occasio.json> [--strict]\n\n' +
      'Verifies a portable evidence bundle offline (schema, manifest, chain\n' +
      'slice, policy binding, git state, and signature if present).\n' +
      'Exits non-zero on any failure — usable directly as a CI gate.\n\n' +
      'Strictness (default: lenient — unsigned / inferred-policy / no-git\n' +
      'bundles still pass, for quick local checks):\n' +
      '  --strict                  require signature AND policy binding AND git state\n' +
      '  --require-signature       fail if the bundle is unsigned\n' +
      '  --require-policy-binding  fail if policy.source=inferred or no policy snapshot\n' +
      '  --require-git-state       fail if no chain-sourced git_state is present\n'
    );
    return wantsHelp ? 0 : 2;
  }

  const strict = flags.has('--strict');
  const reqCtx = {
    requireSignature:     strict || flags.has('--require-signature'),
    requirePolicyBinding: strict || flags.has('--require-policy-binding'),
    requireGitState:      strict || flags.has('--require-git-state'),
  };

  const col = {
    g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`,
    d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
  };
  const bundlePath = path.resolve(positional[0]);
  process.stdout.write(`${col.b('Verifying')} ${bundlePath}${strict ? col.d(' (strict)') : ''}\n\n`);

  let result;
  try {
    result = await verifyBundle(bundlePath, reqCtx);
  } catch (e) {
    process.stderr.write(`${col.r('✗')} verify crashed: ${e.message}\n`);
    return 2;
  }

  for (const c of result.checks) {
    const mark = c.ok ? col.g('✓') : col.r('✗');
    process.stdout.write(`  ${mark} ${c.name}`);
    if (c.detail) process.stdout.write(`  ${col.d(c.detail)}`);
    process.stdout.write('\n');
  }
  process.stdout.write('\n' + (result.ok ? col.g('✓ bundle verified') : col.r('✗ bundle verification failed')) + '\n');
  return result.ok ? 0 : 1;
}

module.exports = { verifyBundle, runCli, BUNDLE_SCHEMA };
