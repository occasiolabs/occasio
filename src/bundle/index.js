'use strict';

/**
 * occasio bundle — pack one run into a single, self-contained, portable
 * evidence file (`<run_id>.occasio.json`) that a third party verifies offline
 * with one command: `occasio verify <file>`.
 *
 * The bundle embeds everything verification needs, so it does NOT depend on
 * the producer's ~/.occasio chain or any absolute path:
 *   - attestation        the agent-attestation/v1 predicate (incl. subject.git_state from #1)
 *   - sigstore_bundle     the Sigstore Bundle when --sign is used (else null)
 *   - chain_slice         the run's hash-chained rows (verified in slice mode)
 *   - policy_snapshot     the exact policy.yml bytes the attestation commits to
 *   - manifest            sha256 of each embedded artifact + a single bundle_digest
 *
 * Format is plain JSON on purpose: zero new dependencies (no zip lib), trivially
 * diffable, and re-stringifies deterministically for hashing.
 *
 * Read-only over the chain/policy — never mutates either.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

const { loadRunSlice }     = require('../attest/run-slice');
const { buildAttestation } = require('../attest');
const { currentRunId }     = require('../models/events');

const BUNDLE_SCHEMA  = 'occasio-bundle/v1';
const DEFAULT_LOG    = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');
const DEFAULT_POLICY = path.join(os.homedir(), '.occasio', 'policy.yml');

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// Read the policy file's exact bytes (the attestation's policy.file_hash is a
// SHA-256 over these same bytes, so the snapshot lets a verifier re-bind the
// two without the original file).
function readPolicySnapshot(policyFile) {
  let text = null;
  try { text = fs.readFileSync(policyFile, 'utf8'); } catch { text = null; }
  return {
    path:   policyFile,
    text:   text,
    sha256: text === null ? null : sha256hex(text),
  };
}

/**
 * buildBundle({ runId, logFile, policyFile, attestation })
 *   → bundle object, or null when the run slice is empty.
 *
 * If `attestation` is passed (e.g. a freshly signed one), it is embedded as-is;
 * otherwise an unsigned attestation is built from the chain.
 */
function buildBundle({ runId, logFile, policyFile, attestation, sigstoreBundle } = {}) {
  if (!runId || typeof runId !== 'string') {
    throw new Error('buildBundle: runId is required');
  }
  const log = logFile    || DEFAULT_LOG;
  const pol = policyFile || DEFAULT_POLICY;

  const slice = loadRunSlice(log, runId);
  if (slice.event_count === 0) return null;

  const att = attestation || buildAttestation({ runId, logFile: log, policyFile: pol });
  if (!att) return null;

  const policySnapshot = readPolicySnapshot(pol);
  const chainSlice = slice.events;

  // Manifest hashes use JSON.stringify (not canonicalize): chain rows may carry
  // non-integer numbers (request-row cost/savings), which canonicalize rejects.
  // JSON.stringify round-trips deterministically — the verifier re-stringifies
  // the same parsed objects in the same insertion order.
  const attestationSha = sha256hex(JSON.stringify(att));
  const chainSliceSha  = sha256hex(JSON.stringify(chainSlice));
  const policySha      = policySnapshot.text === null ? null : policySnapshot.sha256;

  const manifest = {
    attestation_sha256: attestationSha,
    chain_slice_sha256: chainSliceSha,
    policy_sha256:      policySha,
    bundle_digest:      sha256hex(JSON.stringify({
      schema: BUNDLE_SCHEMA, run_id: runId,
      attestation_sha256: attestationSha,
      chain_slice_sha256: chainSliceSha,
      policy_sha256:      policySha,
    })),
  };

  return {
    schema:          BUNDLE_SCHEMA,
    run_id:          runId,
    attestation:     att,
    sigstore_bundle: sigstoreBundle || null,
    chain_slice:     chainSlice,
    policy_snapshot: policySnapshot,
    manifest,
    generated_at:    new Date().toISOString(),
  };
}

// ── CLI ──────────────────────────────────────────────────────────────────────

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
function bool(args, name) { return args.indexOf(name) >= 0; }

function usage() {
  return [
    'occasio bundle — pack one run into a single portable evidence file',
    '',
    'usage: occasio bundle [--run <id>] [--log <path>] [--policy <path>]',
    '                      [--out <file>] [--stdout]',
    '                      [--sign] [--sign-mode ci|token] [--oidc-token <jwt>]',
    '',
    'flags:',
    '  --run <id>         explicit run_id (default: currentRunId from session.json)',
    '  --log <path>       chain file (default: ~/.occasio/pipeline-events.jsonl)',
    '  --policy <path>    policy file (default: ~/.occasio/policy.yml)',
    '  --out <file>       output path (default: ./<run_id>.occasio.json)',
    '  --stdout           print bundle JSON to stdout instead of writing a file',
    '  --sign             Sigstore-sign the embedded attestation (needs OIDC env or --oidc-token)',
    '',
    'verify with: occasio verify <file>',
    '',
    'note: chain_slice embeds absolute file paths from the run. Intended for',
    'internal audit; review before public distribution.',
    '',
  ].join('\n');
}

async function runCli(args) {
  args = args || [];
  if (bool(args, '--help') || bool(args, '-h')) {
    process.stdout.write(usage());
    return 0;
  }

  const runId = flag(args, '--run') || currentRunId();
  if (!runId) {
    process.stderr.write('[Occasio] bundle: no run_id available. Pass --run <id>.\n');
    return 2;
  }
  const logFile    = flag(args, '--log')    || DEFAULT_LOG;
  const policyFile = flag(args, '--policy') || DEFAULT_POLICY;
  const out        = flag(args, '--out')    || path.resolve(process.cwd(), `${runId}.occasio.json`);
  const toStdout   = bool(args, '--stdout');
  const sign       = bool(args, '--sign');
  const signMode   = flag(args, '--sign-mode');
  const oidcToken  = flag(args, '--oidc-token');

  // Build (and optionally sign) the attestation first, so the signature is
  // embedded inside the bundle's attestation and covered by the manifest hash.
  let attestation, sigstoreBundle = null;
  try {
    attestation = buildAttestation({ runId, logFile, policyFile });
  } catch (e) {
    process.stderr.write(`[Occasio] bundle: ${e.message}\n`);
    return 2;
  }
  if (!attestation) {
    process.stderr.write(`[Occasio] bundle: no events found for run_id ${runId}\n  Checked: ${logFile}\n`);
    return 1;
  }

  if (sign) {
    try {
      const { signAttestation } = require('../attest/sign');
      const { bundle, signatureBlock } = await signAttestation(attestation, { oidcToken, signMode });
      attestation.signature = signatureBlock;
      sigstoreBundle = bundle;
    } catch (e) {
      process.stderr.write(`[Occasio] bundle: signing failed: ${e.message}\n`);
      return 2;
    }
  }

  const bundle = buildBundle({ runId, logFile, policyFile, attestation, sigstoreBundle });
  if (!bundle) {
    process.stderr.write(`[Occasio] bundle: no events found for run_id ${runId}\n`);
    return 1;
  }

  const json = JSON.stringify(bundle, null, 2);
  if (toStdout) { process.stdout.write(json + '\n'); return 0; }
  try {
    fs.writeFileSync(out, json + '\n', 'utf8');
  } catch (e) {
    process.stderr.write(`[Occasio] bundle: cannot write ${out}: ${e.message}\n`);
    return 2;
  }
  process.stdout.write(`✓ Wrote evidence bundle: ${out}\n`);
  process.stdout.write(
    `  run_id: ${runId}  ·  rows: ${bundle.chain_slice.length}` +
    `  ·  signed: ${sigstoreBundle ? 'yes' : 'no'}` +
    `  ·  digest: ${bundle.manifest.bundle_digest.slice(0, 16)}…\n`
  );
  process.stdout.write(`  verify:  occasio verify ${out}\n`);
  return 0;
}

module.exports = { buildBundle, runCli, BUNDLE_SCHEMA };
