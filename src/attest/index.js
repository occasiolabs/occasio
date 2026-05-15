'use strict';

/**
 * occasio attest — produce an AI-Agent Behavioral Attestation (v1) for a
 * single Occasio session (run_id). The output is a self-contained JSON file
 * that *commits* (via first_hash/last_hash) to a contiguous slice of the
 * tamper-evident audit chain and summarises what happened during the run.
 *
 * Phase 0: unsigned attestations (`signature: null`). Phase 1 will wrap this
 * object in an in-toto Statement envelope and Sigstore-sign it.
 *
 * Usage:
 *   occasio attest --run-id <uuid> [--out <path>] [--log <path>]
 *                     [--policy <path>] [--stdout]
 *
 * Reads (all read-only — never mutates the chain):
 *   ~/.occasio/pipeline-events.jsonl   (or --log)
 *   ~/.occasio/policy.yml              (or --policy)
 *
 * Writes:
 *   ./attestation.json                    (or --out, or stdout with --stdout)
 *
 * Exit codes:
 *   0 — success
 *   1 — no events found for the given run_id (user error)
 *   2 — invalid arguments / I/O error
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { loadRunSlice } = require('./run-slice');
const { computePolicyHash } = require('../policy/loader');

const SCHEMA_VERSION = '1.0.0';
const PREDICATE_TYPE =
  'https://github.com/occasiolabs/occasio/spec/agent-attestation/v1';
const GENESIS = '0'.repeat(64);
const VERIFIER_URL =
  'https://github.com/occasiolabs/occasio/blob/main/docs/audit_walker.py';

const DEFAULT_LOG    = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');
const DEFAULT_POLICY = path.join(os.homedir(), '.occasio', 'policy.yml');

// ── helpers ──────────────────────────────────────────────────────────────────

function isoSeconds(a, b) {
  const ai = new Date(a).getTime();
  const bi = new Date(b).getTime();
  if (!Number.isFinite(ai) || !Number.isFinite(bi)) return 0;
  return Math.max(0, Math.round((bi - ai) / 1000));
}

function offsetSeconds(start, then) {
  const ai = new Date(start).getTime();
  const bi = new Date(then).getTime();
  if (!Number.isFinite(ai) || !Number.isFinite(bi)) return 0;
  return Math.max(0, Math.round((bi - ai) / 1000));
}

// Best-effort rules digest from a parsed policy.yml. We deliberately do NOT
// require ../policy/loader.load() (which mutates module-level cache + fires
// change listeners) — `attest` is a pure read.
function readPolicyRulesDigest(policyFile) {
  let text;
  try { text = fs.readFileSync(policyFile, 'utf8'); }
  catch (e) {
    // Loud-fail: a missing/unreadable policy file is operationally significant
    // for an attestation (the rules_digest in the output will be defaults, not
    // the file's real contents). Surface it on stderr; the caller still falls
    // back to schema defaults so attestation generation does not abort.
    // ENOENT is the common, expected case when no user policy exists; demote
    // it to a single-line note. Anything else (EACCES, EIO, etc.) is louder.
    if (e && e.code === 'ENOENT') {
      process.stderr.write(`[Occasio] attest: no policy file at ${policyFile} — using schema defaults for rules_digest\n`);
    } else {
      process.stderr.write(`[Occasio] attest: cannot read policy ${policyFile}: ${e.message} — rules_digest will use schema defaults\n`);
    }
    return null;
  }

  // Tiny line-level scan — full parsing is overkill for a digest. Counts only.
  let denyPaths = 0, denyPatterns = 0, blockSecrets = null;
  let inDenyPaths = false, inDenyPatterns = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '');     // strip comments
    if (/^\s*deny_paths\s*:/.test(line))   { inDenyPaths = true; inDenyPatterns = false; continue; }
    if (/^\s*allow_paths\s*:/.test(line))  { inDenyPaths = false; inDenyPatterns = false; continue; }
    if (/^\s*deny_patterns\s*:/.test(line)){ inDenyPatterns = true; inDenyPaths = false; continue; }
    if (/^\s*tools\s*:/.test(line))        { inDenyPaths = false; inDenyPatterns = false; continue; }

    if (/^\s*block_secrets_in_tool_results\s*:\s*(true|false)\b/.test(line)) {
      blockSecrets = /true/.test(line);
    }

    if (inDenyPaths && /^\s*-\s+\S/.test(line))    denyPaths++;
    if (inDenyPatterns && /^\s{2,}\S+\s*:/.test(line)) denyPatterns++;
  }
  return {
    deny_paths_count:    denyPaths,
    deny_patterns_count: denyPatterns,
    block_secrets:       blockSecrets === null ? true : blockSecrets,  // schema default
  };
}

// Extract platform + model from the slice. Most rows don't carry model directly;
// model is best-effort sourced from the first row that has one.
function pickAgentMeta(events) {
  let platform = null, model = null, session_id = null;
  for (const e of events) {
    if (!platform && typeof e.agent === 'string' && e.agent !== 'occasio') platform = e.agent;
    if (!model && typeof e.model === 'string') model = e.model;
    if (!session_id && typeof e.session_id === 'string') session_id = e.session_id;
    if (platform && model && session_id) break;
  }
  return {
    platform:   platform || 'claude-code',   // adapter default
    model:      model || null,
    session_id: session_id || null,
  };
}

function summariseExecution(events, startedAt) {
  const summary = {
    tool_calls: 0, local: 0, passed: 0, blocked: 0,
    transformed: 0, secrets_redacted: 0,
    blocked_events: [],
  };
  for (const e of events) {
    if (e.kind !== 'tool_call') continue;
    summary.tool_calls++;
    switch (e.action) {
      case 'LOCAL':     summary.local++; break;
      case 'PASS':      summary.passed++; break;
      case 'BLOCK':     summary.blocked++; break;
      case 'TRANSFORM': summary.transformed++; break;
    }
    if (typeof e.secrets_redacted === 'number' && e.secrets_redacted > 0) {
      summary.secrets_redacted += e.secrets_redacted;
    }
    if (e.action === 'BLOCK') {
      const target = (e.tool_inputs && (e.tool_inputs.path || e.tool_inputs.pattern)) || null;
      summary.blocked_events.push({
        tool:        e.tool_name || 'unknown',
        target,
        rule:        e.reason || 'unknown',
        at_offset_s: offsetSeconds(startedAt, e.ts || e.iso),
      });
    }
  }
  return summary;
}

// ── public API ───────────────────────────────────────────────────────────────

/**
 * buildAttestation({ runId, logFile, policyFile, gitCommit, filesChanged })
 *   → attestation object.
 *
 * `gitCommit` / `filesChanged` are optional v1.1 subject extensions —
 * populated by the GitHub Action (Phase 2) to bind a run to a specific
 * commit. Schema already permits both (declared in v1).
 *
 * Throws if runId is missing. Returns null if no events match the run_id.
 */
function buildAttestation({ runId, logFile, policyFile, gitCommit, filesChanged } = {}) {
  if (!runId || typeof runId !== 'string') {
    throw new Error('buildAttestation: runId is required');
  }
  const log = logFile  || DEFAULT_LOG;
  const pol = policyFile || DEFAULT_POLICY;

  const slice = loadRunSlice(log, runId);
  if (slice.event_count === 0) return null;

  // Look for a policy_loaded row inside the slice — it tells us exactly which
  // policy hash was active during the run. Fall back to the file's current
  // hash if no such row exists.
  let polHash = null, polPath = null, polSource = 'unknown', polVersion = null;
  for (const e of slice.events) {
    if (e.kind === 'policy_loaded' && e.tool_inputs) {
      polHash    = e.tool_inputs.policy_hash || polHash;
      polPath    = e.tool_inputs.policy_path || polPath;
      polVersion = (typeof e.tool_inputs.version === 'number') ? e.tool_inputs.version : polVersion;
      polSource  = e.policy_source || (polPath ? 'user' : 'default');
      break;
    }
  }
  if (!polHash) {
    // No policy_loaded row inside this run slice — we cannot prove which
    // policy was active during the run. Mark the source as 'inferred' so a
    // downstream verifier knows the hash came from the file's *current*
    // bytes (which may have been edited after the run ended).
    polHash   = computePolicyHash(pol);
    polPath   = pol;
    polSource = 'inferred';
  }

  const agent = pickAgentMeta(slice.events);
  const first = slice.events[0];
  const last  = slice.events[slice.events.length - 1];
  const startedAt = first.ts || first.iso || new Date().toISOString();
  const endedAt   = last.ts  || last.iso  || startedAt;

  return {
    schema_version: SCHEMA_VERSION,
    predicate_type: PREDICATE_TYPE,
    subject: Object.assign(
      { run_id: runId },
      (gitCommit && typeof gitCommit === 'string') ? { git_commit: gitCommit } : {},
      (Array.isArray(filesChanged) && filesChanged.length) ? { files_changed: filesChanged.slice() } : {}
    ),
    agent: {
      platform:    agent.platform,
      model:       agent.model,
      session_id:  agent.session_id,
      started_at:  startedAt,
      ended_at:    endedAt,
      wall_time_s: isoSeconds(startedAt, endedAt),
    },
    policy: {
      file_hash:    polHash,
      file_path:    polPath,
      source:       polSource,
      version:      polVersion,
      rules_digest: readPolicyRulesDigest(pol) || {
        deny_paths_count: 0, deny_patterns_count: 0, block_secrets: true,
      },
    },
    execution_summary: summariseExecution(slice.events, startedAt),
    audit_chain: {
      genesis:      GENESIS,
      first_hash:   slice.first_hash,
      last_hash:    slice.last_hash,
      event_count:  slice.event_count,
      chain_file:   log,
      verifier_url: VERIFIER_URL,
    },
    signature:    null,
    generated_at: new Date().toISOString(),
  };
}

// ── CLI ──────────────────────────────────────────────────────────────────────

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
function bool(args, name) { return args.indexOf(name) >= 0; }

function runAttestCli(args) {
  args = args || [];

  // Subcommand: `occasio attest verify <file>` → delegate.
  if (args[0] === 'verify') {
    const { runAttestVerifyCli } = require('./verify');
    return runAttestVerifyCli(args.slice(1)).catch(e => {
      process.stderr.write(`[Occasio] attest verify: ${e.message}\n`);
      process.exit(2);
    });
  }

  if (bool(args, '--help') || bool(args, '-h')) {
    process.stdout.write(
      'Usage:\n' +
      '  occasio attest --run-id <uuid> [--out <path>] [--log <path>] [--policy <path>] [--stdout]\n' +
      '                    [--sign] [--sign-mode ci|token] [--oidc-token <jwt>] [--bundle-out <path>]\n' +
      '                    [--git-commit <sha>] [--files-changed <a,b,c>]\n' +
      '  occasio attest verify <attestation.json> [--bundle <path>]\n'
    );
    return;
  }

  const runId  = flag(args, '--run-id');
  if (!runId) {
    process.stderr.write('[Occasio] attest: --run-id <uuid> is required\n');
    process.exit(2);
  }
  const logFile    = flag(args, '--log')    || DEFAULT_LOG;
  const policyFile = flag(args, '--policy') || DEFAULT_POLICY;
  const out        = flag(args, '--out')    || path.resolve(process.cwd(), 'attestation.json');
  const toStdout   = bool(args, '--stdout');
  const sign       = bool(args, '--sign');
  const signMode   = flag(args, '--sign-mode');     // 'ci' | 'token' | undefined
  const oidcToken  = flag(args, '--oidc-token');    // explicit JWT (token-mode)
  const bundleOut  = flag(args, '--bundle-out')
                     || out.replace(/\.json$/i, '') + '.sigstore.json';
  const gitCommit  = flag(args, '--git-commit');
  const filesRaw   = flag(args, '--files-changed');
  const filesChanged = filesRaw
    ? filesRaw.split(',').map(s => s.trim()).filter(Boolean)
    : undefined;

  let attestation;
  try {
    attestation = buildAttestation({ runId, logFile, policyFile, gitCommit, filesChanged });
  } catch (e) {
    process.stderr.write(`[Occasio] attest: ${e.message}\n`);
    process.exit(2);
  }
  if (!attestation) {
    process.stderr.write(`[Occasio] attest: no events found for run_id ${runId}\n`);
    process.stderr.write(`  Checked: ${logFile}\n`);
    process.exit(1);
  }

  if (!sign) {
    emitUnsigned(attestation, out, toStdout, runId);
    return;
  }

  // Signing path — async. Lazy-require sign.js to keep cold-start cheap.
  const { signAttestation } = require('./sign');
  return signAttestation(attestation, { oidcToken, signMode })
    .then(({ bundle, signatureBlock }) => {
      attestation.signature = signatureBlock;
      const json = JSON.stringify(attestation, null, 2);
      if (toStdout) {
        process.stdout.write(json + '\n');
        return;
      }
      fs.writeFileSync(out,       json + '\n', 'utf8');
      fs.writeFileSync(bundleOut, JSON.stringify(bundle, null, 2) + '\n', 'utf8');
      process.stdout.write(`✓ Wrote signed attestation: ${out}\n`);
      process.stdout.write(`  bundle:    ${bundleOut}\n`);
      process.stdout.write(
        `  run_id: ${runId}  ·  events: ${attestation.audit_chain.event_count}` +
        `  ·  blocked: ${attestation.execution_summary.blocked}` +
        `  ·  secrets_redacted: ${attestation.execution_summary.secrets_redacted}\n`
      );
      process.stdout.write(`  identity:  ${signatureBlock.identity}\n`);
      if (signatureBlock.rekor_entry) process.stdout.write(`  rekor:     ${signatureBlock.rekor_entry}\n`);
    })
    .catch(e => {
      process.stderr.write(`[Occasio] attest: signing failed: ${e.message}\n`);
      process.exit(2);
    });
}

function emitUnsigned(attestation, out, toStdout, runId) {
  const json = JSON.stringify(attestation, null, 2);
  if (toStdout) { process.stdout.write(json + '\n'); return; }
  try {
    fs.writeFileSync(out, json + '\n', 'utf8');
    process.stdout.write(`✓ Wrote attestation: ${out}\n`);
    process.stdout.write(
      `  run_id: ${runId}  ·  events: ${attestation.audit_chain.event_count}` +
      `  ·  blocked: ${attestation.execution_summary.blocked}` +
      `  ·  secrets_redacted: ${attestation.execution_summary.secrets_redacted}\n`
    );
    process.stdout.write('  signature: null  ·  use --sign to Sigstore-sign\n');
  } catch (e) {
    process.stderr.write(`[Occasio] attest: cannot write ${out}: ${e.message}\n`);
    process.exit(2);
  }
}

module.exports = {
  buildAttestation,
  runAttestCli,
  SCHEMA_VERSION,
  PREDICATE_TYPE,
  GENESIS,
  // exported for tests
  _readPolicyRulesDigest: readPolicyRulesDigest,
};
