'use strict';

/**
 * occasio policy lock — write a `policy.lock.json`: an attributable,
 * tamper-evident record of the *approved* policy.
 *
 * The chain's `policy_loaded` rows already prove which policy was ACTIVE during
 * a run. The lock proves which policy was APPROVED: a committable artifact
 * carrying the policy's byte-hash plus a machine-independent summary, optionally
 * Sigstore-signed. `occasio policy diff` then detects drift from this baseline.
 *
 * The summary is built from loader.parse() (raw, pre-resolution values) so the
 * lock is source-control-friendly and leaks no absolute paths from the locking
 * machine. The authoritative drift signal is `policy_hash` (sha256 of the raw
 * file bytes), reused from loader.computePolicyHash.
 *
 * Usage:
 *   occasio policy lock [--file <policy.yml>] [--out <lock>] [--sign] [--oidc-token <jwt>]
 *   occasio policy lock --verify <lock> [--against <policy.yml>] [--bundle <path>]
 */

const fs   = require('fs');
const path = require('path');

const LOCK_SCHEMA = 'occasio-policy-lock/v1';
// Dedicated DSSE payload type so a signed lock is self-describing and never
// confused with a paranoid report or receipt.
const POLICY_LOCK_PAYLOAD_TYPE = 'application/vnd.occasio.policy-lock+json';

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

const FLAG_KEYS = [
  'block_secrets_in_tool_results',
  'redact_secrets_in_tool_results',
  'distill_tool_results',
  'block_requests_over_budget',
];

/**
 * Machine-independent semantic view of a parsed policy (loader.parse output).
 * Stable key order + sorted lists so two locks of the same policy are equal.
 */
function summarize(parsed) {
  const p = parsed || {};
  const flags = {};
  for (const k of FLAG_KEYS) if (typeof p[k] === 'boolean') flags[k] = p[k];

  const listOf = (v) => Array.isArray(v) ? v.filter(x => typeof x === 'string').slice().sort() : [];

  const deny_patterns = {};
  if (p.deny_patterns && typeof p.deny_patterns === 'object' && !Array.isArray(p.deny_patterns)) {
    for (const k of Object.keys(p.deny_patterns).sort()) {
      if (typeof p.deny_patterns[k] === 'string') deny_patterns[k] = p.deny_patterns[k];
    }
  }

  const tools = {};
  if (p.tools && typeof p.tools === 'object' && !Array.isArray(p.tools)) {
    for (const name of Object.keys(p.tools).sort()) {
      const e = p.tools[name];
      if (e && typeof e === 'object') {
        const t = { action: e.action };
        if (e.transform) t.transform = e.transform;
        tools[name] = t;
      }
    }
  }

  let limits = {};
  if (p.limits && typeof p.limits === 'object' && !Array.isArray(p.limits)) {
    limits = require('../limits').normalizeLimits(p.limits);
  }

  return {
    flags,
    deny_paths:    listOf(p.deny_paths),
    allow_paths:   listOf(p.allow_paths),
    deny_patterns,
    tools,
    limits,
  };
}

/** Build a lock object from a policy file path. Never throws. */
function buildLock(policyPath) {
  const loader = require('./loader');
  let rawText = null;
  try { rawText = fs.readFileSync(policyPath, 'utf8'); } catch { rawText = null; }
  const parsed = rawText !== null ? loader.parse(rawText) : {};
  return {
    schema:      LOCK_SCHEMA,
    policy_path: policyPath,
    policy_hash: loader.computePolicyHash(policyPath),
    version:     typeof parsed.version === 'number' ? parsed.version : 1,
    summary:     summarize(parsed),
    locked_at:   new Date().toISOString(),
    signature:   null,
    _present:    rawText !== null,   // not serialized; stripped before write
  };
}

// Canonical bytes that get signed / re-verified: the lock minus its signature
// and minus the transient _present marker.
function lockPayload(lock) {
  const { canonicalize } = require('../attest/canonicalize');
  const { signature: _s, _present: _p, ...rest } = lock;
  return canonicalize(rest);
}

/**
 * Verify a saved lock: (1) Sigstore signature when present + signed payload
 * equals the lock; (2) optionally that a given policy file still matches the
 * locked hash (drift check). Returns { ok, checks:[{name,ok,detail}] }.
 */
async function verifyLock(lockPath, ctx = {}) {
  const checks = [];
  let lock;
  try { lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')); }
  catch (e) { return { ok: false, checks: [{ name: 'read lock', ok: false, detail: e.message }] }; }

  if (lock.schema !== LOCK_SCHEMA) {
    return { ok: false, checks: [{ name: 'schema', ok: false, detail: `unexpected schema ${lock.schema}` }] };
  }
  checks.push({ name: 'schema', ok: true, detail: LOCK_SCHEMA });

  // Signature (only when the lock claims to be signed)
  if (lock.signature) {
    try {
      const bundlePath = ctx.bundlePath || (lockPath.replace(/\.json$/i, '') + '.sigstore.json');
      const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
      const sigstore = ctx.sigstoreModule || require('sigstore');
      await sigstore.verify(bundle);
      const env = bundle.dsseEnvelope;
      if (!env || !env.payload) throw new Error('bundle missing dsseEnvelope.payload');
      if (env.payloadType !== POLICY_LOCK_PAYLOAD_TYPE) {
        throw new Error(`unexpected payloadType ${env.payloadType} (want ${POLICY_LOCK_PAYLOAD_TYPE})`);
      }
      const signed = Buffer.from(env.payload, 'base64').toString('utf8');
      if (signed !== lockPayload(lock)) throw new Error('signed payload differs from lock contents');
      checks.push({ name: 'signature', ok: true, detail: lock.signature.identity ? JSON.stringify(lock.signature.identity) : 'sigstore-verified' });
    } catch (e) {
      checks.push({ name: 'signature', ok: false, detail: e.message });
      return { ok: false, checks };
    }
  } else {
    checks.push({ name: 'signature', ok: true, detail: 'unsigned lock' });
  }

  // Drift check against a live policy file
  if (ctx.againstPolicy) {
    const loader = require('./loader');
    const cur = loader.computePolicyHash(ctx.againstPolicy);
    if (cur === lock.policy_hash) {
      checks.push({ name: 'policy matches lock', ok: true, detail: cur.slice(0, 12) + '…' });
    } else {
      checks.push({ name: 'policy matches lock', ok: false, detail: `drift: lock ${lock.policy_hash.slice(0, 12)}… vs current ${cur.slice(0, 12)}…` });
      return { ok: false, checks };
    }
  }

  return { ok: checks.every(c => c.ok), checks };
}

// ── CLI ────────────────────────────────────────────────────────────────────

function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }

async function runLockCli(args) {
  args = args || [];
  const loader = require('./loader');

  if (has(args, '--help') || has(args, '-h')) {
    process.stdout.write(
      'occasio policy lock — record the approved policy as a signed lock file\n\n' +
      'usage: occasio policy lock [--file <policy.yml>] [--out <lock>] [--sign] [--oidc-token <jwt>]\n' +
      '       occasio policy lock --verify <lock> [--against <policy.yml>] [--bundle <path>]\n'
    );
    return 0;
  }

  // Verify mode
  const verifyTarget = flag(args, '--verify');
  if (verifyTarget) {
    const against = flag(args, '--against');
    const res = await verifyLock(path.resolve(verifyTarget), {
      againstPolicy: against ? path.resolve(against) : undefined,
      bundlePath:    flag(args, '--bundle') ? path.resolve(flag(args, '--bundle')) : undefined,
    });
    process.stdout.write(`${col.b('Verifying lock')} ${path.resolve(verifyTarget)}\n\n`);
    for (const c of res.checks) {
      process.stdout.write(`  ${c.ok ? col.g('✓') : col.r('✗')} ${c.name}${c.detail ? '  ' + col.d(c.detail) : ''}\n`);
    }
    process.stdout.write('\n' + (res.ok ? col.g('✓ lock verified') : col.r('✗ lock verification failed')) + '\n');
    return res.ok ? 0 : 1;
  }

  // Create mode
  const policyPath = path.resolve(flag(args, '--file') || loader.DEFAULT_PATH);
  const out        = path.resolve(flag(args, '--out')  || path.join(process.cwd(), 'policy.lock.json'));
  const sign       = has(args, '--sign');
  const oidcToken  = flag(args, '--oidc-token');

  const lock = buildLock(policyPath);
  if (!lock._present) {
    process.stderr.write(`${col.y('⚠')} no policy file at ${policyPath} — locking the empty/default policy (hash ${lock.policy_hash.slice(0, 12)}…)\n`);
  }

  let bundle = null;
  if (sign) {
    try {
      const { signParanoidReport } = require('../paranoid/sign');
      const r = await signParanoidReport(lockPayload(lock), { oidcToken, payloadType: POLICY_LOCK_PAYLOAD_TYPE });
      lock.signature = r.signatureBlock;
      bundle = r.bundle;
    } catch (e) {
      process.stderr.write(`${col.r('✗')} signing failed: ${e.message}\n`);
      return 2;
    }
  }

  const { _present, ...toWrite } = lock;
  try {
    fs.writeFileSync(out, JSON.stringify(toWrite, null, 2) + '\n', 'utf8');
    if (bundle) fs.writeFileSync(out.replace(/\.json$/i, '') + '.sigstore.json', JSON.stringify(bundle, null, 2) + '\n', 'utf8');
  } catch (e) {
    process.stderr.write(`${col.r('✗')} cannot write ${out}: ${e.message}\n`);
    return 2;
  }

  const s = toWrite.summary;
  process.stdout.write(`${col.g('✓')} Wrote policy lock: ${out}\n`);
  process.stdout.write(`  hash:    ${toWrite.policy_hash.slice(0, 24)}…\n`);
  process.stdout.write(`  summary: ${Object.keys(s.flags).length} flags · ${s.deny_paths.length} deny_paths · ${s.allow_paths.length} allow_paths · ${Object.keys(s.deny_patterns).length} deny_patterns · ${Object.keys(s.tools).length} tools · ${Object.keys(s.limits).length} limits\n`);
  process.stdout.write(`  signed:  ${bundle ? 'yes' : 'no'}\n`);
  process.stdout.write(`  ${col.d('drift-check later with:')} occasio policy diff --since ${path.relative(process.cwd(), out) || out}\n`);
  return 0;
}

module.exports = { buildLock, verifyLock, summarize, lockPayload, runLockCli, LOCK_SCHEMA, POLICY_LOCK_PAYLOAD_TYPE };
