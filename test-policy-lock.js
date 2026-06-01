#!/usr/bin/env node
'use strict';

/**
 * test-policy-lock.js — signed policy lock + diff (Idea #7).
 *
 * Covers:
 *   - src/policy/lock.js   buildLock / summarize / lockPayload / verifyLock
 *   - src/policy/diff.js   diffSummaries (per-section)
 *
 * No network: the signed round-trip uses a stub sigstore module (matching
 * test-bundle.js / test-attest.js). Temp policies live in os.tmpdir().
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { buildLock, verifyLock, summarize, lockPayload, LOCK_SCHEMA, POLICY_LOCK_PAYLOAD_TYPE } = require('./src/policy/lock');
const { diffSummaries } = require('./src/policy/diff');
const { signParanoidReport } = require('./src/paranoid/sign');
const loader = require('./src/policy/loader');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

const tmps = [];
function mkTmp(p) { const d = fs.mkdtempSync(path.join(os.tmpdir(), p)); tmps.push(d); return d; }

const POLICY_A = [
  'version: 1',
  'block_secrets_in_tool_results: true',
  'distill_tool_results: false',
  'deny_paths:',
  '  - ~/.ssh',
  '  - /etc/secret',
  'deny_patterns:',
  '  internal_url: "https://internal\\\\."',
  'limits:',
  '  max_tool_calls_per_round: 50',
  'tools:',
  '  Bash:',
  '    action: PASS',
  '',
].join('\n');

// ── 1. buildLock structure + machine independence ────────────────────────────
console.log('\n1. buildLock');
const dir = mkTmp('lf-lock-');
const polA = path.join(dir, 'policy.yml');
fs.writeFileSync(polA, POLICY_A);
const lock = buildLock(polA);
{
  assert('schema tag', lock.schema === LOCK_SCHEMA);
  assert('policy_hash = computePolicyHash', lock.policy_hash === loader.computePolicyHash(polA) && /^[0-9a-f]{64}$/.test(lock.policy_hash));
  assert('summary.flags captured', lock.summary.flags.block_secrets_in_tool_results === true && lock.summary.flags.distill_tool_results === false);
  assert('summary.deny_paths machine-independent (raw ~ preserved, sorted)',
    lock.summary.deny_paths.includes('~/.ssh') && lock.summary.deny_paths.includes('/etc/secret'));
  assert('summary.deny_patterns keeps label→regex', typeof lock.summary.deny_patterns.internal_url === 'string');
  assert('summary.limits normalized', lock.summary.limits.max_tool_calls_per_round === 50);
  assert('summary.tools captured', lock.summary.tools.Bash && lock.summary.tools.Bash.action === 'PASS');
  assert('no absolute resolved path leaked into summary', !lock.summary.deny_paths.some(p => p.includes(os.homedir())));
}

// ── 2. diffSummaries — per-section detection ─────────────────────────────────
console.log('\n2. diffSummaries');
{
  const base = summarize(loader.parse(POLICY_A));
  assert('identical → not changed', diffSummaries(base, summarize(loader.parse(POLICY_A))).changed === false);

  const flip = { ...base, flags: { ...base.flags, block_secrets_in_tool_results: false } };
  let d = diffSummaries(base, flip);
  assert('flag flip detected', d.changed && d.sections.some(s => s.name === 'flags' && s.rows.some(r => r.mark === '~' && r.key === 'block_secrets_in_tool_results')));

  const addPath = { ...base, deny_paths: [...base.deny_paths, '/var/x'].sort() };
  d = diffSummaries(base, addPath);
  assert('added deny_path detected (+)', d.sections.some(s => s.name === 'deny_paths' && s.rows.some(r => r.mark === '+' && r.key === '/var/x')));

  const rmPath = { ...base, deny_paths: base.deny_paths.filter(p => p !== '/etc/secret') };
  d = diffSummaries(base, rmPath);
  assert('removed deny_path detected (-)', d.sections.some(s => s.name === 'deny_paths' && s.rows.some(r => r.mark === '-' && r.key === '/etc/secret')));

  const chgPat = { ...base, deny_patterns: { internal_url: 'CHANGED' } };
  d = diffSummaries(base, chgPat);
  assert('changed deny_pattern regex detected (~)', d.sections.some(s => s.name === 'deny_patterns' && s.rows.some(r => r.mark === '~' && r.key === 'internal_url')));

  const chgLimit = { ...base, limits: { max_tool_calls_per_round: 10 } };
  d = diffSummaries(base, chgLimit);
  assert('changed limit detected (~)', d.sections.some(s => s.name === 'limits' && s.rows.some(r => r.mark === '~')));

  const chgTool = { ...base, tools: { Bash: { action: 'LOCAL' } } };
  d = diffSummaries(base, chgTool);
  assert('changed tool action detected (~)', d.sections.some(s => s.name === 'tools' && s.rows.some(r => r.mark === '~' && r.key === 'Bash')));
}

// ── 3. signed lock round-trip with stub sigstore + tamper ────────────────────
console.log('\n3. signed lock — verifyLock');
(async () => {
  function jwt(claims) {
    const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
    return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
  }
  const signStub = {
    attest(payload, payloadType) {
      return Promise.resolve({
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        verificationMaterial: { tlogEntries: [{ logIndex: '3' }] },
        dsseEnvelope: { payload: payload.toString('base64'), payloadType },
      });
    },
  };
  const verifyStub = { verify: async () => true };

  const l = buildLock(polA);
  const r = await signParanoidReport(lockPayload(l), { oidcToken: jwt({ sub: 'repo:o/r:ref:refs/heads/main' }), sigstoreModule: signStub, payloadType: POLICY_LOCK_PAYLOAD_TYPE });
  l.signature = r.signatureBlock;
  const lockPath = path.join(dir, 'policy.lock.json');
  const sidecar  = path.join(dir, 'policy.lock.sigstore.json');
  const { _present, ...toWrite } = l;
  fs.writeFileSync(lockPath, JSON.stringify(toWrite, null, 2));
  fs.writeFileSync(sidecar, JSON.stringify(r.bundle, null, 2));

  assert('dedicated DSSE payload type', r.bundle.dsseEnvelope.payloadType === 'application/vnd.occasio.policy-lock+json' && r.signatureBlock.payload_type === 'application/vnd.occasio.policy-lock+json');

  const ok = await verifyLock(lockPath, { sigstoreModule: verifyStub });
  assert('signed lock verifies', ok.ok === true, JSON.stringify(ok.checks));

  // a lock signed with the WRONG payload type (e.g. paranoid-report) must fail
  {
    const l2 = buildLock(polA);
    const wrong = await signParanoidReport(lockPayload(l2), { oidcToken: jwt({ sub: 'x' }), sigstoreModule: signStub /* no payloadType → defaults to paranoid-report */ });
    l2.signature = wrong.signatureBlock;
    const lp2 = path.join(dir, 'wrongtype.lock.json');
    const { _present: _p2, ...tw2 } = l2;
    fs.writeFileSync(lp2, JSON.stringify(tw2, null, 2));
    fs.writeFileSync(path.join(dir, 'wrongtype.lock.sigstore.json'), JSON.stringify(wrong.bundle, null, 2));
    const badType = await verifyLock(lp2, { sigstoreModule: verifyStub });
    assert('wrong DSSE payload type → verify fails', badType.ok === false && badType.checks.some(c => c.name === 'signature' && !c.ok && /payloadType/i.test(c.detail || '')));
  }

  // drift check: same policy → matches; edited policy → drift
  const ok2 = await verifyLock(lockPath, { sigstoreModule: verifyStub, againstPolicy: polA });
  assert('verify --against current policy → matches', ok2.ok === true && ok2.checks.some(c => c.name === 'policy matches lock' && c.ok));

  const polEdited = path.join(dir, 'edited.yml');
  fs.writeFileSync(polEdited, POLICY_A.replace('block_secrets_in_tool_results: true', 'block_secrets_in_tool_results: false'));
  const ok3 = await verifyLock(lockPath, { sigstoreModule: verifyStub, againstPolicy: polEdited });
  assert('verify --against edited policy → drift fails', ok3.ok === false && ok3.checks.some(c => c.name === 'policy matches lock' && !c.ok));

  // tamper the signed lock body → signed payload no longer matches
  const tampered = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  tampered.policy_hash = '0'.repeat(64);
  fs.writeFileSync(lockPath, JSON.stringify(tampered, null, 2));
  const bad = await verifyLock(lockPath, { sigstoreModule: verifyStub });
  assert('tampered lock fails signature check', bad.ok === false && bad.checks.some(c => c.name === 'signature' && !c.ok));

  // ── 4. backward-compat: minimal policy (no limits/deny_patterns/tools) ──────
  console.log('\n4. backward-compat — minimal policy');
  {
    const minPol = path.join(dir, 'min.yml');
    fs.writeFileSync(minPol, 'version: 1\nblock_secrets_in_tool_results: true\n');
    const ml = buildLock(minPol);
    assert('minimal lock builds', ml.schema === LOCK_SCHEMA && /^[0-9a-f]{64}$/.test(ml.policy_hash));
    assert('empty sections', Object.keys(ml.summary.deny_patterns).length === 0 && Object.keys(ml.summary.limits).length === 0 && Object.keys(ml.summary.tools).length === 0);
    assert('diff identical minimal → not changed', diffSummaries(ml.summary, summarize(loader.parse('version: 1\nblock_secrets_in_tool_results: true\n'))).changed === false);
  }

  loader._resetCache();
  for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
  console.log(`\n${failed === 0 ? '✓' : '✗'} policy-lock: ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
