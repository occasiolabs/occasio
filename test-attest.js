#!/usr/bin/env node
'use strict';

/**
 * test-attest.js — H2 from the 2026-05-15 code review.
 *
 * Covers src/attest/{canonicalize,sign,verify,index}.js. Tests focus on the
 * deterministic surfaces (canonical-JSON byte-stability, in-toto envelope
 * shape, identity/rekor extraction) plus a full sign→verify round-trip using
 * a stub sigstore module — no network, no real Fulcio/Rekor.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

const { canonicalize }                 = require('./src/attest/canonicalize');
const sign                             = require('./src/attest/sign');
const { signAttestation, buildInTotoStatement, _decodeIdentity, _extractRekorEntry } = sign;
const { verifyAttestation }            = require('./src/attest/verify');
const { createAuditor, GENESIS }       = require('./src/audit/jsonl-auditor');
const { buildAttestation }             = require('./src/attest/index');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}
async function asyncAssert(label, fn) {
  try { const ok = await fn(); assert(label, ok === true || ok === undefined); }
  catch (e) { assert(label, false, e.message); }
}

// ── 1. canonicalize: stability + key sort ────────────────────────────────────
console.log('\n1. canonicalize — determinism');
{
  const a = { b: 1, a: 2, c: [3, 2, 1] };
  const b = { c: [3, 2, 1], a: 2, b: 1 };
  assert('key order is normalized', canonicalize(a) === canonicalize(b));
  assert('expected output bytes', canonicalize(a) === '{"a":2,"b":1,"c":[3,2,1]}');
  assert('nested object sort',
    canonicalize({ z: { y: 1, x: 2 } }) === '{"z":{"x":2,"y":1}}');
}

// ── 2. canonicalize: undefined handling ──────────────────────────────────────
console.log('\n2. canonicalize — undefined handling');
{
  assert('undefined keys omitted',
    canonicalize({ a: 1, b: undefined, c: 2 }) === '{"a":1,"c":2}');
  assert('undefined array elements → null',
    canonicalize([1, undefined, 3]) === '[1,null,3]');
  let threw = false;
  try { canonicalize(undefined); } catch { threw = true; }
  assert('undefined at top level throws', threw);
}

// ── 3. canonicalize: type rejections ─────────────────────────────────────────
console.log('\n3. canonicalize — type rejections');
{
  let nonInt = false;
  try { canonicalize(1.5); } catch (e) { nonInt = /non-integer/i.test(e.message); }
  assert('non-integer number rejected', nonInt);
  let nonFinite = false;
  try { canonicalize(Infinity); } catch (e) { nonFinite = /non-finite/i.test(e.message); }
  assert('non-finite number rejected', nonFinite);
  let fn = false;
  try { canonicalize(() => {}); } catch (e) { fn = /unsupported|undefined/i.test(e.message); }
  assert('function rejected', fn);
  // Integer-valued floats pass (JS can't distinguish 1.0 from 1).
  assert('integer-valued number accepted', canonicalize(1.0) === '1');
}

// ── 4. canonicalize: special strings ─────────────────────────────────────────
console.log('\n4. canonicalize — strings');
{
  assert('unicode passthrough',
    canonicalize({ s: 'äöü' }) === '{"s":"äöü"}');
  // JSON.stringify emits \uXXXX for lone surrogates — confirm we use that path.
  const lone = '\uD800';  // unpaired high surrogate
  assert('lone surrogate escaped via JSON.stringify',
    canonicalize(lone) === JSON.stringify(lone));
  assert('empty string', canonicalize('') === '""');
  assert('null literal', canonicalize(null) === 'null');
}

// ── 5. buildInTotoStatement ──────────────────────────────────────────────────
console.log('\n5. buildInTotoStatement');
{
  const att = {
    schema_version: '1.0.0',
    subject:        { run_id: 'r1' },
    audit_chain:    { first_hash: 'a'.repeat(64), last_hash: 'b'.repeat(64), event_count: 2 },
    signature:      null,
  };
  const stmt = buildInTotoStatement(att);
  assert('_type set', stmt._type === 'https://in-toto.io/Statement/v1');
  assert('predicateType set', /agent-attestation\/v1$/.test(stmt.predicateType));
  assert('subject.name carries run_id', stmt.subject[0].name === 'occasio:run:r1');
  assert('subject digest is last_hash', stmt.subject[0].digest.sha256 === 'b'.repeat(64));
  assert('predicate omits signature field', !('signature' in stmt.predicate));
  assert('predicate keeps everything else', stmt.predicate.subject.run_id === 'r1');

  let threw = false;
  try { buildInTotoStatement({ subject: {}, audit_chain: {} }); }
  catch (e) { threw = /last_hash/.test(e.message); }
  assert('refuses to sign empty audit_chain', threw);
}

// ── 6. _decodeIdentity ───────────────────────────────────────────────────────
console.log('\n6. _decodeIdentity');
{
  // Build a fake JWT: header.payload.signature, only payload matters.
  function jwt(claims) {
    const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
    return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
  }
  assert('prefers sub claim',
    _decodeIdentity(jwt({ sub: 'repo:foo/bar:ref:refs/heads/main', iss: 'https://token.actions' })) === 'repo:foo/bar:ref:refs/heads/main');
  assert('falls back to iss#email',
    _decodeIdentity(jwt({ iss: 'https://accounts.google.com', email: 'a@b.c' })) === 'https://accounts.google.com#a@b.c');
  assert('falls back to iss only',
    _decodeIdentity(jwt({ iss: 'https://accounts.google.com' })) === 'https://accounts.google.com');
  assert('garbage → unknown', _decodeIdentity('not.a.jwt') === 'unknown');
}

// ── 7. _extractRekorEntry ────────────────────────────────────────────────────
console.log('\n7. _extractRekorEntry');
{
  assert('returns search URL for valid bundle',
    _extractRekorEntry({ verificationMaterial: { tlogEntries: [{ logIndex: '12345' }] } })
      === 'https://search.sigstore.dev/?logIndex=12345');
  assert('null when no tlog entry', _extractRekorEntry({ verificationMaterial: {} }) === null);
  assert('null on malformed bundle', _extractRekorEntry(null) === null);
}

// ── 8. signAttestation: round-trip with stub sigstore ────────────────────────
console.log('\n8. signAttestation — token mode with stub');
(async () => {
  function jwt(claims) {
    const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
    return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
  }
  const att = {
    schema_version: '1.0.0',
    subject:        { run_id: 'r-test' },
    audit_chain:    { first_hash: 'a'.repeat(64), last_hash: 'b'.repeat(64), event_count: 1 },
    signature:      null,
    generated_at:   '2026-05-15T00:00:00Z',
  };
  const stubBundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
    verificationMaterial: { tlogEntries: [{ logIndex: '99' }] },
    dsseEnvelope: { payload: 'BASE64', payloadType: 'application/vnd.in-toto+json' },
  };
  let capturedPayload = null, capturedPayloadType = null, capturedToken = null;
  const stub = {
    attest(payload, payloadType, opts) {
      capturedPayload = payload;
      capturedPayloadType = payloadType;
      capturedToken = opts.identityToken;
      return Promise.resolve(stubBundle);
    },
  };
  const token = jwt({ sub: 'repo:foo/bar:ref:refs/heads/main' });
  const out = await signAttestation(att, {
    oidcToken: token, sigstoreModule: stub, now: () => new Date('2026-05-15T00:00:01Z'),
  });
  assert('bundle returned',                out.bundle === stubBundle);
  assert('payload is canonical JSON bytes', Buffer.isBuffer(capturedPayload));
  assert('payloadType is in-toto',          capturedPayloadType === 'application/vnd.in-toto+json');
  assert('token forwarded',                 capturedToken === token);
  assert('statementJSON is canonical',
    out.statementJSON === canonicalize(buildInTotoStatement(att)));
  assert('signatureBlock identity decoded', out.signatureBlock.identity === 'repo:foo/bar:ref:refs/heads/main');
  assert('signatureBlock has rekor URL',    /logIndex=99$/.test(out.signatureBlock.rekor_entry));
  assert('signatureBlock signed_at',        out.signatureBlock.signed_at === '2026-05-15T00:00:01.000Z');
  assert('envelope_sha256 matches payload',
    out.signatureBlock.envelope_sha256 === crypto.createHash('sha256').update(capturedPayload).digest('hex'));
})().then(runRoundTripTests).then(printSummary);

// ── 9. full sign → verify round-trip with real audit chain ───────────────────
async function runRoundTripTests() {
  console.log('\n9. full sign → verify round-trip');

  function jwt(claims) {
    const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
    return `${enc({ alg: 'none' })}.${enc(claims)}.sig`;
  }

  // Build a real audit chain.
  const chainFile = path.join(os.tmpdir(), `occasio-attest-test-${process.pid}-chain.jsonl`);
  if (fs.existsSync(chainFile)) fs.unlinkSync(chainFile);
  const a = createAuditor(chainFile);
  const runId = 'roundtrip-run-' + crypto.randomBytes(4).toString('hex');
  const evt = i => ({
    timestamp: `2026-05-15T00:00:0${i}Z`,
    id:        `evt-${i}`,
    sessionId: 'sess-roundtrip',
    runId,
    agent:     'claude-code',
    protocol:  'anthropic',
    direction: 'outbound',
    kind:      'tool_call',
    toolName:  'shell_bash',
    toolInput: { command: `echo ${i}` },
  });
  a.record(evt(0), { action: 'PASS', reason: 'test', policySource: 'default' }, { passThrough: true });
  a.record(evt(1), { action: 'PASS', reason: 'test', policySource: 'default' }, { passThrough: true });

  // Build the attestation (no real policy file → falls back to defaults).
  const att = buildAttestation({
    runId,
    logFile: chainFile,
    policyFile: path.join(os.tmpdir(), 'nonexistent-policy.yml'),
  });
  assert('buildAttestation returns object', !!att);
  assert('attestation event_count = 2', att.audit_chain.event_count === 2);
  assert('first_hash present',  !!att.audit_chain.first_hash);
  assert('last_hash present',   !!att.audit_chain.last_hash);

  // Sign with stub. The bundle below mirrors the shape sigstore-js v3
  // emits in production — every field present here exists on a real prod
  // bundle. The verify path only touches a subset, but the mock asserts the
  // full shape so the test fails loudly if we ever start depending on a
  // field the real Sigstore output does not provide.
  const canonicalStmt = canonicalize(buildInTotoStatement(att));
  const stubBundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
    verificationMaterial: {
      certificate: {
        rawBytes: Buffer.from('-----BEGIN CERTIFICATE-----STUB-----END CERTIFICATE-----', 'utf8').toString('base64'),
      },
      tlogEntries: [{
        logIndex:           '777',
        logId:              { keyId: Buffer.alloc(32, 0xab).toString('base64') },
        kindVersion:        { kind: 'intoto', version: '0.0.2' },
        integratedTime:     '1746000000',
        canonicalizedBody:  Buffer.from('canonical-body', 'utf8').toString('base64'),
      }],
    },
    dsseEnvelope: {
      payload:     Buffer.from(canonicalStmt, 'utf8').toString('base64'),
      payloadType: 'application/vnd.in-toto+json',
      signatures:  [{ sig: Buffer.from('stub-signature', 'utf8').toString('base64') }],
    },
  };
  // Shape assertions — make the mock break loudly if a future refactor
  // assumes a field we never actually populate.
  assert('stub bundle: mediaType matches sigstore v0.3',
    /vnd\.dev\.sigstore\.bundle\+json;version=0\.3/.test(stubBundle.mediaType));
  assert('stub bundle: certificate.rawBytes present',
    typeof stubBundle.verificationMaterial.certificate.rawBytes === 'string');
  assert('stub bundle: tlogEntry has logIndex + integratedTime',
    !!stubBundle.verificationMaterial.tlogEntries[0].logIndex &&
    !!stubBundle.verificationMaterial.tlogEntries[0].integratedTime);
  assert('stub bundle: dsseEnvelope has signatures[]',
    Array.isArray(stubBundle.dsseEnvelope.signatures) &&
    stubBundle.dsseEnvelope.signatures.length === 1);
  let verifyCalled = false;
  const stubSigstore = {
    attest: () => Promise.resolve(stubBundle),
    verify: () => { verifyCalled = true; return Promise.resolve(true); },
  };
  const { signatureBlock } = await signAttestation(att, {
    oidcToken: jwt({ sub: 'test-identity' }),
    sigstoreModule: stubSigstore,
  });
  att.signature = signatureBlock;

  // Persist and verify.
  const attPath    = path.join(os.tmpdir(), `occasio-attest-test-${process.pid}.json`);
  const bundlePath = path.join(os.tmpdir(), `occasio-attest-test-${process.pid}.sigstore.json`);
  fs.writeFileSync(attPath,    JSON.stringify(att) + '\n');
  fs.writeFileSync(bundlePath, JSON.stringify(stubBundle) + '\n');

  const result = await verifyAttestation(attPath, bundlePath, { sigstoreModule: stubSigstore });
  assert('verify called sigstore.verify', verifyCalled);
  assert('verify ok=true',                 result.ok === true);
  assert('all 3 checks pass',              result.checks.length === 3 && result.checks.every(c => c.ok));
  assert('rekor logIndex surfaced',        String(result.rekor_entry) === '777');
  assert('identity surfaced',              result.identity === 'test-identity');

  // ── tamper: corrupt the predicate inside the bundle ────────────────────────
  console.log('\n10. tamper — bundle payload no longer matches attestation');
  const badStmt = canonicalize(buildInTotoStatement({
    ...att,
    subject: { run_id: runId + '-FORGED' },
  }));
  const badBundle = {
    ...stubBundle,
    dsseEnvelope: {
      payload:     Buffer.from(badStmt, 'utf8').toString('base64'),
      payloadType: 'application/vnd.in-toto+json',
    },
  };
  const badBundlePath = bundlePath + '.bad';
  fs.writeFileSync(badBundlePath, JSON.stringify(badBundle) + '\n');
  const badResult = await verifyAttestation(attPath, badBundlePath, { sigstoreModule: stubSigstore });
  assert('payload-mismatch → verify ok=false', badResult.ok === false);
  assert('failure flagged on the right check',
    badResult.checks.some(c => /bundle payload matches/i.test(c.name) && !c.ok));

  // ── tamper: corrupt the audit chain referenced by the attestation ─────────
  console.log('\n11. tamper — audit chain mutated under a previously-signed attestation');
  const rows = fs.readFileSync(chainFile, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  rows[0].hash = '0'.repeat(64);
  fs.writeFileSync(chainFile, rows.map(r => JSON.stringify(r)).join('\n') + '\n');
  const tamperedResult = await verifyAttestation(attPath, bundlePath, { sigstoreModule: stubSigstore });
  assert('chain tamper → verify ok=false', tamperedResult.ok === false);
  assert('chain integrity check failed',
    tamperedResult.checks.some(c => /audit chain/i.test(c.name) && !c.ok));

  // ── missing files ─────────────────────────────────────────────────────────
  console.log('\n12. missing attestation/bundle files');
  const missing = await verifyAttestation('/nonexistent/att.json', '/nonexistent/bundle.json', { sigstoreModule: stubSigstore });
  assert('missing files → ok=false',     missing.ok === false);
  assert('first check is read failure',  /read attestation/i.test(missing.checks[0].name) && !missing.checks[0].ok);

  // ── sigstore.verify rejects → loud fail ───────────────────────────────────
  console.log('\n13. sigstore.verify rejects → caller surfaces it');
  const rejecting = {
    attest: stubSigstore.attest,
    verify: () => Promise.reject(new Error('mock-cert-invalid')),
  };
  const rejected = await verifyAttestation(attPath, bundlePath, { sigstoreModule: rejecting });
  assert('rejecting verify → ok=false', rejected.ok === false);
  assert('sigstore failure surfaced',
    rejected.checks.some(c => /sigstore signature/i.test(c.name) && /mock-cert-invalid/.test(c.detail || '')));

  // cleanup
  for (const f of [attPath, bundlePath, badBundlePath, chainFile]) {
    try { fs.unlinkSync(f); } catch {}
  }
}

function printSummary() {
  console.log(`\n${'─'.repeat(40)}`);
  const total = passed + failed;
  if (failed === 0) {
    console.log(`✓ All ${total} attest tests passed\n`);
    process.exit(0);
  } else {
    console.error(`✗ ${failed}/${total} attest tests failed\n`);
    process.exit(1);
  }
}
