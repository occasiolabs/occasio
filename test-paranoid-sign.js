#!/usr/bin/env node
'use strict';

/**
 * test-paranoid-sign.js: unit tests for src/paranoid/sign.js with a
 * mocked sigstore module and a synthetic OIDC token.
 *
 * The real Sigstore signing path requires a GitHub Actions OIDC env, which
 * is not available in unit tests. This file injects a fake sigstore module
 * via ctx.sigstoreModule and a fake JWT via ctx.oidcToken to exercise the
 * function's contract without touching the network:
 *
 *   - the canonical payload bytes are what gets passed to sigstore.attest
 *   - the DSSE payload type is the new paranoid-specific MIME type
 *   - identity is decoded from the JWT claims
 *   - the rekor URL is extracted from the bundle and surfaced in the
 *     signatureBlock
 */

const crypto = require('crypto');
const { signParanoidReport, DSSE_PAYLOAD_TYPE } = require('./src/paranoid/sign');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
}

// Build a synthetic JWT: header.payload.signature where payload carries
// recognisable iss/sub/aud claims so decodeIdentity can extract them.
function makeJwt(claims) {
  const head = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig  = 'fake-signature';
  return `${head}.${body}.${sig}`;
}

(async () => {

  console.log('\nBlock 1: DSSE payload type constant');
  {
    assert('DSSE_PAYLOAD_TYPE is the paranoid-specific MIME',
      DSSE_PAYLOAD_TYPE === 'application/vnd.occasio.paranoid-report+json');
  }

  console.log('\nBlock 2: signParanoidReport happy path with mocked sigstore');
  {
    const claims = {
      iss: 'https://token.actions.githubusercontent.com',
      sub: 'https://github.com/occasiolabs/occasio/.github/workflows/publish.yml@refs/heads/main',
      aud: 'sigstore',
    };
    const jwt = makeJwt(claims);
    const reportJson = JSON.stringify({ hello: 'world', n: 42 });

    let capturedPayload, capturedType, capturedOpts;
    const fakeSigstore = {
      attest: async (payload, type, opts) => {
        capturedPayload = payload;
        capturedType    = type;
        capturedOpts    = opts;
        return {
          verificationMaterial: {
            tlogEntries: [{ logIndex: '12345', integratedTime: '0' }],
          },
        };
      },
    };

    const { bundle, signatureBlock, payloadSha256 } = await signParanoidReport(reportJson, {
      sigstoreModule: fakeSigstore,
      oidcToken: jwt,
      tlogUpload: true,
    });

    // sigstore.attest contract
    assert('sigstore.attest was called with the report bytes',
      Buffer.isBuffer(capturedPayload) && capturedPayload.toString('utf8') === reportJson);
    assert('sigstore.attest was called with the paranoid DSSE payload type',
      capturedType === DSSE_PAYLOAD_TYPE);
    assert('sigstore.attest was called with the provided OIDC token',
      capturedOpts && capturedOpts.identityToken === jwt);
    assert('sigstore.attest tlogUpload defaults true',
      capturedOpts && capturedOpts.tlogUpload === true);

    // Output shape
    assert('bundle is the fake bundle returned by sigstore.attest',
      bundle && bundle.verificationMaterial && bundle.verificationMaterial.tlogEntries.length === 1);
    assert('signatureBlock.type = sigstore-cosign-keyless',
      signatureBlock.type === 'sigstore-cosign-keyless');
    assert('signatureBlock.payload_type = DSSE_PAYLOAD_TYPE',
      signatureBlock.payload_type === DSSE_PAYLOAD_TYPE);
    assert('signatureBlock.payload_sha256 matches sha256(reportJson)',
      signatureBlock.payload_sha256 === crypto.createHash('sha256').update(reportJson).digest('hex'));
    assert('payloadSha256 returned and matches',
      payloadSha256 === signatureBlock.payload_sha256);
    assert('signatureBlock.rekor_entry built from logIndex',
      signatureBlock.rekor_entry === 'https://search.sigstore.dev/?logIndex=12345');

    // Identity decoded from JWT
    assert('signatureBlock.identity.issuer extracted from JWT iss',
      signatureBlock.identity && signatureBlock.identity.issuer === claims.iss);
    assert('signatureBlock.identity.subject extracted from JWT sub',
      signatureBlock.identity && signatureBlock.identity.subject === claims.sub);
    assert('signatureBlock.identity.audience extracted from JWT aud',
      signatureBlock.identity && signatureBlock.identity.audience === claims.aud);
  }

  console.log('\nBlock 3: tlogUpload=false honoured');
  {
    let captured;
    const fakeSigstore = {
      attest: async (_p, _t, opts) => { captured = opts; return { verificationMaterial: { tlogEntries: [] } }; },
    };
    await signParanoidReport('{}', {
      sigstoreModule: fakeSigstore,
      oidcToken: makeJwt({ iss: 'x', sub: 'y' }),
      tlogUpload: false,
    });
    assert('tlogUpload=false propagated to sigstore.attest',
      captured && captured.tlogUpload === false);
  }

  console.log('\nBlock 4: no OIDC token and no CI env -> informative error');
  {
    const wasCi = process.env.GITHUB_ACTIONS;
    delete process.env.GITHUB_ACTIONS;
    let thrown = null;
    try {
      await signParanoidReport('{}', { sigstoreModule: { attest: async () => ({}) } });
    } catch (e) { thrown = e; }
    if (wasCi !== undefined) process.env.GITHUB_ACTIONS = wasCi;

    assert('error thrown when no OIDC available',
      thrown && /no OIDC token/i.test(thrown.message));
    assert('error message names the env vars and --oidc-token',
      thrown && /id-token: write|--oidc-token/.test(thrown.message));
  }

  console.log('\nBlock 5: JWT with malformed payload still produces null-claim identity');
  {
    let captured;
    const fakeSigstore = {
      attest: async () => ({ verificationMaterial: { tlogEntries: [] } }),
    };
    const malformedJwt = 'not-a-jwt';
    const { signatureBlock } = await signParanoidReport('{}', {
      sigstoreModule: fakeSigstore,
      oidcToken: malformedJwt,
    });
    captured = signatureBlock;
    assert('malformed JWT yields identity=null (no throw)',
      captured.identity === null);
  }

  console.log(`\n  ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
  process.exit(0);
})();
