'use strict';

/**
 * Sign a paranoid-doctor report with Sigstore (keyless, GitHub Actions OIDC).
 *
 * Reuses the token acquisition + module loading path from src/attest/sign.js.
 * The signed payload is the canonical JSON of the report itself; no in-toto
 * Statement wrapper is added because the paranoid report is not an artefact
 * attestation in the SLSA sense. It is an "I scanned this install and here is
 * what I found" claim, signed so a third party can verify provenance of the
 * claim itself.
 *
 * Two signing modes (mirror of attest/sign.js):
 *   - 'ci'    — GitHub Actions OIDC (default when GITHUB_ACTIONS=true)
 *   - 'token' — ctx.oidcToken explicit JWT (for tests + manual)
 *
 * Returns: { bundle, signatureBlock, payloadSha256 }. The bundle is the
 * Sigstore Bundle (DSSE-wrapped). signatureBlock is a small descriptor the
 * renderer can embed in the human report.
 */

const crypto = require('crypto');

const DSSE_PAYLOAD_TYPE = 'application/vnd.occasio.paranoid-report+json';
const SIGSTORE_AUDIENCE = 'sigstore';

async function fetchGithubActionsToken() {
  const url      = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !reqToken) {
    throw new Error(
      "sign: GitHub Actions OIDC env vars missing. " +
      "Workflow needs `permissions: id-token: write`. " +
      "Vars: ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN."
    );
  }
  const fetchUrl = `${url}&audience=${encodeURIComponent(SIGSTORE_AUDIENCE)}`;
  const res = await fetch(fetchUrl, { headers: { Authorization: `Bearer ${reqToken}` } });
  if (!res.ok) {
    throw new Error(`sign: OIDC token request failed: ${res.status} ${res.statusText}`);
  }
  const body = await res.json();
  if (!body || typeof body.value !== 'string') {
    throw new Error('sign: OIDC token response missing `value`');
  }
  return body.value;
}

function decodeIdentity(jwt) {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());
    return {
      issuer:  payload.iss || null,
      subject: payload.sub || null,
      audience: payload.aud || null,
    };
  } catch { return null; }
}

function extractRekorEntry(bundle) {
  try {
    const tlog = bundle?.verificationMaterial?.tlogEntries?.[0];
    if (!tlog || tlog.logIndex == null) return null;
    return `https://search.sigstore.dev/?logIndex=${tlog.logIndex}`;
  } catch { return null; }
}

async function signParanoidReport(reportJsonString, ctx = {}) {
  const payload = Buffer.from(reportJsonString, 'utf8');

  let identityToken, mode = ctx.signMode;
  if (ctx.oidcToken) {
    identityToken = ctx.oidcToken;
    mode = mode || 'token';
  } else {
    mode = mode || (process.env.GITHUB_ACTIONS === 'true' ? 'ci' : null);
    if (mode !== 'ci') {
      throw new Error(
        "sign: no OIDC token. Pass --oidc-token <jwt> or run inside " +
        "GitHub Actions with `permissions: id-token: write`."
      );
    }
    identityToken = await fetchGithubActionsToken();
  }

  const sigstore = ctx.sigstoreModule || require('sigstore');
  const bundle = await sigstore.attest(payload, DSSE_PAYLOAD_TYPE, {
    identityToken,
    tlogUpload: ctx.tlogUpload !== false,
  });

  const now = (ctx.now ? ctx.now() : new Date()).toISOString();
  const payloadSha256 = crypto.createHash('sha256').update(payload).digest('hex');
  const signatureBlock = {
    type:         'sigstore-cosign-keyless',
    identity:     decodeIdentity(identityToken),
    rekor_entry:  extractRekorEntry(bundle),
    signed_at:    now,
    payload_sha256: payloadSha256,
    payload_type: DSSE_PAYLOAD_TYPE,
  };
  return { bundle, signatureBlock, payloadSha256 };
}

module.exports = { signParanoidReport, DSSE_PAYLOAD_TYPE };
