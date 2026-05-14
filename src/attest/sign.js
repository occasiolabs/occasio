'use strict';

/**
 * sign.js — wrap a LocalFirst Phase-0 attestation in an in-toto Statement v1
 * envelope and Sigstore-sign it keyless. Outputs (a) a populated
 * `signature` object to inline in the predicate JSON, and (b) the Sigstore
 * Bundle as a sidecar file for cryptographic verification.
 *
 * Two signing modes:
 *   - 'ci'   — GitHub Actions OIDC. Reads ACTIONS_ID_TOKEN_REQUEST_URL /
 *              ACTIONS_ID_TOKEN_REQUEST_TOKEN and exchanges for a Sigstore
 *              identity token. The standard CI flow.
 *   - 'token'— `--oidc-token <jwt>` was provided explicitly (CI-emulate
 *              for tests + manual runs).
 *
 * No local browser flow in Phase 1 by design (see plan: lokaler Browser-Flow
 * wird später nachgerüstet falls Bedarf da ist).
 *
 * The function is decoupled from sigstore-js via lazy require so tests can
 * stub the module without paying its import cost on every CLI invocation.
 */

const crypto = require('crypto');
const { canonicalize } = require('./canonicalize');

const PREDICATE_TYPE =
  'https://github.com/localfirst-ai/localfirst/spec/agent-attestation/v1';
const STATEMENT_TYPE     = 'https://in-toto.io/Statement/v1';
const DSSE_PAYLOAD_TYPE  = 'application/vnd.in-toto+json';
const SIGSTORE_AUDIENCE  = 'sigstore';

// ── in-toto Statement envelope ───────────────────────────────────────────────

/**
 * Build the in-toto Statement v1 that will be signed. The `subject` carries
 * the audit-chain commitment: `last_hash` is itself a SHA-256 over the entire
 * run-id slice (each prev_hash chains back to GENESIS), so signing it commits
 * cryptographically to every event in the slice.
 */
function buildInTotoStatement(attestation) {
  if (!attestation || !attestation.audit_chain || !attestation.audit_chain.last_hash) {
    throw new Error('sign: attestation has no audit_chain.last_hash — refusing to sign an empty slice');
  }
  // The predicate JSON we sign should NOT carry a placeholder `signature` field;
  // signature metadata is filled into the predicate AFTER signing succeeds.
  const { signature: _omit, ...predicate } = attestation;

  return {
    _type:         STATEMENT_TYPE,
    predicateType: PREDICATE_TYPE,
    subject: [
      {
        name:   `localfirst:run:${attestation.subject.run_id}`,
        digest: { sha256: attestation.audit_chain.last_hash },
      },
    ],
    predicate,
  };
}

// ── OIDC token acquisition ───────────────────────────────────────────────────

/**
 * Fetch a Sigstore-audience identity token from the GitHub Actions OIDC
 * provider. Requires `permissions: id-token: write` in the workflow.
 * Returns the JWT string.
 */
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
  const res = await fetch(fetchUrl, {
    headers: { Authorization: `Bearer ${reqToken}` },
  });
  if (!res.ok) {
    throw new Error(`sign: OIDC token request failed: ${res.status} ${res.statusText}`);
  }
  const body = await res.json();
  if (!body || typeof body.value !== 'string') {
    throw new Error('sign: OIDC token response missing `value`');
  }
  return body.value;
}

// ── identity decoding (best-effort, no signature check) ──────────────────────

/**
 * Decode the OIDC JWT payload for the `iss` + `sub` claims. We only use these
 * for the human-readable `signature.identity` field — the cryptographic
 * binding is in the Sigstore certificate, not here. Best-effort: if decoding
 * fails we fall back to `'unknown'`.
 */
function decodeIdentity(jwt) {
  try {
    const parts = jwt.split('.');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (claims.sub) return claims.sub;        // GitHub: workflow ref
    if (claims.iss && claims.email) return `${claims.iss}#${claims.email}`;
    return claims.iss || 'unknown';
  } catch { return 'unknown'; }
}

// ── Bundle parsing (extract Rekor entry URL for human display) ───────────────

function extractRekorEntry(bundle) {
  try {
    const entry = bundle?.verificationMaterial?.tlogEntries?.[0];
    if (!entry || !entry.logIndex) return null;
    // Public Rekor instance URL format. Private Sigstore deployments would
    // need a different base URL — Phase 1 supports public-good only.
    return `https://search.sigstore.dev/?logIndex=${entry.logIndex}`;
  } catch { return null; }
}

// ── public API ───────────────────────────────────────────────────────────────

/**
 * Sign an attestation. Returns { bundle, signatureBlock, statementJSON }.
 *
 *   ctx.oidcToken         — explicit JWT (token-mode); takes precedence
 *   ctx.signMode          — 'ci' | 'token' (auto-detected if absent)
 *   ctx.sigstoreModule    — DI for tests; defaults to require('sigstore')
 *   ctx.now               — DI for tests; defaults to () => new Date()
 *   ctx.tlogUpload        — default true (Rekor log entry). Set false in tests.
 */
async function signAttestation(attestation, ctx = {}) {
  const statement = buildInTotoStatement(attestation);
  // Canonical JSON: makes byte-equivalence in verify.js deterministic across
  // runtime versions and re-serialisation steps. The verifier re-canonicalises
  // the parsed predicate from the bundle before comparing — both sides agree.
  const statementJSON = canonicalize(statement);
  const payload = Buffer.from(statementJSON, 'utf8');

  // Token acquisition
  let identityToken;
  let mode = ctx.signMode;
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

  // Sigstore sign (keyless)
  const sigstore = ctx.sigstoreModule || require('sigstore');
  const bundle = await sigstore.attest(payload, DSSE_PAYLOAD_TYPE, {
    identityToken,
    tlogUpload: ctx.tlogUpload !== false,
  });

  const now = (ctx.now ? ctx.now() : new Date()).toISOString();
  const signatureBlock = {
    type:            'sigstore-cosign-keyless',
    identity:        decodeIdentity(identityToken),
    rekor_entry:     extractRekorEntry(bundle),
    signed_at:       now,
    envelope_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
  };

  return { bundle, signatureBlock, statementJSON };
}

module.exports = {
  signAttestation,
  buildInTotoStatement,
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  DSSE_PAYLOAD_TYPE,
  // for tests
  _decodeIdentity: decodeIdentity,
  _extractRekorEntry: extractRekorEntry,
};
