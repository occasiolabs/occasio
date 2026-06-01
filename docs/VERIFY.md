# Verify an Occasio attestation in 60 seconds

You received an Occasio attestation bundle (typically a `.json` predicate plus a `.sigstore.json` Sigstore bundle and a `pipeline-events.jsonl` chain file). This page is the third-party verifier's manual: how to confirm the attestation is genuine, unmodified, and reflects events that actually happened, using only public tools and the verifier code shipped with Occasio.

You do not need an Occasio account, a network connection to Occasio Labs, or any vendor portal. The three checks below run offline.

## Simplest: a single evidence bundle (one file, one command)

If the producer sent you a single `*.occasio.json` **evidence bundle** (produced by `occasio bundle --run <id> --out run.occasio.json`), you do not need to juggle separate files — the bundle embeds the attestation, the run's audit-chain slice, the policy snapshot, and (if signed) the Sigstore bundle.

```bash
npm install -g @occasiolabs/occasio
occasio verify run.occasio.json
```

`occasio verify` runs six checks offline and exits non-zero on any failure (so it drops straight into CI):

1. **schema** — recognised bundle format.
2. **manifest integrity** — embedded artifacts hash to the recorded manifest.
3. **chain slice integrity** — every chain row's hash recomputes and links to its predecessor, anchored to the attestation's `first_hash`/`last_hash`.
4. **policy binding** — the embedded policy bytes match the attestation's `policy.file_hash` (proves which `policy.yml` was active; skipped only when the producer's attestation marked the policy `inferred`).
5. **git state matches chain** — the attestation's `subject.git_state` (commit, diff hash, changed/untracked files) byte-matches the `git_state` rows in the embedded chain — so a forged "what the agent changed" claim fails verification.
6. **signature** — when present, the Sigstore bundle is cryptographically valid and its signed predicate matches the embedded attestation.

The sections below cover the older multi-file form (separate `.json` + `.sigstore.json` + `pipeline-events.jsonl`).

## What you need

- The three files: `<name>.json`, `<name>.sigstore.json`, `pipeline-events.jsonl`.
- One of: Node.js 18+ with `@occasiolabs/occasio` installed, or Python 3 with the standard library (plus optional `sigstore-python` for the cryptographic step), or `cosign` for the signature step.

## Path 1: one command via the Occasio CLI

```bash
npm install -g @occasiolabs/occasio
occasio attest verify <name>.json
```

`occasio attest verify` runs all three checks (Sigstore signature, predicate equivalence, audit chain integrity). It prints a clear pass or fail for each step and exits non-zero on any failure. Total time on a typical attestation: under one second.

## Path 2: independent verification with the Python walker

If you do not want to install the Occasio npm package, the same verification is reproducible with the Python walker shipped in the docs directory of the Occasio source repo. Both implementations are kept byte-identical on the predicate and chain steps (cross-language invariant, asserted in the test suite).

```bash
# Download docs/attest_verify.py and docs/audit_walker.py from the repo
python attest_verify.py <name>.json
```

This performs the predicate-equivalence and audit-chain steps in pure stdlib. Add `sigstore-python` if you also want the cryptographic signature step in the same script.

## Path 3: each step with separate tools

A reviewer who wants to use only canonical sigstore-ecosystem tooling can do the three steps explicitly:

### Step 1: Sigstore signature

```bash
cosign verify-blob \
  --bundle <name>.sigstore.json \
  --certificate-identity-regexp 'https://github\.com/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <name>.json
```

This verifies the DSSE bundle's certificate chain against the Fulcio root and confirms the Rekor inclusion proof. The `--certificate-identity-regexp` should be tightened to the exact GitHub workflow you expect; the example above accepts any GitHub-hosted workflow.

### Step 2: Predicate equivalence

Decode the DSSE envelope inside the Sigstore bundle, parse its payload as an in-toto Statement v1, and compare the `predicate` field byte-for-byte with the canonicalised attestation JSON. This proves the predicate file has not been swapped after signing.

The canonicalisation rules are documented in [`spec/agent-attestation/v1/README.md`](../spec/agent-attestation/v1/README.md#verification-model). The shipped `occasio attest verify` does this for you; the Python walker reproduces it independently.

### Step 3: Audit chain integrity

```bash
occasio audit verify --file pipeline-events.jsonl
```

Or independently with the Python walker:

```bash
python docs/audit_walker.py pipeline-events.jsonl
```

Walks every row, recomputes each `hash` from the canonical row bytes, confirms each `prev_hash` matches the previous row's `hash` and that the first row's `prev_hash` is the GENESIS sentinel (64 zero hex digits). Then asserts the attestation's `audit_chain.first_hash` and `audit_chain.last_hash` appear in the chain in the correct relative order.

## What each step proves

| Step | Proves |
|---|---|
| Sigstore signature | The predicate was signed by a known workflow at a known time (Fulcio cert chain plus Rekor transparency log entry). |
| Predicate equivalence | The predicate file in your hand is byte-identical to what was actually signed. |
| Audit chain integrity | The events the predicate references actually happened in the order claimed, and the chain has not been tampered with. |

Each step is independent. If any one fails, the attestation does not verify. There is no "trust us" path.

## Common failure modes

- **Sigstore step fails with "certificate not yet valid" or "expired"**: clock skew between the signer and the verifier. Confirm both have an accurate system time.
- **Predicate equivalence fails after a JSON pretty-print**: do not reformat the predicate JSON before verifying. The canonical bytes are what was signed; whitespace changes break equivalence by design.
- **Chain integrity fails with "prev_hash mismatch"**: the chain file has been edited or the file you received is incomplete. Request a fresh copy and reverify.
- **Chain integrity fails with "first_hash not found"**: the chain file you received does not contain the slice the predicate claims. The signer and the chain file are from different runs.

## Where to read more

- [`spec/agent-attestation/v1/README.md`](../spec/agent-attestation/v1/README.md): the predicate specification this verifies against.
- [`docs/AUDIT.md`](AUDIT.md): the audit-chain row format and the canonical-serialisation rules.
- [`docs/SUPPLY-CHAIN-TRIANGLE.md`](SUPPLY-CHAIN-TRIANGLE.md): where Occasio attestations sit alongside SLSA Provenance and CycloneDX AI-BOM.
