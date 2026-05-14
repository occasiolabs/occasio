# Python verifier — cross-language verification of Occasio attestations

A second reference implementation of the [`agent-attestation/v1`](../spec/agent-attestation/v1/README.md) verifier, written in Python and depending only on the stdlib + optional `sigstore-python`. Lives alongside `audit_walker.py` (which it reuses for the chain step).

## Why this exists

A predicate type whose verification is only feasible in the language that produced it is not a standard — it is one vendor's artifact. The Python verifier proves that Occasio attestations are **language-independent** and can be re-verified by any auditor in their environment of choice.

This is the proof artifact for the OpenSSF / in-toto Attestation Registry submission. The same predicate JSON + Sigstore bundle is verified pass/fail by:

- `occasio attest verify` (Node)
- `python docs/attest_verify.py` (Python)
- The browser viewer at [`integrations/attest-view/`](../integrations/attest-view/) (in-browser, partial — Sigstore crypto is deferred to one of the two above)

The Node test suite asserts that all three implementations agree byte-for-byte on the same payload (`test-interceptor.js` — search for `xlang:`).

## Files

| File | Purpose |
|---|---|
| `canonicalize.py` | RFC 8785 subset, mirror of `src/attest/canonicalize.js` |
| `audit_walker.py` | SHA-256 chain walker (pre-existing, reused) |
| `attest_verify.py` | End-to-end verifier with CLI |

The Python `canonicalize` and the JS `canonicalize` must stay in lockstep. The two files exist in parallel deliberately — bundling them into one cross-compiled artifact would defeat the point of cross-language verifiability.

## Usage

```bash
# Verify a signed attestation pair end-to-end
python docs/attest_verify.py path/to/occasio-attestation.json

# Explicit bundle path (default: <attestation>.sigstore.json sidecar)
python docs/attest_verify.py path/to/att.json --bundle path/to/bundle.json

# Override the chain file (default: read chain_file from the attestation)
python docs/attest_verify.py path/to/att.json --chain path/to/pipeline-events.jsonl

# Machine-readable output
python docs/attest_verify.py --json path/to/att.json
```

Exit code 0 when every (non-skipped) check passes, 1 otherwise.

## What the three checks prove

1. **Sigstore signature** — Fulcio certificate chain valid + Rekor inclusion proof present. Requires `pip install sigstore`; without it the step is marked `SKIP` so the auditor knows not to trust a partial result.
2. **Bundle payload matches attestation** — re-decode the DSSE envelope, canonicalize its `predicate`, compare canonical bytes to the canonicalised attestation (minus `signature` metadata). Pure-stdlib, always runs.
3. **Audit chain integrity** — SHA-256 walk every `prev_hash → hash` link from GENESIS, then assert that the attestation's `first_hash` and `last_hash` appear in the chain in the correct relative order. Reuses `audit_walker.py`.

Each check is independent. Skipping any one of them is not the same as a full verification, and the verifier surfaces that distinction explicitly (the overall pass requires `ok=True` on every check; skipped counts as not-ok).

## Round-trip claim

For a payload produced by `occasio attest --sign` and verified by `occasio attest verify`, the Python verifier produces the same pass/fail result on:
- the unmodified payload (both pass on steps 2+3; step 1 requires sigstore-python)
- a tampered predicate (both fail at step 2)
- a tampered chain (both fail at step 3)
- a tampered Sigstore bundle (both fail at step 1; SKIP if sigstore-python not installed)

The test suite covers cases 1, 2, and 3 deterministically with the Sigstore step mocked. The cross-language byte-equivalence on the predicate-canonicalization step is asserted via Python-spawn from the Node test runner (`xlang:` and `xlang-float:` test blocks); both implementations reject non-integer numbers so the equivalence cannot be silently broken by adding a float field to a future schema. Case 4 (real Sigstore tamper detection) requires GitHub Actions OIDC infrastructure and is exercised by the live Action's self-verify step in CI, not by the in-process test suite.

## Install hint for Sigstore step

```bash
pip install sigstore        # adds the Fulcio + Rekor verification step
```

Versions tracked: `sigstore-python >= 3.0`. The verifier degrades gracefully if a different major version is installed (the `Verifier` API is the stable surface used here).

## Limitations

- **Identity pinning is not enforced** by the reference verifier. The default `policy.UnsafeNoOp()` accepts any Fulcio cert. An auditor whose compliance regime requires a specific workflow-ref identity (e.g. `repo:org/repo:ref:refs/heads/main`) should adapt the call to `policy.Identity(...)`. Pattern intentionally exposed: this is a policy decision, not a verifier decision.
- **The Python canonicalize is a JCS subset**, not full RFC 8785. The deviations are documented inline in `canonicalize.py`. Non-integer numbers are explicitly rejected on both sides as a load-bearing cross-language invariant — see `canonicalize.py` and `src/attest/canonicalize.js` for the rationale.
