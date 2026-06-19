# Python verifier — cross-language verification of Occasio attestations

A second reference implementation of the [`agent-attestation/v1`](../spec/agent-attestation/v1/README.md) verifier, written in Python and depending only on the stdlib + optional `sigstore-python`. Lives alongside `audit_walker.py` (which it reuses for the chain step).

## Why this exists

A predicate type whose verification is only feasible in the language that produced it is not a standard — it is one vendor's artifact. The Python verifier proves that Occasio attestations are **language-independent** and can be re-verified by any auditor in their environment of choice.

This is the proof artifact for the OpenSSF / in-toto Attestation Registry submission. The same predicate JSON + Sigstore bundle is verified pass/fail by:

- `occasio verify` (Node, `src/bundle/verify.js`)
- `python docs/verify_bundle.py` (Python)
- The browser viewer at [`integrations/attest-view/`](../integrations/attest-view/) (in-browser, partial — Sigstore crypto is deferred to one of the two above)

The Node test suite asserts that Node and Python agree byte-for-byte on the same single-file evidence bundle (`test-bundle-xlang.js`) — honest bundles pass in both, each single-point tamper (chain / policy / git / manifest bytes) fails the same check in both, and the strict requirements fail closed identically. (The per-row canonical-serialization guarantee they both depend on has its own Node↔Python pin in `test-audit-xlang.js`.)

## Files

| File | Purpose |
|---|---|
| `canonicalize.py` | RFC 8785 subset, mirror of `src/attest/canonicalize.js` (predicate + git_state comparison) |
| `audit_walker.py` | SHA-256 chain walker + V8 `JSON.stringify` reproduction (`_v8_json`), reused for the manifest hashes and per-row chain hash |
| `verify_bundle.py` | **Bundle verifier** for `run.occasio.json`, mirror of `src/bundle/verify.js` (the launch verifier) |
| `attest_verify.py` | Legacy verifier for the pre-cutover multi-file form (`.json` + `.sigstore.json` + chain) |

The Python `canonicalize` and the JS `canonicalize` must stay in lockstep. The two files exist in parallel deliberately — bundling them into one cross-compiled artifact would defeat the point of cross-language verifiability.

## Usage

```bash
# Verify a single-file evidence bundle (lenient — quick local check)
python docs/verify_bundle.py path/to/run.occasio.json

# Audit-grade: require signature + policy binding + git state
python docs/verify_bundle.py path/to/run.occasio.json --strict

# Or granular requirements
python docs/verify_bundle.py path/to/run.occasio.json --require-policy-binding --require-git-state

# Machine-readable output
python docs/verify_bundle.py --json path/to/run.occasio.json
```

Exit code 0 when every check passes, 1 otherwise. (The legacy `attest_verify.py` keeps the same CLI shape for the old multi-file form.)

## What the six checks prove

Identical to `occasio verify`, in the same order: **schema**, **manifest integrity** (embedded artifacts hash to the manifest, via the V8 `JSON.stringify` reproduction in `audit_walker._v8_json`), **chain slice integrity** (per-row hash recomputes + links, anchored to the attestation's `first_hash`/`last_hash`), **policy binding** (`sha256(policy_snapshot) == attestation.policy.file_hash`), **git state** (`deriveGitState(slice)` byte-matches `subject.git_state`), and **signature** (Sigstore valid + DSSE predicate matches; needs `pip install sigstore`). Under `--strict` the last-three skips become hard failures.

## Round-trip claim

For a `run.occasio.json` produced by `occasio bundle --sign`, the Python verifier produces the same pass/fail result as `occasio verify` on (proven by `test-bundle-xlang.js`):
- the unmodified bundle (both pass)
- a tampered chain row (both fail at *chain slice integrity*)
- a swapped policy snapshot (both fail at *policy binding*)
- a forged `subject.git_state` (both fail at *git state matches chain*)
- edited manifest bytes (both fail at *manifest integrity* — proves the `_v8_json` byte-equality)
- an unsigned bundle under `--strict` (both fail at *signature*)

The test suite covers cases 1, 2, and 3 deterministically with the Sigstore step mocked. The cross-language byte-equivalence on the predicate-canonicalization step is asserted via Python-spawn from the Node test runner (`xlang:` and `xlang-float:` test blocks); both implementations reject non-integer numbers so the equivalence cannot be silently broken by adding a float field to a future schema. Case 4 (real Sigstore tamper detection) requires GitHub Actions OIDC infrastructure and is exercised by the live Action's self-verify step in CI, not by the in-process test suite.

## Install hint for Sigstore step

```bash
pip install sigstore        # adds the Fulcio + Rekor verification step
```

Versions tracked: `sigstore-python >= 3.0`. The verifier degrades gracefully if a different major version is installed (the `Verifier` API is the stable surface used here).

## Limitations

- **Identity pinning is not enforced** by the reference verifier. The default `policy.UnsafeNoOp()` accepts any Fulcio cert. An auditor whose compliance regime requires a specific workflow-ref identity (e.g. `repo:org/repo:ref:refs/heads/main`) should adapt the call to `policy.Identity(...)`. Pattern intentionally exposed: this is a policy decision, not a verifier decision.
- **The Python canonicalize is a JCS subset**, not full RFC 8785. The deviations are documented inline in `canonicalize.py`. Non-integer numbers are explicitly rejected on both sides as a load-bearing cross-language invariant — see `canonicalize.py` and `src/attest/canonicalize.js` for the rationale.
