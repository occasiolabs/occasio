# AI-Agent Behavioral Attestation v1

**Predicate type URI:** `https://github.com/localfirst-ai/localfirst/spec/agent-attestation/v1`

**Status:** Draft 1 (v1.0.0). Tracked at [`schemas/agent-attestation-v1.json`](../../../schemas/agent-attestation-v1.json).

**License:** Apache-2.0.

## What this predicate claims

A signed cryptographic statement about **what an AI coding agent did during a single bounded session**, including every governed tool call, every blocked attempt, every transform applied to a tool result, and the active policy that produced those decisions — all bound to a tamper-evident audit chain.

The predicate answers the question **"What did the AI agent actually do while producing this artifact?"** — which is orthogonal to, and complementary with:

- **SLSA Provenance** (what build process produced the artifact)
- **CycloneDX ML-BOM / AIBOM** (what model + training data sit in the AI system)

None of those predicate types describe **runtime behavioral integrity**: which files were read, which were blocked, which secrets were redacted, which policy was enforcing the call. This predicate fills that gap.

## Use cases

- A pull request opened by an AI coding agent ships an attestation as a GitHub Check. A reviewer sees `47 tool calls · 2 blocked · 1 secret redacted` before merge.
- A SOC2 auditor receives signed attestations covering every AI-assisted change in the audit period and re-walks the chain offline using an independent verifier.
- An enterprise mandates that every vendor's AI-agent contribution carries a behavioral attestation conformant to this predicate type.

## Envelope

This predicate is intended to be wrapped in an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) and signed via [Sigstore](https://www.sigstore.dev/) (keyless, GitHub OIDC). The Statement carries:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://github.com/localfirst-ai/localfirst/spec/agent-attestation/v1",
  "subject": [{
    "name":   "localfirst:run:<uuid>",
    "digest": { "sha256": "<last_hash from the run's audit chain slice>" }
  }],
  "predicate": { /* the v1 object below */ }
}
```

The `subject.digest.sha256` is the `last_hash` of the audit-chain slice attested by this predicate. Because the chain hash-links every event back to the GENESIS sentinel via `prev_hash → hash`, signing this single hash transitively commits to every event in the slice.

## Predicate fields (v1.0.0)

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | yes | `"1.0.0"` |
| `predicate_type` | string | yes | Constant: predicate URI above |
| `subject.run_id` | string | yes | UUID identifying the agent session |
| `subject.git_commit` | string \| null | no | Set in CI when the attestation is bound to a commit |
| `subject.files_changed` | string[] | no | Paths modified during the run |
| `agent.platform` | string | yes | e.g. `claude-code`, `cline`, `mcp` |
| `agent.model` | string \| null | yes | Model ID, if surfaced by the adapter |
| `agent.session_id` | string \| null | yes | Adapter-level session ID |
| `agent.started_at` | RFC 3339 | yes | First event in slice |
| `agent.ended_at` | RFC 3339 | yes | Last event in slice |
| `agent.wall_time_s` | integer | yes | Elapsed seconds |
| `policy.file_hash` | hex-64 | yes | SHA-256 of the active policy.yml bytes (or `0`*64 when no file) |
| `policy.file_path` | string \| null | yes | Path on the producer's machine |
| `policy.source` | enum | yes | `user`, `default`, `unknown`, or `inferred` (see below) |
| `policy.version` | integer \| null | yes | Policy file `version:` field |
| `policy.rules_digest` | object | yes | `deny_paths_count`, `deny_patterns_count`, `block_secrets` |
| `execution_summary.tool_calls` | integer | yes | Total in slice (excluding policy events) |
| `execution_summary.local` | integer | yes | `LOCAL` decisions |
| `execution_summary.passed` | integer | yes | `PASS` decisions |
| `execution_summary.blocked` | integer | yes | `BLOCK` decisions |
| `execution_summary.transformed` | integer | yes | `TRANSFORM` decisions |
| `execution_summary.secrets_redacted` | integer | yes | Σ secrets redacted across slice |
| `execution_summary.blocked_events` | array | no | One entry per BLOCK with `tool`, `target`, `rule`, `at_offset_s` |
| `audit_chain.genesis` | hex-64 | yes | Constant: 64 zeros |
| `audit_chain.first_hash` | hex-64 \| null | yes | Hash of first row in slice |
| `audit_chain.last_hash` | hex-64 \| null | yes | Hash of last row in slice |
| `audit_chain.event_count` | integer | yes | Number of rows in slice |
| `audit_chain.chain_file` | string | yes | Path to the chain file (advisory) |
| `audit_chain.verifier_url` | URI | yes | Where to fetch the independent verifier |
| `signature` | object \| null | yes | `null` for unsigned; populated when Sigstore-signed |
| `generated_at` | RFC 3339 | no | Producer timestamp |

The full JSON Schema (Draft-07) is the authoritative source: [`schemas/agent-attestation-v1.json`](../../../schemas/agent-attestation-v1.json).

### `policy.source` values

- `user` — a `policy_loaded` event was observed inside the run slice and the active policy came from a user-supplied file.
- `default` — a `policy_loaded` event was observed and the producer was running on its built-in default policy.
- `unknown` — a `policy_loaded` event was observed but its `policy_source` field was not set.
- `inferred` — **no `policy_loaded` event was found in the slice.** The producer fell back to hashing the policy file's bytes *at attest time*, which may have been edited after the run ended. Verifiers SHOULD treat `inferred` as weaker evidence than the other three and surface this distinction to the user.

## Verification model

A consumer of an attestation must perform three independent checks, in order, all of which must pass:

1. **Sigstore signature.** Verify the Sigstore Bundle's certificate chain (Fulcio root) and inclusion proof (Rekor transparency log). This proves *who* produced the predicate.
2. **Predicate ↔ payload equivalence.** Re-decode the DSSE envelope inside the Sigstore Bundle, parse its payload as an in-toto Statement, and compare its `predicate` (modulo the `signature` metadata field) byte-for-byte with the attestation JSON in hand. This proves *that the predicate file has not been swapped*.
3. **Audit chain integrity.** Re-walk the `chain_file` end-to-end using the canonical SHA-256 walker, and confirm that `first_hash` and `last_hash` appear in that chain in the correct relative order. This proves *the predicate reflects events that actually happened*.

Each check is a hard requirement. A consumer that skips any of them is not verifying this predicate.

A reference verifier is available at [`docs/audit_walker.py`](../../../docs/audit_walker.py) for the chain step. The Sigstore signature is verifiable by any [sigstore-conformant](https://www.sigstore.dev/) tool — `cosign verify-blob`, `sigstore-js`, or `sigstore-python`. The full verifier (all three steps in one call) ships as `localfirst attest verify`.

## Compatibility and stability

- **Breaking changes** to required fields require a new predicate URI (`/v2`, etc.).
- **Additive changes** (new optional fields) are permitted in `v1.x` and do not bump the URI.
- The predicate URI in this spec is **canonical and stable**. It will not be moved or re-pointed.
- Consumers MUST refuse to verify attestations whose `predicate_type` does not match exactly.

## Relationship to other specifications

| Spec | Relationship |
|---|---|
| [in-toto Attestation Framework](https://github.com/in-toto/attestation) | Carrier envelope. This predicate type is a v1 in-toto Statement payload. |
| [SLSA Provenance](https://slsa.dev/spec/v1.0/provenance) | Complementary. SLSA describes builds; this predicate describes AI-agent runtime behavior. |
| [CycloneDX ML-BOM / OWASP AIBOM](https://cyclonedx.org/capabilities/mlbom/) | Complementary. ML-BOM describes models/data; this predicate describes session-level agent actions. |
| [Sigstore](https://www.sigstore.dev/) | Signing transport. Reference implementation uses Sigstore keyless via GitHub OIDC. |

## Open questions (tracked for v1.1 / v2)

- **Multi-commit attestations.** Today the attestation binds to a single `run_id`. A natural extension: one attestation per PR covering N commits from M runs. v1.1 will likely add `subject.git_commits[]` and a way to merge slices.
- **Policy provenance.** Today `policy.file_hash` commits to the file bytes. We do not carry the *origin* of the policy (was it committed to a repo? signed by a security team?). v1.1 may add `policy.attestation_url` for nested signed claims.
- **Event-level disclosure.** Today the chain-file path is advisory; the chain itself is not bundled. A v1.x option may add an embedded compressed chain slice for fully offline verification, at a size cost.

## Reference implementation

The producing CLI, full verifier, JSON Schema, and an independent Python audit-chain walker live in [`localfirst-ai/localfirst`](https://github.com/localfirst-ai/localfirst). The reference Sigstore-signed attestations from that repo's own CI runs serve as conformance examples (Phase 3 of the rollout plan).

## Authors and contributions

Apache-2.0 licensed. Issues and pull requests at [`localfirst-ai/localfirst`](https://github.com/localfirst-ai/localfirst). Predicate-type submissions to the [in-toto attestation registry](https://github.com/in-toto/attestation) tracking once production usage and external adopters reach the registry's bar.
