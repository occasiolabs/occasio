# Reference Pipeline — from AI-agent PR to cryptographically-attested merge

End-to-end walkthrough of the Occasio attestation pipeline. Read top-to-bottom; every step has a copy-paste artefact and an explanation of what it proves.

## What this pipeline is for

When an AI coding agent (Claude Code, Cline, MCP-routed, etc.) opens a PR, the reviewer's question is *"What did the agent actually do?"* — every tool call, every blocked attempt, every secret redacted, under which policy, on what audit-chain commitment. This pipeline answers that question with a signed artifact that can be verified offline by any third party using only `cosign` and the published predicate type.

Three deliverables land on the PR:

1. A **Check Run** with a human-readable summary of the run.
2. A workflow **artifact** containing the signed predicate JSON and the Sigstore Bundle.
3. A **View Evidence** link that opens the standalone viewer page with both files pre-loaded.

## Try it locally in 30 seconds

```bash
occasio demo attest
```

This builds a synthetic audit chain, an unsigned attestation, runs the canonical-JSON round-trip check, and previews the Check Run summary. No Sigstore, no GitHub, no API key — just the pipeline working against in-memory data. Use this to validate the build end-to-end before deploying any of the rest.

## Step 1 — your agent runs under Occasio

A Occasio session must produce events into `~/.occasio/pipeline-events.jsonl`. The simplest way is to invoke Claude Code (or any supported agent) through the local proxy:

```bash
occasio claude --hardened
```

`--hardened` routes `Read`/`Glob`/`Grep` through the unified runtime so tool calls are intercepted locally, distillation applied, and secret scanning runs on every tool result. The `~/.occasio/session.json` file gets a fresh `run_id` per session.

## Step 2 — produce an attestation locally (sanity check)

After a session ends, run:

```bash
occasio attest --run-id "$(jq -r .run_id ~/.occasio/session.json)"
```

This writes `attestation.json` to the cwd. The predicate is unsigned (`signature: null`) — that part lands in the GitHub Action step below. Inspect the predicate; the file is human-readable JSON. The `audit_chain.last_hash` is the commitment: signing it later transitively commits to every event in the slice.

## Step 3 — drop in the GitHub Action

Create `.github/workflows/attest-on-pr.yml` in your repo:

```yaml
name: Attest AI-generated PR

on:
  pull_request:
    branches: [main]

permissions:
  id-token: write    # Sigstore keyless via GitHub OIDC
  checks:    write   # post the PR Check Run
  contents:  read

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 2     # so files-changed can diff HEAD^..HEAD

      # ── Your AI-agent step here ────────────────────────────────────
      # The agent must run under Occasio so its tool calls land in
      # ~/.occasio/pipeline-events.jsonl. Example with Claude Code:
      - run: npm i -g @occasiolabs/occasio @anthropic-ai/claude-code
      - run: occasio claude --hardened < .github/agent-prompt.txt
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      # ── Sign + Check Run ───────────────────────────────────────────
      - uses: occasiolabs/attest-action@v1
        # All inputs optional — run_id auto-resolves from session.json,
        # paths default to ~/.occasio/*. Defaults are tuned for the
        # 95% case.
```

That's it. The composite Action handles:
- `occasio attest --sign` using the workflow's OIDC token (no key management)
- Uploading `attestation.json` + `.sigstore.json` as a workflow artifact (90-day retention)
- Creating the Check Run via the GitHub API

## Step 4 — what reviewers see

The Check Run lands on the PR as:

```
✓ Occasio Attested · 47 calls · 2 blocked
  Claude Opus 4.7 · Policy strict-v2.1 (sha a126…3a)
  Chain ✓ verified · Signature ✓ Sigstore keyless
  [View evidence ↗]   [Artifact ↗]
```

Click **View evidence** to open the [viewer](https://occasiolabs.github.io/attest-view) with the artifact's two JSON files. The viewer runs two browser-side checks (DSSE-payload equivalence + audit-chain replay) and surfaces the Rekor transparency log link for cryptographic verification.

The viewer **deliberately does not** verify the Sigstore certificate chain in-browser — bundling Fulcio/Rekor trust roots in-browser is a serious build problem we have not solved cheaply, and we are honest about it on the page itself. Offline crypto-verification is one CLI call:

```bash
occasio attest verify occasio-attestation.json
```

That command runs three checks in order, all of which must pass:
1. Sigstore signature is valid (cert chain → Fulcio root, Rekor inclusion proof)
2. The DSSE payload inside the bundle byte-matches the attestation predicate (modulo `signature` field)
3. The audit chain integrity verifies end-to-end; the claimed `first_hash` / `last_hash` exist in the chain in the right relative order

## Step 5 — what auditors do

Auditors do not need access to the producer's machine. They download the workflow artifact, install Occasio (or `cosign`), and verify offline. The signed artifact is portable and self-contained: predicate JSON + Sigstore Bundle + (optionally) the chain file.

For a SOC2 audit period the workflow becomes:
1. Pull all `occasio-attestation` artifacts from the period (GitHub API)
2. For each: `occasio attest verify` and capture the exit code
3. Aggregate the `execution_summary` data: how many runs, how many blocks, what rules, what files

The audit chain is hash-linked across all of an agent's runs on the same machine; verifying any one slice does not require touching the producer's full log.

## Compatibility and what's stable

- **Predicate URI** `https://github.com/occasiolabs/occasio/spec/agent-attestation/v1` is **canonical**. It will not be moved or re-pointed.
- **Required fields** in v1 do not change without bumping the URI to `/v2`.
- **New optional fields** can land in v1.x (currently reserved: `subject.git_commit`, `subject.files_changed` — already in the schema, populated by the GitHub Action).
- The **Sigstore Bundle** is the standard `sigstore-bundle+json;version=0.2` shape — works with `cosign`, `sigstore-js`, `sigstore-python`, any future conformant tool.

## What this does NOT yet do

- **Multi-commit attestations.** Today the predicate binds to a single `run_id`. v1.1 will likely add `subject.git_commits[]` and a way to merge slices for a PR that includes N commits from M runs.
- **Embedded chain slice.** Today the chain-file path is advisory; the chain itself is not bundled. A v1.x option may add an embedded compressed chain for fully offline replay at a size cost.
- **Policy provenance.** `policy.file_hash` commits to the file bytes. We do not yet carry the *origin* of the policy (was it committed to a repo? signed by a security team?). v1.1 may add `policy.attestation_url` for nested signed claims.

## Reference / further reading

- [`spec/agent-attestation/v1/README.md`](../spec/agent-attestation/v1/README.md) — predicate type specification
- [`schemas/agent-attestation-v1.json`](../schemas/agent-attestation-v1.json) — authoritative JSON Schema
- [`integrations/attest-action/`](../integrations/attest-action/) — the GitHub Action
- [`integrations/attest-view/`](../integrations/attest-view/) — the static viewer page
