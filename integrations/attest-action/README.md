# LocalFirst Attest — GitHub Action

Produce a Sigstore-signed AI-Agent Behavioral Attestation for a [LocalFirst](https://github.com/localfirst-ai/localfirst) session, attach it to the workflow run, and surface a GitHub Check on the pull request with a human-readable summary.

> **Predicate:** [`agent-attestation/v1`](https://github.com/localfirst-ai/localfirst/blob/main/spec/agent-attestation/v1/README.md)

## What you see in the PR

```
✓ LocalFirst Attested · 47 calls · 2 blocked
  Claude Opus 4.7 · Policy strict-v2.1 (sha a126…3a)
  Chain ✓ verified · Signature ✓ Sigstore keyless
  [View evidence ↗]   [Artifact ↗]
```

A Check Run with that summary lands on every PR. Reviewers click *View evidence* to open the standalone viewer page; auditors download the artifact for offline verification.

## Quick start

```yaml
# .github/workflows/attest-ai-pr.yml
name: Attest AI-generated PR

on:
  pull_request:
    branches: [main]

permissions:
  id-token: write    # OIDC for Sigstore keyless
  checks:    write   # write the PR Check Run
  contents:  read

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 2          # so files-changed can diff HEAD^..HEAD

      # ... your AI-agent step here. The agent must run under LocalFirst,
      # so that ~/.localfirst/pipeline-events.jsonl carries its tool calls.
      #
      # For example, if your CI uses Claude Code through localfirst claude:
      # - run: npm i -g @localfirst-ai/localfirst @anthropic-ai/claude-code
      # - run: localfirst claude < your-prompt.txt

      - uses: localfirst-ai/attest-action@v1
        with:
          run-id: ''             # auto-resolves from ~/.localfirst/session.json
```

## Inputs

| Name | Default | Description |
|---|---|---|
| `run-id` | _(empty)_ | LocalFirst run_id. Auto-resolves from `~/.localfirst/session.json` if absent. |
| `chain-file` | `~/.localfirst/pipeline-events.jsonl` | Path to the audit chain. |
| `policy-file` | `~/.localfirst/policy.yml` | Path to the policy that governed the run. |
| `sign` | `true` | If `true`, Sigstore-sign via the workflow's OIDC token. |
| `localfirst-version` | `latest` | Version of `@localfirst-ai/localfirst` to install. |
| `github-token` | `${{ github.token }}` | Token used to create the Check Run. |
| `view-base-url` | `https://localfirst-ai.github.io/attest-view` | Base URL of the static View-Evidence page. |

## Outputs

| Name | Description |
|---|---|
| `attestation-path` | Filesystem path to `localfirst-attestation.json`. |
| `bundle-path` | Filesystem path to `localfirst-attestation.sigstore.json`. |
| `check-run-url` | URL of the created GitHub Check Run. |
| `rekor-entry` | Rekor transparency log search URL (when signed). |

## Permissions

For Sigstore keyless signing the workflow **must** grant `id-token: write`. For the Check Run it **must** grant `checks: write`. Use the minimum:

```yaml
permissions:
  id-token: write
  checks: write
  contents: read
```

## How verification works

The attestation file written by this action is a self-contained JSON object conforming to the [`agent-attestation/v1`](https://github.com/localfirst-ai/localfirst/blob/main/spec/agent-attestation/v1/README.md) predicate. The accompanying Sigstore Bundle (`.sigstore.json`) is signed by a short-lived Fulcio certificate bound to this workflow's OIDC identity, with a Rekor transparency log entry.

The action **self-verifies** the signed attestation in the same CI run before publishing the artifact — Sigstore signature, DSSE-payload-equivalence, and audit-chain integrity all checked. If any check fails the action fails, so no broken attestation ever reaches a consumer. This is the real-OIDC end-to-end round-trip the test suite cannot exercise locally.

To re-verify offline at any time, install LocalFirst and run:

```bash
npm install -g @localfirst-ai/localfirst
localfirst attest verify localfirst-attestation.json
```

The verifier performs three independent checks and refuses any single failure:
1. Sigstore signature is valid (cert chain → Fulcio root, Rekor inclusion proof).
2. The DSSE payload inside the bundle byte-matches the attestation predicate.
3. The audit chain integrity verifies end-to-end; the claimed `first_hash` / `last_hash` exist in the chain in the right order.

## License

Apache-2.0. Same license as the [LocalFirst](https://github.com/localfirst-ai/localfirst) repository.
