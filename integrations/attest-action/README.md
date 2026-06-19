# Occasio Attest — GitHub Action

Produce a Sigstore-signed AI-Agent Behavioral Attestation for a [Occasio](https://github.com/occasiolabs/occasio) session, attach it to the workflow run, and surface a GitHub Check on the pull request with a human-readable summary.

> **Predicate:** [`agent-attestation/v1`](https://github.com/occasiolabs/occasio/blob/main/spec/agent-attestation/v1/README.md)

## What you see in the PR

```
✓ Occasio Attested · 47 calls · 2 blocked
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

      # ... your AI-agent step here. The agent must run under Occasio,
      # so that ~/.occasio/pipeline-events.jsonl carries its tool calls.
      #
      # For example, if your CI uses Claude Code through occasio claude:
      # - run: npm i -g @occasiolabs/occasio @anthropic-ai/claude-code
      # - run: occasio claude < your-prompt.txt

      - uses: occasiolabs/occasio/integrations/attest-action@v1
        with:
          run-id: ''             # auto-resolves from ~/.occasio/session.json
```

## Inputs

| Name | Default | Description |
|---|---|---|
| `run-id` | _(empty)_ | Occasio run_id. Auto-resolves from `~/.occasio/session.json` if absent. |
| `chain-file` | `~/.occasio/pipeline-events.jsonl` | Path to the audit chain. |
| `policy-file` | `~/.occasio/policy.yml` | Path to the policy that governed the run. |
| `sign` | `true` | If `true`, Sigstore-sign via the workflow's OIDC token. |
| `occasio-version` | `latest` | Version of `@occasiolabs/occasio` to install. |
| `github-token` | `${{ github.token }}` | Token used to create the Check Run. |
| `view-base-url` | `https://occasiolabs.github.io/attest-view` | Base URL of the static View-Evidence page. |

## Outputs

| Name | Description |
|---|---|
| `bundle-path` | Filesystem path to the single-file evidence bundle `run.occasio.json`, verifiable with `occasio verify`. |
| `attestation-path` | Back-compat alias for `bundle-path` (same single file). |
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

The artifact written by this action is a single self-contained evidence bundle, `run.occasio.json` (schema `occasio-bundle/v1`): it embeds the [`agent-attestation/v1`](https://github.com/occasiolabs/occasio/blob/main/spec/agent-attestation/v1/README.md) predicate, the run's audit-chain slice, the exact policy snapshot, and — when signed — the Sigstore Bundle (Fulcio cert bound to this workflow's OIDC identity, Rekor transparency log entry).

The action **self-verifies** the signed bundle with `occasio verify --strict` in the same CI run before publishing the artifact. If any check fails the action fails, so no broken bundle ever reaches a consumer. This is the real-OIDC end-to-end round-trip the test suite cannot exercise locally.

To re-verify offline at any time, install Occasio and run:

```bash
npm install -g @occasiolabs/occasio
occasio verify --strict run.occasio.json
```

The verifier performs six independent checks and refuses any single failure:
1. Schema + required keys present.
2. Manifest integrity: the embedded artifacts hash to the manifest.
3. Audit-chain slice integrity end-to-end, anchored to the attestation's `first_hash` / `last_hash`.
4. Policy binding: the embedded policy bytes match `attestation.policy.file_hash`.
5. Git state: `attestation.subject.git_state` re-derives from the embedded chain slice.
6. Signature: the Sigstore bundle is valid and its DSSE payload matches the embedded predicate.

For an independent, Occasio-code-free check, an auditor can run the reference Python verifier on the same file: `python docs/verify_bundle.py run.occasio.json --strict`.

## License

Apache-2.0. Same license as the [Occasio](https://github.com/occasiolabs/occasio) repository.
