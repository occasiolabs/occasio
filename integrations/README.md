# Integrations

Standalone artifacts that are **distributed as their own repositories** but live here during development so they share a commit history with the LocalFirst engine.

| Directory | Eventual location | Purpose |
|---|---|---|
| [`attest-action/`](attest-action/) | `localfirst-ai/attest-action` (GitHub Action) | Composite Action that produces a Sigstore-signed [`agent-attestation/v1`](../spec/agent-attestation/v1/README.md) for an AI-agent PR and creates a Check Run summarising it. |
| [`attest-view/`](attest-view/) | `localfirst-ai/attest-view` (GitHub Pages) | Static viewer page that renders an attestation, walks the audit chain in-browser, and links to the Rekor transparency log. |

Each subdirectory carries its own `README.md` and is self-contained: nothing here imports from `../src` or `../bin`. When the corresponding public repositories are created, these directories will be copied (or `git subtree split`-ed) into them and removed from the main repo.

This staging arrangement is **temporary** and exists so Phase 2 can ship as a single coherent diff. Phase 3 will perform the repository extraction.
