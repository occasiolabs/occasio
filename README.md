# Occasio

> Cryptographically verifiable behavioral attestation for AI coding agents.

When an AI agent writes code in your CI, the question a reviewer or auditor will ask is not *"what did it produce"* — it is *"what did it actually do"*. Which files did it read. Which it was blocked from reading. Which secrets it tried to leak. Which policy was in effect. Whether that record can be trusted six months later.

Occasio sits between the agent and the cloud on your own machine, decides every tool call against one human-readable policy, writes a tamper-evident audit chain of every decision, and produces signed attestations that a third party can verify offline using only `cosign` or a 200-line Python script.

```bash
npm install -g @occasiolabs/occasio

occasio demo attest      # End-to-end attestation pipeline (30s, no API key)
occasio demo anomalies   # Live EDR detection on a synthetic adversarial chain (5s)
occasio harness          # Real Claude Code attacking a denied path — defense holds
```

The first two demos run against synthetic data so you can see the full pipeline in under a minute with no external dependencies. The third spawns a real Claude Code subordinate under your Anthropic login (bundled auth — no API key required) and proves the defense end-to-end.

---

## What it does, in four layers

**Layer 1 — Tool-call interception.** A local proxy sits between the agent and the Anthropic API. `Read`, `Glob`, `Grep`, `TodoRead`/`TodoWrite`, and a curated set of read-only shell commands (`cat`, `head`, `git status`, `git log --oneline -N`, `ls`, `find`) run in-process on your machine. The file bytes never enter the outbound request.

**Layer 2 — Policy enforcement.** Every tool call hits one decision: `LOCAL` / `PASS` / `BLOCK` / `TRANSFORM`, driven by [`policy.yml`](policy-templates/dev-default.yml). `deny_paths` is enforced on the realpath-resolved absolute path so symlinks and traversal variants resolve to the same denial. `block_secrets_in_tool_results` redacts API keys and JWTs out of any tool output before it re-enters the prompt. Hot-reload: edits to `policy.yml` take effect on the next call, with a `policy_loaded` row written to the audit chain.

**Layer 3 — Behavioral attestation.** `occasio attest --run-id <uuid>` produces a self-contained JSON predicate that commits to the full audit-chain slice for one agent session: every tool call, every block, every transform, every redacted secret, plus the active policy's SHA-256 hash and rules digest. `--sign` wraps it in an [in-toto Statement v1](https://github.com/in-toto/attestation) and Sigstore-signs it using GitHub Actions OIDC (no key management). The predicate type URI is [`agent-attestation/v1`](spec/agent-attestation/v1/README.md). Two independent reference verifiers ship — Node (`occasio attest verify`) and Python ([`docs/attest_verify.py`](docs/attest_verify.py)) — and the test suite asserts they agree byte-for-byte on the same payload.

**Layer 4 — Anomaly detection (EDR).** `occasio anomalies` runs four detectors over a time window of the audit chain: deny-rate spike, file-read-volume burst, previously-unseen tool-input shape, secret-redaction-rate spike. Severity escalates against your historical baseline — a ×500 deviation from normal triggers HIGH; see [`docs/edr-demo.md`](docs/edr-demo.md) for the reproducible defense-in-depth walkthrough.

---

## Why now

Three regulatory drivers, all converging on the same requirement: **runtime evidence of AI-agent behavior must be cryptographically verifiable.**

- **EU AI Act Art. 12** mandates comprehensive automated logging of high-risk AI systems. In effect from 2026 for regulated sectors.
- **NIST AI RMF (GOVERN, MEASURE, MANAGE families)** is becoming required in US Federal procurement and is influencing FedRAMP AI controls.
- **SOC 2 Common Criteria** are extending to AI-agent controls — auditors at major firms started asking "show me the agent's tool-call log" in 2026 audits.

There is currently no off-the-shelf product producing a signed, third-party-verifiable artifact for what an AI coding agent did inside your CI. Occasio fills that gap with an open schema (Apache-2.0) and ships the reference implementations for it.

---

## Quickstart

Requires Node.js ≥ 18. Works on Windows, macOS, Linux.

```bash
npm install -g @occasiolabs/occasio   # Install
occasio doctor                          # Verify setup (Node, claude CLI, port, profile)
occasio policy init                     # Write ~/.occasio/policy.yml (dev-default)
occasio register                        # Add 'claude' shell alias (one-time)
claude "read package.json and tell me the version"
```

After the alias is registered, every `claude` invocation routes through Occasio transparently. Audit-chain rows accumulate at `~/.occasio/pipeline-events.jsonl`.

**Inspect the run:**

```bash
occasio status                  # Session totals
occasio replay --detail         # Run-level audit
occasio audit verify            # Re-walk the hash chain end-to-end
occasio anomalies               # Run EDR detectors over the last 15 minutes
occasio attest --run-id <uuid>  # Build a behavioral attestation for one session
```

---

## Commands

| Command | What it does |
|---|---|
| `occasio claude [args]` | Start Claude Code with Occasio proxy active |
| `occasio register` | Register `claude` shell alias |
| `occasio doctor` | Setup health-check |
| `occasio status` | Session totals + savings breakdown |
| `occasio replay` | Run-level audit (`--detail`, `--run <id>`, `--attribute`) |
| `occasio inspect` | Per-request cloud-boundary manifest |
| `occasio boundary` | Three-column view: produced / re-entered / prevented |
| `occasio ledger` | Per-request token ledger |
| `occasio distill` | Inspect distilled tool outputs |
| `occasio dashboard` | Live browser dashboard at http://localhost:3001 |
| `occasio audit verify` | Re-walk the SHA-256 audit chain end-to-end |
| `occasio audit repair --file <path>` | Truncate a crash-partial trailing line (writes `.bak`) |
| `occasio report` | Governance summary export (`--days N`, `--format csv`) |
| `occasio anomalies` | EDR detection over the audit chain (`--window 15m`, `--json`) |
| `occasio attest --run-id <uuid>` | Build a behavioral attestation predicate v1 |
| `occasio attest --sign` | Sigstore-sign via GitHub Actions OIDC |
| `occasio attest verify <file>` | Re-verify a signed attestation end-to-end |
| `occasio policy [show \| validate \| init \| doctor]` | Policy authoring + diagnosis |
| `occasio harness` | Run scripted adversarial scenarios against your policy |
| `occasio redteam` | Autonomous tester-LLM probes a subject Claude Code session |
| `occasio computer-use --dry-run` | Apply a Computer-Use policy to synthetic tool_use blocks |
| `occasio demo attest` | End-to-end attestation pipeline against a synthetic chain |
| `occasio demo anomalies` | EDR smoke test: synthetic adversarial chain → all 4 detectors |
| `occasio selftest` | In-process governance self-checks on a scratch chain |
| `occasio baseline [learn \| compare]` | Per-project behavior baseline + drift detection |
| `occasio preflight` | Read-only mine of recent activity for policy suggestions |

Session-level overrides on top of `policy.yml`:

| Flag | Effect |
|---|---|
| `--preset strict` | Forces `block_secrets_in_tool_results` on for the session |
| `--preset off` | Pure passthrough, log only |
| `--budget <N>` | Hard cap: HTTP 402 once session cost reaches $N |
| `--hardened` | Routes Read/Glob/Grep through unified runtime + distill + secret scan |

---

## Verification

Three independent checks, all required for a verified attestation:

1. **Sigstore signature** — Fulcio certificate chain + Rekor inclusion proof. Verifiable by any sigstore-conformant tool (`cosign verify-blob`, `sigstore-js`, `sigstore-python`).
2. **DSSE payload ↔ attestation predicate equivalence** — re-decode the in-toto Statement inside the bundle, canonicalise the predicate via [RFC 8785 subset](src/attest/canonicalize.js), compare byte-for-byte with the attestation predicate (minus the `signature` metadata field).
3. **Audit chain integrity** — SHA-256-walk every `prev_hash → hash` link from the GENESIS sentinel, then assert the attestation's `first_hash` and `last_hash` appear in the chain in the right relative order.

Two reference verifiers ship side by side:

- **Node**: `occasio attest verify <file>`
- **Python**: `python docs/attest_verify.py <file>` — stdlib + optional `sigstore-python`, reuses [`docs/audit_walker.py`](docs/audit_walker.py) for the chain step. See [`docs/python-verifier.md`](docs/python-verifier.md).

**Cross-language invariant** (asserted in the test suite as `xlang:` and `xlang-float:` cases): both verifiers agree byte-for-byte on the predicate-equivalence and audit-chain steps for the same payload, including tamper-detection cases. Non-integer numbers are rejected by both canonicalize implementations so a future schema cannot silently introduce divergence.

The **Sigstore signature step** uses the standard DSSE-wrapped in-toto Statement format; any sigstore-conformant tool verifies it (`cosign verify-blob`, `sigstore-js`, `sigstore-python`). The test suite mocks the signing path; a real-OIDC end-to-end signed-and-verified round-trip requires a GitHub Actions environment and is exercised by the [`integrations/attest-action/`](integrations/attest-action/) workflow in CI.

A third partial verifier runs in-browser at [`integrations/attest-view/`](integrations/attest-view/) for drag-and-drop inspection. The browser performs the predicate-equivalence and audit-chain steps but defers Sigstore certificate-chain verification to one of the two CLIs (bundling Fulcio/Rekor trust roots in-browser is intentionally not done; the page is explicit about it).

---

## Architecture

```
agent (Claude Code / Cline / MCP / Computer Use)
  │
  ▼  tool call
┌──────────────────────────────────────────────────────────────┐
│  Occasio proxy                                            │
│                                                              │
│  Layer 1: adapter parse → canonical event                    │
│  Layer 2: policy decision (LOCAL / PASS / BLOCK / TRANSFORM) │
│  Layer 2: deny_paths + deny_patterns + secret redaction      │
│  Layer 2: native dispatch for LOCAL/TRANSFORM tools          │
│           ──► row appended, SHA-256-chained                  │
│  Layer 4: anomaly detectors (windowed, on-demand or live)    │
└──────────────────────────────────────────────────────────────┘
  │
  ▼  cloud-bound: only PASS calls, with shaped result if TRANSFORM
Anthropic API

End of session
  │
  ▼  occasio attest --run-id … --sign
Layer 3: signed in-toto Statement → Sigstore bundle → GitHub Check Run
  │
  ▼  independent verifier
Node / Python / cosign — all must agree
```

---

## Log format

All data is stored locally at `~/.occasio/`:

```
~/.occasio/
  pipeline-events.jsonl        # tamper-evident audit chain (SHA-256 linked)
  policy.yml                   # active policy
  session.json                 # current run_id, totals
  logs/YYYY-MM-DD.jsonl        # per-request log
  baseline/<cwd-hash>.json     # per-project behavior baseline (opt-in)
```

The audit-chain row schema is documented in [`docs/AUDIT.md`](docs/AUDIT.md). Each row carries `prev_hash` and `hash` (SHA-256 hex), with the first row chained from a fixed GENESIS sentinel (64 zeros). `occasio audit verify` and `docs/audit_walker.py` are independent implementations of the walker.

---

## Demos

- [**EDR defense-in-depth**](docs/edr-demo.md) — real Claude Code attacking a denied path under your policy, all blocks held, EDR fires HIGH ×100–×1000 over baseline. Reproducible in <2 minutes.
- [**Reference Pipeline**](docs/reference-pipeline.md) — PR with AI-agent → GitHub Action signs attestation via Sigstore keyless → Check Run on the PR → independent verification offline.
- [**Cross-protocol governance**](docs/demos/mcp-block.md) — the same `deny_paths` rule producing identical `BLOCK` rows under Claude Code's HTTP proxy and the MCP server.

---

## Reference

- [`spec/agent-attestation/v1/README.md`](spec/agent-attestation/v1/README.md) — predicate type specification
- [`schemas/agent-attestation-v1.json`](schemas/agent-attestation-v1.json) — authoritative JSON Schema
- [`docs/AUDIT.md`](docs/AUDIT.md) — audit-chain row schema and canonical-serialisation rules
- [`docs/compliance-mapping.md`](docs/compliance-mapping.md) — SOC 2 Common-Criteria mapping
- [`docs/python-verifier.md`](docs/python-verifier.md) — independent Python verifier
- [`docs/edr-demo.md`](docs/edr-demo.md) — defense-in-depth walkthrough
- [`docs/reference-pipeline.md`](docs/reference-pipeline.md) — end-to-end CI pipeline
- [`integrations/attest-action/`](integrations/attest-action/) — GitHub Action that signs + posts a Check Run
- [`integrations/attest-view/`](integrations/attest-view/) — static browser viewer for attestation files

---

## Requirements

- **Node.js ≥ 18**
- **Claude Code** (`npm install -g @anthropic-ai/claude-code`) — or any agent that respects `ANTHROPIC_BASE_URL`
- **Python 3** (optional) — required for the independent verifier and LAO context trimming
- **`sigstore-python`** (optional) — adds the cryptographic Sigstore step to the Python verifier

---

## License

Occasio is open source under the [Apache License 2.0](LICENSE), including an explicit patent grant for safe enterprise use. Versions 0.6.6 and earlier were released under the MIT License and remain MIT in perpetuity for those releases.

Contributions are accepted under Apache-2.0; please sign off your commits per the [DCO](https://developercertificate.org/) (`git commit -s`).
