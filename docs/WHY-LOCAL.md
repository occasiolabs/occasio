# Why local

Occasio runs entirely on the machine you install it on. There is no Occasio cloud, no Occasio account, no Occasio API key. Your prompts, your tool calls, and your audit chain stay on local disk. The proxy is a process you start; the audit log is a file you own; the verifier is a CLI you can run offline.

## Data flow

```
                ┌──────────────────────────────────────┐
                │  Your machine                        │
                │                                      │
   your editor  │   AI agent (Claude Code, Cline,      │
   or CLI ───── │   MCP client, Computer Use)          │
                │             │                        │
                │             ▼                        │
                │   Occasio proxy on 127.0.0.1:<port>  │
                │   ├── Policy engine (decides)        │
                │   ├── Local executors (Read, Glob,   │
                │   │   Grep, TodoWrite, bounded shell)│
                │   ├── Auditor (hash-chained JSONL)   │
                │   └── outbound dispatcher            │
                │             │                        │
                └─────────────┼────────────────────────┘
                              │
                              ▼
                  Your configured LLM endpoint
                  (typically api.anthropic.com,
                  authenticated with your own key)

                  Local artefacts on disk only:
                    ~/.occasio/pipeline-events.jsonl  (audit chain)
                    ~/.occasio/policy.yml             (rules)
                    ~/.occasio/session.json           (run pointer)
                    ~/.occasio/logs/YYYY-MM-DD.jsonl  (per-request log)
```

The only network path Occasio creates is the outbound call from your machine to whichever LLM endpoint you configured. Authentication is your own API key, billed against your own account. Occasio is not in the path between you and that endpoint as a service; it is a library running in your process.

## What does not happen

- No telemetry endpoint, no beacon, no opt-out analytics. The npm package contains no fetch calls to any Occasio-controlled host.
- No aggregator service. There is no central database that collects per-user usage.
- No account creation or signup. Install with `npm install -g @occasiolabs/occasio` and run.
- No remote storage of prompts, responses, or tool outputs. The eyes capture (opt-in via `--eyes`) writes only to `~/.occasio/eyes/` on your disk.
- No third-party analytics dependencies. The npm install tree contains exactly two runtime deps (`proper-lockfile` and `sigstore`) and has no telemetry transit.

## How to verify

You do not need to take this on trust. The architecture is verifiable, and the most direct verification ships in the package:

```
occasio doctor --paranoid
```

This scans the installed source for every outbound network primitive and classifies each callsite (proxy-bound, LLM endpoint, signing infrastructure, local-loopback, hardcoded, unclassified). It checks for the signatures of known telemetry SDKs in both source and dependencies. It surfaces the audit chain's integrity status. The output is screenshot-grade and exits non-zero if any critical finding appears. A JSON form is available via `--paranoid --json` for tooling.

Additional cross-checks:

- **Source**: the project is Apache 2.0. Every line that touches your data is in `src/`. The paranoid doctor's source-scan covers every `.js` file under `src/` and `bin/`.
- **Tests**: `test-interceptor.js` and the suites it chains together exercise the proxy, the auditor, and the policy engine end to end. `test-paranoid.js` block 5 asserts the paranoid-doctor scan against the real source tree produces zero critical findings, so a future contribution that introduces a hardcoded outbound URL or a telemetry SDK fails CI. `npm test` runs the lot.
- **npm provenance**: published releases will carry npm-provenance attestations linking the published artefact to a specific GitHub source commit (lands with v0.10.0+).
- **Audit chain**: every governed action writes one row to a hash-chained JSONL on your disk. `occasio audit verify` re-walks the chain end-to-end. An independent Python walker at `docs/audit_walker.py` reproduces the verification using only the stdlib.

## Related

- [`docs/COMPARE.md`](COMPARE.md) describes where Occasio sits among AI agent observability tools at the deployment-model level.
- [`docs/SUSTAINABILITY.md`](SUSTAINABILITY.md) describes the revenue model and the architectural reasons it stays consistent with local-first.
- [`docs/AUDIT.md`](AUDIT.md) specifies the audit-chain row format precisely enough for third-party verification.
