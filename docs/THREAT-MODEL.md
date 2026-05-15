# Threat Model

This document is the first-party threat model for the occasio proxy.
Audience: security reviewers (internal, third-party), auditors evaluating
SOC2 / EU-AI-Act / NIST-AI-RMF alignment claims, and contributors
proposing changes that cross a trust boundary.

It is written using **STRIDE** (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege) over
the five trust boundaries enumerated below. STRIDE is the right framing
because the threats here are concrete data-flow concerns; privacy-class
risks (LINDDUN) are addressed only briefly because the proxy explicitly
does not store user content beyond the audit chain and the ledger.

Scope status: **first-party, unaudited.** This document reflects the
author's view of the system. It has not been reviewed by an external
party. Treat findings as starting points for an audit, not as evidence
that the system is audited.

## System overview

```
┌───────────────────┐   B1   ┌───────────────────┐   B2   ┌─────────────────┐
│   Claude Code     │ ◀────▶ │   occasio proxy   │ ◀────▶ │  Anthropic API  │
│   (or other CLI)  │  SSE   │   (interceptor)   │  TLS   │                 │
└───────────────────┘        └──┬──────────┬─────┘        └─────────────────┘
                                │          │
                              B3│          │B4
                                ▼          ▼
                       ┌──────────────┐   ┌──────────────────┐
                       │  MCP server  │   │  local FS / shell │
                       │  (parity)    │   │  (native handlers)│
                       └──────────────┘   └──────────────────┘
                                            │
                                          B5│
                                            ▼
                                  ┌─────────────────────┐
                                  │  audit chain +      │
                                  │  attestation bundle │
                                  └─────────────────────┘
```

### Trust boundaries

- **B1 — Agent ↔ Proxy.** The agent (Claude Code or another caller) is
  treated as **untrusted input** to the proxy. The proxy parses
  Anthropic SSE protocol, tool-use blocks, and follow-up headers.
- **B2 — Proxy ↔ Anthropic API.** The proxy is a TLS client of the
  upstream. The upstream is trusted as a service, not as an oracle —
  the proxy must not let upstream responses dictate local actions.
- **B3 — MCP path.** When invoked as `occasio-mcp`, the proxy speaks
  the MCP JSON-RPC frame protocol on stdin/stdout. Caller is
  untrusted; the wire format must not let a malformed frame escape.
- **B4 — Proxy ↔ local resources.** Native handlers read files and
  invoke shell subprocesses. Inputs originating from B1 reach this
  boundary as tool-use blocks. Path traversal, shell injection, and
  symlink-following are the concrete concerns here.
- **B5 — Audit / attest write surface.** The hash-chained JSONL ledger
  and the Sigstore-signed in-toto attestation bundles. The integrity
  guarantee is the basis for every compliance claim downstream.

## Out of scope

- **Operating-system privilege escalation.** If an attacker can already
  write to `~/.occasio/` or run code as the user, all bets are off.
  The proxy assumes filesystem ACLs on the home directory are intact.
- **TLS / cert-pinning of the upstream.** The proxy uses Node's default
  TLS stack against `api.anthropic.com`. We rely on the platform CA
  store. MITM with a CA-store compromise is out of scope.
- **Supply-chain compromise of `sigstore` or `proper-lockfile`.** These
  are the two runtime deps. Pinning + lockfile audit is the
  responsibility of the deployment, not the proxy.
- **Side-channels on the host (timing, cache, EM).** Out of scope.
- **Anthropic API quota exhaustion attacks.** Anthropic's concern, not
  the proxy's. The budget gate (`--budget`) reduces but does not
  eliminate cost exposure.

## STRIDE — boundary-by-boundary

### B1 — Agent ↔ Proxy (SSE / tool-use blocks)

| Class | Threat | Current mitigation | Residual |
|---|---|---|---|
| **S** | A non-Anthropic SSE-shaped payload pretending to be a tool-use block. | Tool-use blocks must match the schema enforced in `parseSSE`. Unknown `name` falls back to cloud (not executed locally). | If the agent itself is compromised, the proxy will faithfully execute whatever it asks. Out of scope (the agent is the trust source for the operator). |
| **T** | Modified SSE frames designed to inject extra tool-use blocks downstream. | The proxy re-emits a synthesized SSE stream to the agent — it does not blindly forward upstream bytes. Tool-use blocks are reconstructed from parsed structures. | A bug in `parseSSE` or `runOneRound` that lets a forged block slip through would defeat this. **Fuzz target.** |
| **R** | Agent denies having issued a tool call. | Every block is appended to `pipeline-events.jsonl` with `tool_inputs` captured (post-ARCH-27 governance milestone). The hash-chain makes selective deletion detectable. | The proxy cannot prove the agent's *intent* — only that the call was made. |
| **I** | A malicious tool-use response from the upstream leaks proxy state (cwd, env) back to the agent. | Native handlers never read process env vars and only resolve paths under `process.cwd()` (with explicit absolute-path opt-in for Read). Synthetic responses (`BLOCK`) are templated, not interpolated from upstream. | `expandPsEnvVars` resolves `$env:VAR` in PowerShell input. If a policy author writes a rule that echoes env-expanded input back, the value reaches the agent. Document this in policy-author guidance. |
| **D** | Huge SSE payload starves the proxy. | `MAX_OUTPUT` (512 KB) caps file reads; shell exec uses `maxBuffer: 512_000`. SSE chunks are processed streamingly, not buffered whole. | An attacker can still cause many small allocations. No per-connection rate limit. **Add later.** |
| **E** | Tool-use block escalates from a non-interceptable tool (e.g. `Write`) to a privileged dispatch path. | `isInterceptable` is a pure function on `block.name + block.input`; non-whitelisted names return `false` and always go to the cloud (where the agent's own confirmation prompts apply). | The proxy does not *prevent* the cloud from executing dangerous tools — it only declines to execute them locally. The policy engine's `deny_patterns` is the mechanism to actually block. Document the distinction. |

### B2 — Proxy ↔ Anthropic API

| Class | Threat | Current mitigation | Residual |
|---|---|---|---|
| **S** | A man-in-the-middle pretending to be `api.anthropic.com`. | Node TLS with system CA store. | No cert pinning. Out of scope per "Out of scope" above. |
| **T** | Upstream response modified to inject tool-use blocks the agent didn't authorize. | Tool-use blocks coming back are parsed structurally and dispatched through the same gate as user-originated blocks (`isInterceptable` → handler/cloud). A tampered upstream cannot achieve more than a malicious agent already could. | If the upstream is fully compromised, it can mint any tool-use block. The agent's local-confirmation UX is the final defense; the proxy does not add one. |
| **R** | Proxy denies having sent a request. | The audit chain records every `tool_use` row including `run_id`, `iso`, `cwd`. The cloud send itself is logged separately. Selective deletion is detectable via hash-chain verifier (`audit/verifier.js`). | The proxy cannot prove *what* it sent (only that a send happened) unless full-body capture is enabled. That is intentional to limit content exposure. |
| **I** | Secrets in tool output (cred files, env dumps) get sent upstream. | `scanSecrets` runs over Read output; `block_secrets` policy mode aborts the round. `redact_secrets` mode substitutes redacted tokens. | Pattern-based detection misses novel secret formats. No entropy-based detection. **Calibration gap.** |
| **D** | Cost-amplification: the upstream is induced to bill the operator (compromised agent in a loop). | `--budget N` gate: 80% warning, 100% block (402). | The block fires *after* the request that crosses the threshold. Single-call cost spikes are not pre-flighted. |
| **E** | Upstream-controlled `tool_use` block names a privileged action. | Whitelist-based interception; everything not on the list falls through and is shown to the agent. The agent's own confirmation governs whether it runs. | Defense-in-depth gap: the proxy does not add its own confirmation step. By design. |

### B3 — MCP path

| Class | Threat | Current mitigation | Residual |
|---|---|---|---|
| **S** | A non-MCP client speaking JSON-RPC into stdin. | JSON-RPC frames validated structurally (method whitelist, params schema in `mcp-normalize.js`). Unknown method → error response. | The MCP server inherits the trust profile of whoever spawned it (CLI parent process). |
| **T** | Frame splicing — partial JSON across multiple writes designed to confuse the parser. | Line-buffered (`split('\n')`); each line parsed independently. Malformed frames are dropped with a logged error (per `mcp-server.js` line 304). | Buffering is unbounded if no newline arrives. **Add a max-line-length gate.** |
| **R** | Same audit chain as B1; same guarantees. | `tools_mcp_count` and `mcp-experiment.jsonl` distinguish MCP rows from interceptor rows. | — |
| **I** | A response under MCP leaks more than the equivalent interceptor response. | `executeLocalTool` is the shared wrapper; both paths produce the same shape including `secrets` scan. | — |
| **D** | Same as B1. | — | No per-client rate limit. |
| **E** | A misconfigured MCP server runs in a different cwd than expected. | The cwd at spawn time is captured in `tool_use` rows (post-ARCH-26 cwd-in-log work). Path enforcement honours this cwd. | If two MCP servers share a `.occasio` log dir but different cwds, audit interpretation needs the row's cwd, not the verifier's cwd. Documented. |

### B4 — Proxy ↔ local FS / shell

| Class | Threat | Current mitigation | Residual |
|---|---|---|---|
| **S** | Symlink pointing at a sensitive file. Read tool dereferences. | `handleReadTool` uses `fs.readFileSync` which follows symlinks. Path-policy enforcement (`deny_paths`) is evaluated against the *resolved* path, not the requested path. | Race condition: TOCTOU between policy check and read. No `O_NOFOLLOW` on Node's fs API for sync calls. **Document; consider switching to `lstat`-then-`open` pattern.** |
| **T** | Shell command modified mid-flight to alter behaviour. | Shell strings are passed verbatim to `child_process.exec` with `maxBuffer`. No shell-string concatenation from upstream. | The native shell handler is the cleaner path — it never invokes a shell. Commands that fall back to `runLocally` do go through a shell. By design (existing user workflows depend on shell features). |
| **R** | A subprocess writes to the audit log to mask its activity. | Audit log lives under `~/.occasio/` and is opened append-only by the proxy itself. Subprocesses are spawned with the proxy's environment but do not inherit the file descriptor. | OS-level privesc covers this; out of scope. |
| **I** | Path traversal via `..` in Read input. | `handleReadTool` calls `path.resolve(process.cwd(), fp)` — this *does not* contain `..` escapes. Policy `deny_paths` then evaluates the resolved path. UNC / network paths (`\\server\share\…` and `//server/share/…`) are rejected at the `isReadHandleable` gate to prevent SMB-resolution DoS. **Fuzz-verified.** | Absolute paths are accepted by design (the agent often needs to read system files like `/etc/hosts`). The defense is the policy layer, not the handler. |
| **D** | `**/**/**/...` glob causing a deep walk. | `GLOB_MAX = 500` matches; `walkGlob` skips `node_modules`, `.git`, etc.; `GLOB_MAX_DEPTH = 16` caps recursion depth; `GLOB_MAX_MS = 2000` caps wall-clock per walk. Both env-tunable. | An attacker can still consume ~2 s per call. Stacking many calls in a round is the residual vector — partially covered by `--budget` (cost) but not by a per-round count cap. |
| **E** | `nativeHandle` executes a command it shouldn't (e.g. a `git` subcommand that mutates). | `isBareGitReadOnly` and `isGitCSegment` whitelist subcommands (status, log, diff, …). Unknown subcommands return `null` (= fall through, not execute). | The whitelist is the integrity guarantee. Regression in the whitelist is the highest-impact local bug class. **Fuzz target.** |

### B5 — Audit / attest

| Class | Threat | Current mitigation | Residual |
|---|---|---|---|
| **S** | A different process appends a forged row to `pipeline-events.jsonl`. | Hash-chain: each row's `prev_hash` is the SHA-256 of the previous canonical row. The verifier (`audit/verifier.js`) detects any insertion or modification. Optional file-locking (`proper-lockfile`) for multi-writer scenarios (audit v0.8.4). | If an attacker fully replays the chain (recomputing hashes), the GENESIS sentinel is the only fixed anchor. Bundle this into the Sigstore attestation for external attestability. |
| **T** | Selective deletion of rows. | Same. Chain verification fails on any gap. | — |
| **R** | Operator denies a tool call happened. | Sigstore-signed attestation bundles cryptographically commit to the chain head. | Signing is opt-in (`occasio attest sign`); a non-signing operator has only the local hash chain. |
| **I** | `tool_inputs` recorded in the chain contain secrets that propagate downstream. | Audit-time secret scanning is **not** applied; the chain captures inputs as-is for forensic value. The expectation is that operators consume the chain in a trusted environment. | If the chain is sent to a third party (compliance vendor), pre-redaction is the operator's responsibility. **Document this prominently.** |
| **D** | Audit write failure aborts the proxy. | `AuditWriteError` is intentionally session-fatal (per `pipeline.js` line 39). No silent fallback. | A consistently failing audit (full disk, permissions) bricks the proxy. This is the right tradeoff but it must be loud — currently is. |
| **E** | The `attest` CLI signs a bundle the chain does not support. | `canonicalize.js` produces a stable byte representation; `sign.js` signs that. Verification recomputes both. Any drift fails. | A bug in `canonicalize.js` is the single point of failure for the attestation pipeline. The "canonical-byte round-trip stable" test is the primary mitigation; broaden it. |

## Mitigation matrix — which control covers which boundary

| Control | B1 | B2 | B3 | B4 | B5 |
|---|---|---|---|---|---|
| `isInterceptable` whitelist | ✓ | — | ✓ | ✓ | — |
| `scanSecrets` | ✓ | ✓ | ✓ | — | — |
| `--budget` gate | — | ✓ | — | — | — |
| Native handler (no shell) | — | — | — | ✓ | — |
| `deny_paths` / `deny_patterns` | — | — | — | ✓ | — |
| Hash-chain audit | ✓ | ✓ | ✓ | ✓ | ✓ |
| Sigstore attestation | — | — | — | — | ✓ |
| `MAX_OUTPUT` / `GLOB_MAX` caps | — | — | — | ✓ | — |

## Residual risks worth naming

These are real and currently unmitigated:

1. **No per-connection rate limit** on the SSE interceptor or MCP server.
   DoS from a buggy or malicious agent is possible.
2. **No symlink-following control.** `handleReadTool` will follow a
   symlink that escapes `cwd`. Policy `deny_paths` against the *resolved*
   path is the only defense.
3. **Pattern-based secret detection only.** No entropy heuristic.
   `redact_secrets` mode mitigates accidental leaks; targeted exfil with
   custom-format keys would slip through.
4. **Anomaly detector calibrated on synthetic data.** FP-rate is
   documented but empirical baselines from real sessions are not yet
   gathered. The detector currently performs more like a smoke detector
   than a precision instrument.
5. ~~**No glob depth limit.**~~ **Addressed** in the same commit set as this
   document: `GLOB_MAX_DEPTH=16` and `GLOB_MAX_MS=2000` cap recursion and
   wall-clock per walk. A pathological symlink loop now stops at depth 16
   or 2 s, whichever fires first. Both are env-tunable.
6. **The whitelist in `isBareGitReadOnly` is the highest-impact integrity
   surface.** A regression that admits `git push` would let a compromised
   agent leak via the local git remote.
7. **Audit chain captures `tool_inputs` verbatim.** Operators sending
   the chain to third parties must pre-redact.
8. **Sigstore caret-pin (`^3.1.0`).** A compromised minor version of
   sigstore is admitted by the resolver. Lockfile commits help but do not
   eliminate this.
9. **No replay protection on the MCP frame parser.** A replayed valid
   frame is treated as a new request. Acceptable because the MCP server
   is stateless per call, but worth knowing.

## Verification mapping

| Mitigation | Where proven |
|---|---|
| `isInterceptable` whitelist correctness | `test-interceptor.js` §2, §19–§22 + `test-native-handlers.js` §1–§4 |
| Hash-chain tamper detection | `test-audit-chain.js` (86 tests inc. integrity, GENESIS, repair) |
| Sigstore round-trip | `test-attest.js` (58 tests) + CI-gated `test:e2e` |
| `deny_paths` enforcement | `test-policy-paths.js` (26 tests) |
| Public-API export drift | `test-native-handlers.js` §5 (drift guard) |
| Native handler robustness against adversarial inputs | `test-fuzz.js` (new — this commit) |

## Change protocol

Any change that crosses one of these boundaries must update this
document in the same PR. Changes inside a boundary (refactor, perf,
ergonomics) do not. The author judges; reviewers can require an update.
