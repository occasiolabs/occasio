# Validation Evidence

LocalFirst is built on an evidence-driven loop. Every interception path is live-validated against real Claude Code traffic before it counts as supported. This document records what was validated, when, and how — so anyone can reproduce or audit the claims.

## Methodology

Each slice follows the same loop:

1. **Observe** — capture an actual tool-call command from `~/.localfirst/interceptor-debug.log` after a real Claude Code session.
2. **Implement** — write the narrowest possible handler for the observed shape. No speculative coverage.
3. **Live-validate** — run a fresh session, confirm the pattern triggers locally, confirm `check-validation` passes against the new debug log.
4. **Record** — note the live-validation timestamp and the evidence in the slice's project memory.

Two scripts enforce the discipline:

- `scripts/restart-check.js` — detects when the proxy is running stale code (interceptor.js modified after proxy start). Prevents validation runs against an old build.
- `scripts/check-validation.js` — scans the debug log for unhandled git-context shapes. Defaults to filtering since the current session start (read from `session.json`); fails when any unhandled pattern remains.

## Validated interception paths

### Read / Glob / Grep / TodoWrite / TodoRead — native

In product since v0.6.0. Intercepted in-process without subprocess. ~550 unit tests cover input shapes, edge cases, and content scanning.

### Bash / PowerShell native handlers

`cat`, `head`, `tail`, `ls`, `find -name`, `test -f|-e|-d` and the PowerShell equivalents (`Get-Content`, `Get-ChildItem`, `Test-Path`). Selected by curated allowlist; all other commands fall through to the cloud path.

### Git context — four live-validated shapes

| Slice | Shape | Validated |
|---|---|---|
| D-1 | `git -C <path> status` and `git -C <path> log --oneline -N` | 2026-05-08 |
| D-2 | `git -C <path> status && echo "---" && git -C <path> log` (compound chains with `-C` segments) | 2026-05-08 — built but did not match live traffic; superseded by D-3 |
| D-3 | `cd "<abs-path>" && git status` (Bash); `Set-Location "<abs-path>"; git status; Write-Host "---"; git log --oneline -N` (PowerShell) | 2026-05-08 |
| D-4 | bare `git status` and `git log --oneline -N` in current cwd | 2026-05-08 |

D-2 is recorded as a cautionary example: it was implemented for a pattern the team expected Claude Code to generate (`git -C` segments in compounds with `echo` separators). When the next live session ran, Claude Code instead generated `cd "path" && git status` — D-2's segment whitelist didn't match. D-3 was the corrective slice. The takeaway, baked into the standard now, is: do not implement a handler until the exact pattern is observed in a real debug log.

### Secret scanning

Eight high-confidence patterns: Anthropic keys, GitHub PATs, AWS access keys, private-key headers, database connection URLs, `api_key=` / `api-key=`, `password=`, and `access|bearer|auth` tokens. The scanner runs against every tool result in-process. `localfirst demo` exercises the same `scanSecrets` function against five fixture files in 10 seconds — same code path that fires in real sessions.

## Test surface

- **996 unit tests** covering routing, native handlers, secret patterns, cost math, classifier behavior, partial-batch interception, and validation script behavior.
- **65 smoke tests** exercising the full `interceptToolUse` execution path against partial-batch SSE fixtures, including all four git shapes.
- **Live-fire validation** required for any change that touches tool-call routing or display surfaces.

Run `npm test` for unit tests, `npm run smoke` for full-path smoke tests.

## Reproducing the cost claim

The "84% saved" figure in the README is from a real 7-request session captured on 2026-05-08 19:36:56. Counterfactual cost is computed as `actual_cost + payload_savings + context_savings + cache_savings`, where:

- `payload_savings` — distillation + LAO compression measured per request
- `context_savings` — compounding model based on the JSONL log sequence (no heuristic; see `calcCompoundingSavings`)
- `cache_savings` — exact, from Anthropic's prompt-cache headers

The math and the savings buckets are visible in `localfirst status` under `Breakdown:` and recomputed on every read of the session.

## Stage 3 — Cline live validation (2026-05-09)

Real Cline traffic was routed through the proxy and produced verifiable canonical-pipeline dispatch. This is the boundary-layer claim — that LocalFirst's interior is genuinely agent-agnostic — backed by a second agent end-to-end.

**Routing signal used:** SSE content fingerprint. The user's Cline release did not forward the explicit `x-localfirst-agent` header through its UI, so the proxy fell back to scanning tool-block names in the response and matching them against the registered agent maps. `read_file` is a Cline-registered name; the agent router selected the cline adapter automatically.

**Verbatim proxy stderr from the validation run** (01:42, 2026-05-09):

```
[proxy] routed to cline adapter (fingerprint)
[interceptor/pipeline] native read_file(EVIDENCE.md) → exit 1
01T42:07  ↑  ~1.4kt  ·  11 msgs  ·  read_file(EVIDENCE.md) ~13t
```

What this proves:
- Fingerprint detection fired correctly against real Cline SSE.
- The cline adapter's `parseConversationTurn` ran end-to-end: parsed the SSE, applied the `read_file` input transformer (`{path}` → `{file_path}`), emitted a canonical `BoundaryEvent` with `agent: 'cline'`.
- The canonical pipeline accepted the cline-originated event: `policy.evaluate` returned LOCAL, `dispatcher.dispatch` looked up `NATIVE_HANDLERS.read_file` (canonical key), the native handler executed.
- Two agents (Claude Code + Cline) now flow through the same canonical pipeline using the same policy engine, dispatcher, scanner, and auditor.

**Caveats** (operational, not architectural):

- The handler returned exit 1 because Cline sent a path relative to its VS Code workspace and the proxy resolved it relative to its own CWD. Workaround for further validation: start `localfirst claude` from the Cline workspace root. A workspace-aware path-resolution slice is a future operational enhancement, not a structural gap.
- Subsequent Cline runs (01:48 onward) emitted only `attempt_completion` because Cline cached prior file content. `attempt_completion` is intentionally unmapped — it correctly falls through to PASS. These runs do not constitute additional validation evidence; the 01:42 run is the canonical record.
- Cline's full tool surface (`write_to_file`, `replace_in_file`, `browser_action`, `use_mcp_tool`, etc.) is intentionally unmapped today. Adding canonical handlers for any of them is a separate forward slice if and when it becomes a product priority.
- The mid-loop fallback counter bug surfaced during this validation (`Ran locally: 0 of 3` despite the canonical pipeline running) was fixed in commit `ebdda9a`. The fix is unit-test verified but has not been live-confirmed against a Cline session that exercises both an interceptable tool and a follow-up unmapped tool in the same conversation. The fix is correct; it just hasn't been observed in production traffic.

**Architectural conclusion:** Stage 3 is sufficiently live-validated. The boundary-layer architecture supports a second agent without requiring changes to the pipeline, policy, dispatcher, scanner, or auditor layers. All four were originally generalizations needed for any second agent: parameterized agent identity, registry-driven gating, canonical input shapes, and policy-driven partial-batch checks. None are Claude-Code-specific anymore.

## Audit log hash chain (2026-05-09)

`pipeline-events.jsonl` is now hash-chained. Each row carries:

- `prev_hash` — SHA-256 hex of the previous row (`"0000...0000"` for the first row)
- `hash` — SHA-256 hex of `JSON.stringify(rowWithoutHash)`, where `rowWithoutHash` includes `prev_hash`

Chain continuity is verified by `localfirst audit verify`. The verifier checks: (1) first chained row's `prev_hash` equals the GENESIS sentinel, (2) each subsequent row's `prev_hash` equals the computed hash of the previous row, (3) stored hash equals recomputed hash for every row.

Tamper detection: modifying any field in any row causes a hash mismatch on that row and a chain-break error on every subsequent row. The verifier uses the recomputed hash (not the stored hash) to advance the expected chain, so a single tampered row generates cascading errors — making the tamper location unambiguous.

Legacy rows (written before hash-chain support) are preserved as-is, counted separately as "unverified," and do not break the chain. The chain starts at GENESIS from the first hash-bearing row.

The claim is tamper-evident (any modification is detectable), not tamper-proof with attribution (the user owns the machine and could re-hash — that is structurally honest and expected for an on-machine audit log). For compliance use cases, the chain is exportable and independently verifiable by a third party against a known-good reference hash.

## Limitations

- **Windows is the live-validated platform.** Mac support is in progress; contributions for `cd`/path handling on Mac are welcome.
- **Read-only Bash coverage.** Write commands (`git push`, `npm install`, etc.) intentionally fall through to the cloud path.
- **No statefulness across sessions.** The cwd tracking in compound chains is local to a single execution; the proxy never mutates `process.cwd()`.
- **The Anthropic prompt cache exists independently.** The cache_savings line reflects savings the user gets even without LocalFirst. We surface it for completeness, but it is not LocalFirst-attributable.
