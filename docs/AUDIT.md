# Occasio — Audit Log Format and Independent Verification

**Audience.** Security / compliance reviewers and platform engineers who need to verify Occasio's audit trail without trusting Occasio's own verifier.

**Promise.** Every governed tool call writes one row to `~/.occasio/pipeline-events.jsonl`. Each row is hash-chained to the previous row using SHA-256, starting from a fixed genesis sentinel. Any post-hoc edit, reordering, or deletion within the chain is detectable by re-walking the file. This document specifies the row format and the canonical-serialization rules precisely enough that an independent walker (a small Python script, included) reproduces the verification end-to-end.

---

## 1. Row format

Each line of `pipeline-events.jsonl` is a UTF-8 JSON object. A row is built in **this exact field order**:

```
ts, event_id, session_id, run_id,
agent, protocol, direction, kind,
tool_name, tool_inputs,
action, reason, policy_source, executor, transform,
result_kind, exit_code, secrets_redacted, distilled, tokens_saved,
prev_hash, hash
```

Field semantics:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (ISO-8601) | Event timestamp from the boundary event. |
| `event_id` | string (UUID) | Unique per event. |
| `session_id` | string | Stable per Occasio session. |
| `run_id` | string | Stable per agent run. |
| `agent` | string | Canonical agent id (e.g. `claude-code`). |
| `protocol` | string | Wire protocol (e.g. `anthropic-http`). |
| `direction` | string | `inbound` (agent → cloud) or `outbound`. |
| `kind` | string | `tool_call`, `request`, etc. |
| `tool_name` | string | Canonical tool name (e.g. `read_file`). |
| `tool_inputs` | object \| absent | Normalized inputs (see `src/audit/input-normalizer.js`). Absent means the tool's inputs are intentionally not logged. |
| `action` | string | `LOCAL`, `PASS`, `BLOCK`, or `TRANSFORM`. |
| `reason` | string | Reason code from the policy engine. |
| `policy_source` | string | `default` or `user`. |
| `executor` | string \| absent | Where the action ran (e.g. `native`). |
| `transform` | string \| absent | Transform applied, if any. |
| `result_kind` | string | `local`, `pass`, `block`, `transform`, or `unknown`. |
| `exit_code` | number \| absent | Non-zero on local execution failure. |
| `secrets_redacted` | number \| absent | Count of secrets redacted in the result. |
| `distilled` | bool \| absent | Whether output was distilled. |
| `tokens_saved` | number \| absent | Tokens saved by distillation. |
| `prev_hash` | string (64-hex) | Hash of the previous row, or genesis on the first row. |
| `hash` | string (64-hex) | SHA-256 of the row's canonical serialization with `hash` removed. |

Fields whose value would be `undefined` (in JS) or `None` (in Python) are **omitted** from the serialized row, not emitted with a null value. This matches V8's `JSON.stringify` default behavior.

### Row kinds

`kind` distinguishes what an audit row records. There are five:

| `kind` | When it fires | Semantics |
|---|---|---|
| `tool_call` | Every governed tool call (Claude Code or MCP) | `tool_inputs` is per-tool (file path, glob, count). `action` is one of `LOCAL`/`PASS`/`BLOCK`/`TRANSFORM`. `result_kind` is `local`/`pass`/`block`/`transform`. |
| `request` | Every HTTP request through the proxy (Anthropic SSE or budget-blocked or local-only) | Per-request accounting row: cost, tokens, cache savings, savings breakdown, coverage counters (`tools_attempted`, `tools_local_count`, `tools_mcp_count`). `event_type` is `cloud_sent`, `local_only`, `blocked`, `trimmed`, or `budget_exceeded`. No `action`/`result_kind` (those are tool-call concepts). |
| `policy_loaded` | Process startup, and on every policy-file edit (hot-reload) | `tool_inputs` is `{ policy_hash, policy_path, version }`. `tool_name` is the placeholder string `"policy_loaded"`. `action` is `"INFO"`. `reason` is `"policy-loaded"`. **`result_kind` is omitted** because a policy-load event has no dispatcher Result. |
| `git_state` | Run start and run end (when launched via the `claude` proxy) | `tool_inputs` is `{ phase, cwd, is_repo, head, branch, dirty, changed_files, untracked_files, diff_hash, digest }`. `phase` is `run_start` or `run_end`. `tool_name` is the placeholder string `"git_state"`. `action` is `"INFO"`. `reason` is `"git-state"`. **`result_kind` is omitted.** Capture is best-effort: a non-git directory or missing git binary records `is_repo:false` rather than aborting the run. |
| `limit_exceeded` | A per-round volume cap (`policy.limits`) was hit and the run was halted | `tool_inputs` is `{ limit, max, actual, round, decision:"block" }` where `limit` is the violated key (`max_tool_calls_per_round` / `max_bash_calls_per_round` / `max_bytes_to_model_per_round`). `tool_name` is the placeholder string `"limit_exceeded"`. `action` is `"BLOCK"`. `reason` is `"limit-exceeded"`. **`result_kind` is omitted.** |

The `policy_loaded` row binds the audit chain to a specific policy file's bytes: a buyer can prove not just "what was blocked" but "under which exact `policy.yml` the block was decided." Because the hash is over the raw file bytes (not the normalized policy object), comments and whitespace count, so the hash matches whatever a reviewer reads in source control.

The `git_state` rows bind a run to the concrete repository state it ran against: the `run_start` row records HEAD + a `diff_hash` before the agent acts, and the `run_end` row records what it left behind (changed/untracked files, post-run `diff_hash`). `occasio attest` lifts these rows into `subject.git_state` (`provenance: "chain"`), and `occasio attest verify` re-derives the same object straight from the hash-protected rows and requires byte-equality — so a tampered git claim in an attestation fails verification.

#### `request` row field order

The `request` row uses its own canonical field order. The order is load-bearing for hash stability and `test-audit-chain.js` test #20 locks it in:

```
audit_schema, ts, event_id, session_id, run_id, agent, protocol, direction,
kind, event_type, model, cwd, input_tokens, output_tokens, cache_read_tokens,
cache_write_tokens, cost, cache_savings, lao_tokens_saved, lao_cost_saved,
distill_tokens_saved, distill_cost_saved, tools_attempted, tools_local_count,
tools_mcp_count, prev_hash, hash
```

Adding a new accounting field is a chain-schema change. Append it to the end of the order (before `prev_hash`), bump `audit_schema` if the semantics break older verifiers, and update `docs/audit_walker.py` in lockstep so independent verification continues to walk every kind.

## 2. Genesis sentinel

The `prev_hash` of the first row in a chain is:

```
0000000000000000000000000000000000000000000000000000000000000000
```

(64 zero hex digits.)

## 3. Hash algorithm

For each row:

1. Take the row object.
2. Remove the `hash` field.
3. Serialize **in insertion order** to a UTF-8 string with no whitespace between tokens, no key sorting, and non-ASCII characters emitted literally. (V8 `JSON.stringify` default; equivalent to Python `json.dumps(d, separators=(",", ":"), ensure_ascii=False)` over a Python 3.7+ dict.)
4. Compute the lowercase hex SHA-256 of the resulting bytes.

That is the value of `hash`. The `prev_hash` of the next row equals this `hash`.

## 4. Independent walker

A standalone Python script, [`audit_walker.py`](audit_walker.py), implements the verification with no Occasio dependencies — only `hashlib`, `json`, `sys` from the standard library. To run it:

```sh
python3 docs/audit_walker.py ~/.occasio/pipeline-events.jsonl
```

Expected output for an intact chain:

```
OK: 31 rows verified
```

If any row's `prev_hash` does not match the previous row's `hash`, or any row's recomputed hash does not match its stored `hash`, the script exits non-zero with a `MISMATCH at line N: …` message identifying the first inconsistency.

## 5. Parity with Occasio's own verifier

Occasio ships its own verifier (`occasio audit verify`). For audit credibility, both must agree on the same file. Parity is checked at every release; v0.6.4 is verified to agree on the maintainer's 31-row reference log.

If you find a row where `audit_walker.py` and `occasio audit verify` disagree, that is a bug. Open an issue with the row line number and we will treat it as audit-credibility-critical (i.e. fix-before-next-release).

## 6. What this proves and does not prove

**Proves.** No row in the chain has been edited after the fact. No row has been removed from the middle of the chain. No row has been reordered.

**Does not prove.**

- That no rows were *omitted* — i.e. that the proxy was running and recording during every session in which it should have been. Gaps in time are visible in the `ts` field, but proving "no governed action escaped the log" requires comparing the audit log against an external record of agent activity. For pilots that need this guarantee, ship the audit rows offsite (SIEM, S3, append-only file) on a tail cadence.
- ~~That the proxy was running with the policy file you expected.~~ **(Resolved in v0.6.6.)** Every process startup and every hot-reload appends a `policy_loaded` row carrying the SHA-256 of the active policy file's bytes; subsequent tool-call rows are bound to the most recent `policy_loaded` row by chain position. To verify "this BLOCK happened under this exact policy file": (1) find the BLOCK row, (2) walk backward to the most recent `policy_loaded` row, (3) compare its `tool_inputs.policy_hash` to a SHA-256 of the file you intend to compare against. The walker in `audit_walker.py` will accept both `kind` values without modification.
- That **multiple processes** writing to the same audit file did not interleave. The Claude Code proxy and the MCP server each emit their own `policy_loaded` rows, which is correct, but they share `pipeline-events.jsonl` under a single-writer assumption documented in v0.6.5's CHANGELOG. Concurrent writers on Windows can interleave; the chain detects the corruption but cannot repair it.
- That a row written *during* a write outage was not lost. v0.6.4 aborts the proxy with exit code 1 when an audit append fails, so a successful tool dispatch cannot coexist with a missing row in steady state. The combination of (a) fail-fatal audit writes and (b) a supervisor that restarts the proxy is the operational guarantee.

## 7. Stability commitment

The audit row schema and field-order list in §1 are part of Occasio's stable surface. They will not change incompatibly across v0.6.x. Any future field will be added in a way that does not invalidate existing rows or re-walks of the chain.

`audit_walker.py` in this repository is the canonical reference. If your verifier produces different bytes on the same input, your verifier is wrong, not the spec.
