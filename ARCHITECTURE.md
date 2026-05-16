# Occasio Architecture

Occasio is built as a **user-side boundary layer** between AI agents and the user's machine. The architecture is layered: each layer has a named module with a clean contract, and policy decisions flow through the canonical pipeline (`adapter → policy → dispatcher → auditor`). Concrete components wrap the implementations in `interceptor.js` / `runtime.js` / `analyzer.js` / `distiller.js` and the per-call defense gates in `outbound-policy.js`.

## The seven layers

```
┌──────────────────────────────────────────────────────────────────────┐
│  L0  Boundary Capture     — HTTP server in src/index.js              │
│  L1  Agent Adapters       — src/adapters/                            │
│  L2  Policy Engine        — src/policy/                              │
│  L3  Dispatch & Execution — src/executor/  +  src/scanner/           │
│  L4  Audit                — src/audit/                               │
│  L5  Observability        — src/dashboard.js, src/inspect.js,        │
│                             src/ledger.js, src/replay.js             │
│  L6  Team Plane           — (does not exist; Stage 6+)               │
└──────────────────────────────────────────────────────────────────────┘

  Agent traffic
        ↓
  [Adapter]    parseResponse(sseBuffer) → BoundaryEvent[]
        ↓
  [Policy]     evaluate(event)          → Decision
        ↓
  [Dispatch]   dispatch(event, decision) → Result
        ↓
  [Audit]      record(event, decision, result)
        ↓
  Response back to agent
```

## Module map

| Layer | Module | Responsibility |
|---|---|---|
| Types | `src/core/boundary-event.js` | `BoundaryEvent` factory + `KINDS`/`DIRECTIONS` |
| Types | `src/core/decision.js`       | `Decision` factory + `PASS`/`LOCAL`/`TRANSFORM`/`BLOCK` constructors |
| Pipeline | `src/core/pipeline.js`    | `process({event, policy, dispatcher, auditor, ctx})` and `processToolEvent(event, opts)` |
| L1 | `src/adapters/claude-code.js`  | Claude Code's Anthropic-HTTP wire format and tool-block shape |
| L2 | `src/policy/engine.js`         | `evaluate(event) → Decision`; delegates to legacy classifier in Stage 1 |
| L2 | `src/policy/rules-default.js`  | Documents the implicit Stage 1 ruleset |
| L3 | `src/executor/dispatcher.js`   | `dispatch(event, decision, ctx) → Result`; `NATIVE_HANDLERS` table |
| L3 | `src/scanner/index.js`         | `scan(content)` for secrets; `reduce(label, content)` for distillation |
| L4 | `src/audit/jsonl-auditor.js`   | `createAuditor(filePath)` → `{record, file}` |

Existing modules (`interceptor.js`, `runtime.js`, `analyzer.js`, `distiller.js`, `classifier.js`, `lao.js`, `budget.js`, `session.js`, `dashboard.js`) are untouched. The new modules are wrappers above them.

## BoundaryEvent (Stage 1)

| Field | Type | Notes |
|---|---|---|
| `id`         | string | uuid; assigned by the factory |
| `timestamp`  | string | ISO 8601 |
| `sessionId`  | string | optional |
| `runId`      | string | optional |
| `agent`      | string | required, e.g. `'claude-code'` |
| `protocol`   | string | required, e.g. `'anthropic-http'` |
| `direction`  | enum   | `'outbound' \| 'inbound'` |
| `kind`       | enum   | `'request' \| 'tool_call' \| 'tool_result' \| 'response'` |
| `toolName`   | string | optional; canonical tool name (Stage 1 uses Claude Code's names) |
| `toolInput`  | object | optional |
| `toolResult` | any    | optional |
| `payload`    | any    | optional |
| `raw`        | any    | adapter-private; opaque to other layers |

**Hard rule:** only the adapter touches `raw`. Any other module reading `raw.something` is an architecture leak.

## Decision (Stage 1)

| Field | Type | Notes |
|---|---|---|
| `action`            | enum   | `'PASS' \| 'LOCAL' \| 'TRANSFORM' \| 'BLOCK'` |
| `reason`            | string | stable code, e.g. `'native-handleable'` |
| `policySource`      | string | `'default'` in Stage 1 |
| `executor`          | string | required for `LOCAL` (e.g. `'native'`) |
| `transform`         | string | required for `TRANSFORM` |
| `syntheticResponse` | object | required for `BLOCK` |

## What flows through the canonical pipeline today

**All seven supported tool kinds** dispatch through the pipeline:

| Tool | Production path |
|---|---|
| Read       | `interceptToolUse` → `makeBoundaryEvent` → `policy.evaluate` → `dispatcher.dispatch` → `NATIVE_HANDLERS.Read` → `runtime.handleReadTool` → `auditor.record` |
| Glob       | same shape via `NATIVE_HANDLERS.Glob` |
| Grep       | same shape via `NATIVE_HANDLERS.Grep` |
| TodoWrite  | same shape via `NATIVE_HANDLERS.TodoWrite` |
| TodoRead   | same shape via `NATIVE_HANDLERS.TodoRead` |
| Bash       | `NATIVE_HANDLERS.Bash` runs `nativeHandle(cmd)`; on null, falls back to `runLocally(cmd)` exec subprocess. `native: true\|false` returned to caller |
| PowerShell | `NATIVE_HANDLERS.PowerShell` expands `$env:` vars then runs `nativeHandle(cmd)`. `expandedCmd` returned for label/audit |

For each call: one `BoundaryEvent` is constructed, one `Decision` is emitted, one `Result` is returned, and one row is appended to `~/.occasio/pipeline-events.jsonl`.

## Multi-round orchestration (post-Phase-D)

The full Anthropic tool-loop is owned by `adapters/claude-code.js::runToolLoop`. It consumes the initial SSE buffer, runs the per-round dispatch through `runOneRound` (which calls the pipeline), accumulates secrets across rounds, calls back to Anthropic via `forwardToCloud`, and returns the same shape `interceptToolUse` previously returned.

```
adapter.runToolLoop({initialSse, reqBody, reqHeaders, ...opts})
  ├── parseConversationTurn(initialSse)        # SSE → blocks + events
  ├── classifyBlock × N                         # batch decision
  ├── for round = 0..maxRounds:
  │     ├── runOneRound(toolBlocks, ctx)       # dispatcher per-block (pipeline)
  │     │     └── pipeline.processToolEvent     # adapter→policy→dispatch→audit
  │     ├── if partialBatch && round 0: return  # caller handles injection
  │     ├── scanToolResults(toolResults)        # cross-round secret scan
  │     └── forwardToCloud(reqBody, headers)    # next Anthropic turn
  └── return { intercepted, response, toolsRun, toolCallUsage, … }
```

**Phase E completed:** `interceptToolUse` and `_legacyInterceptToolUse` have been deleted from `interceptor.js`. `index.js` calls `adapter.runToolLoop({...})` directly. The interceptor module is no longer the entry point for an Anthropic conversation — it now exposes only helpers (`runOneRound`, `blocksToContent`, `parseSSE`, `classifyBlock`, `isInterceptable`, `nativeHandle`, etc.) that the adapter and dispatcher consume.

## Stage 2 — policy as data

Two decisions are now produced by the policy engine reading `~/.occasio/policy.yml`:

| Decision point | Where it runs | YAML key |
|---|---|---|
| Block requests when session cost ≥ budget | `index.js`'s request handler calls `policy.evaluateRequest({sessionCost, budget})` | `block_requests_over_budget` |
| Block tool_results containing secrets | `runToolLoop` calls `policy.evaluateToolResults(toolResults, {mode})` between rounds | `block_secrets_in_tool_results` |

**Policy file format (Stage 2 minimal):**

```yaml
version: 1
block_secrets_in_tool_results: true
block_requests_over_budget:    true
```

Defaults match historical behavior. Users override individual keys. Unknown keys are silently ignored (forward-compatible). The loader is in `src/policy/loader.js`; it implements a tiny YAML subset (key:value, comments, blanks) without external dependencies.

**Tool routing remains classifier-driven** in Stage 2. `policy.evaluate(BoundaryEvent)` still delegates to `classifyBlock`. Stage 3 moves tool routing into the YAML rule set as well.

## Stage 3 — tool routing as data

`policy.yml` now owns the tool-routing decision. Each tool name maps to an entry that says how the boundary should handle a call to that tool:

```yaml
tools:
  Read:
    action: LOCAL
    executor: native
    classifier: read-input-validator
  Bash:
    action: LOCAL
    executor: native
    classifier: bash-allowlist
  Edit:
    action: PASS
```

`policy.engine.evaluate(BoundaryEvent)` reads this section. For each tool call:

- **No entry** → `PASS` with reason `tool_not_handled` (preserves legacy fallback semantics).
- **`action: PASS`** → `PASS` with the entry's reason (default `tool_not_handled`).
- **`action: LOCAL`, no classifier** → unconditional `LOCAL` with the entry's executor.
- **`action: LOCAL`, named classifier** → run the classifier; on `handled: true` emit `LOCAL`, on `handled: false` emit `PASS` with the classifier's reason.
- **Unknown classifier name** → `PASS` (fail-safe), reason names the missing classifier.

### Built-in classifiers

Named entries that wrap existing JS validators (`src/policy/built-in-classifiers.js`):

| Name | Wraps | Reason on reject |
|---|---|---|
| `read-input-validator`  | `isReadHandleable` | `read_unsupported_type` |
| `glob-input-validator`  | `isGlobHandleable` | `glob_injection_or_invalid` |
| `grep-input-validator`  | `isGrepHandleable` | `grep_multiline` / `grep_invalid_input` |
| `todo-write-validator`  | `isTodoHandleable(_, 'TodoWrite')` | `tool_not_handled` |
| `todo-read-validator`   | `isTodoHandleable(_, 'TodoRead')`  | `tool_not_handled` |
| `bash-allowlist`        | `classifyBlock` for Bash         | full FALLBACK_REASONS surface |
| `powershell-allowlist`  | `classifyBlock` for PowerShell    | full FALLBACK_REASONS surface |

The user can author `policy.yml` to:
- Disable a normally-LOCAL tool (`Read: { action: PASS }`).
- Skip the input validator (`Read: { action: LOCAL }` — no classifier means unconditional dispatch).
- Add a tool that wasn't intercepted before (`MyCustomTool: { action: LOCAL, executor: native }` — assumes the dispatcher has a registered `MyCustomTool` handler).

### Default behavior preserved

`DEFAULT_POLICY.tools` reproduces the pre-Stage-3 hardcoded routing exactly. Existing users see no change. To override, the user creates `~/.occasio/policy.yml` with their own `tools:` block; if present, it replaces the defaults entirely.

## Stage 3 — canonical tool-name registry

The pipeline interior speaks **canonical** tool names — agent-agnostic identifiers — instead of any specific agent's protocol names. Adapters map their agent's names into the canonical vocabulary at the BoundaryEvent boundary.

| Canonical name | Claude Code name |
|---|---|
| `read_file`         | `Read` |
| `find_files`        | `Glob` |
| `grep`              | `Grep` |
| `todo_write`        | `TodoWrite` |
| `todo_read`         | `TodoRead` |
| `shell_bash`        | `Bash` |
| `shell_powershell`  | `PowerShell` |

**Where canonical names appear (post-Stage-3):**
- `BoundaryEvent.toolName` — agent-agnostic; the original Claude name remains in `BoundaryEvent.raw.name`.
- `dispatcher.NATIVE_HANDLERS` — keyed on canonical names.
- `policy.tools` (in `policy.yml` defaults and `DEFAULT_TOOLS`).
- `~/.occasio/pipeline-events.jsonl` — `tool_name` is canonical.

**Where Claude-specific names still appear:**
- `BoundaryEvent.raw.name` — preserved for protocol-shape callers.
- `interceptor.classifyBlock` — still uses Claude protocol names internally; the adapter and built-in classifiers translate.
- `runOneRound`'s post-dispatch label-extraction switch — works with Claude `blk.name` because labels are extracted from the Claude protocol input shape (`file_path` / `pattern` / `command`). When a second agent lands, that switch moves into the adapter.
- `toolsRun.tool` field — still Claude's name for dashboard continuity. May change in a future release once the dashboard knows about canonical names.

**Lenient lookup.** Both the policy engine and the dispatcher accept agent-specific names (e.g., a test that constructs an event with `toolName: 'Read'`) by reverse-resolving through the registry. User-written `policy.yml` may use either canonical names (`read_file:`) or agent-specific aliases (`Read:`) — alias keys are translated to canonical at load time.

**Registry API** (`src/core/tool-names.js`):

```js
const t = require('./core/tool-names');
t.CANONICAL.READ_FILE                            // 'read_file'
t.register('claude-code', { Read: 'read_file' }) // adapter init
t.toCanonical('claude-code', 'Read')             // 'read_file'
t.toAgentName('claude-code', 'read_file')        // 'Read'
t.firstCanonicalFor('Read')                      // 'read_file' — searches all agents
t.isCanonical('read_file')                       // true
```

Adding a second agent (Cline, Cursor) is now mechanical: write the adapter, call `register('cline', {...})`, emit `BoundaryEvent`s with canonical names. The pipeline / policy / dispatcher / scanner / audit layers don't change.

## Stage 3 — Cline adapter (synthetic; live validation pending)

Occasio now ships a second adapter (`src/adapters/cline.js`) that recognizes Cline tool calls and routes them through the same canonical pipeline. The adapter's responsibilities:

1. **Tool name registration.** `toolNames.register('cline', { read_file: 'read_file', execute_command: 'shell_bash', ... })`. Tools without a canonical mapping (e.g., `write_to_file`, `browser_action`) fall through to PASS via the policy engine.
2. **Input shape translation.** Per-tool transformers convert Cline's input shape (`{path: 'foo'}`) to canonical (`{file_path: 'foo'}`) so dispatcher handlers and label extraction work uniformly.
3. **Thin runToolLoop wrapper.** Cline shares the multi-round Anthropic-protocol loop with `claude-code`, supplying its own parser and agent identity via `_agent` / `_parser` opts.

### Architectural changes that made this possible

The second-agent attempt surfaced four Claude-specific assumptions that were addressed in this push:

| Assumption | Resolution |
|---|---|
| `runOneRound` hardcoded `'claude-code'` for canonical lookup | `agent` is now a context parameter, supplied by `runToolLoop`. |
| `runOneRound`'s tool-dispatch gate was a hardcoded list of Claude names | Gate is now registry-driven (`toolNames.toCanonical(agent, blk.name)`); any registered tool dispatches. |
| `runOneRound`'s label-extraction switch keyed on Claude `blk.name` | Switch keys on canonical name; expects canonical input shape (each adapter translates inputs). |
| `runToolLoop`'s partial-batch gate called Claude-specific `classifyBlock` | Replaced by a registry+policy-driven check: construct a temporary BoundaryEvent and call `policy.evaluate`. Same outcome for Claude Code; correctly recognizes Cline tools. |

### LIVE_VALIDATION_PENDING

The Cline adapter is exercised by synthetic SSE fixtures based on Cline's published source. Before declaring Cline support production-ready:

- Verify Cline's exact tool name strings (occasionally change between releases).
- Verify per-tool input field names (currently translated from public docs).
- Confirm Cline routes through the proxy correctly when configured with a custom Anthropic base URL.
- Run a real Cline session through the proxy and verify `pipeline-events.jsonl` records `agent: 'cline'`.
- Add live validation: route a real Cline session through the proxy with `x-occasio-agent: cline` set in Cline's request configuration. Verify `~/.occasio/pipeline-events.jsonl` records `agent: 'cline'` and tool dispatches succeed.

## Stage 3 — proxy-side agent routing

`index.js` now selects an adapter per request. Both `claudeCodeAdapter` and `clineAdapter` are loaded at proxy startup (so each agent's tool-name registration runs before any traffic arrives). For each `/v1/messages` request, the proxy reads the `x-occasio-agent` header and dispatches accordingly.

```
Cline VS Code extension (configured with proxy URL + custom header)
       ↓ Anthropic API request with `x-occasio-agent: cline` header
   proxy at localhost:<auto-assigned port; see ANTHROPIC_BASE_URL>
       ↓ selectAdapter(req.headers) → cline adapter
   cline.runToolLoop(...) → canonical pipeline → agent: 'cline' in audit
       ↓ forwardToCloud (header stripped before leaving the machine)
   api.anthropic.com
```

Detection signal: `x-occasio-agent` HTTP header.
- `cline` → Cline adapter.
- Header missing or unrecognized → Claude Code adapter (preserves backward compat).

Implementation: `src/proxy/agent-router.js` exports `selectAdapter(headers, adapters, defaultAgent) → { adapter, agentId, source }`. The router is agent-agnostic: it knows nothing about specific adapters, only how to look one up by header. `index.js` supplies the registered adapter map and the default.

The header is **Occasio-internal**: it never leaves the machine. The proxy strips it from the outbound HTTP request before forwarding to Anthropic.

The dispatcher's `NATIVE_HANDLERS` table is now the **single source of truth** for tool execution. `interceptToolUse` no longer makes any direct call to `handleReadTool` / `handleGlobTool` / `handleGrepTool` / `handleTodoWriteTool` / `handleTodoReadTool` / `nativeHandle` / `runLocally` / `expandPsEnvVars` for tool dispatch. The remaining call sites for those functions are inside the dispatcher, gate-check helpers (`isPowerShellNativeHandleable`, `classifyBlock`), or self-recursive helpers (`runCompound` for D-3 compound chains).

## What still runs on the legacy path

| Surface | Why deferred |
|---|---|
| `mode === 'hardened'` MCP path | Inside `runOneRound` — goes through `executeLocalTool` and accumulates secrets per round; subsumed when richer policy rules + TRANSFORM are introduced |
| Partial-batch interception spanning two HTTP exchanges | `pendingToolInjections` Map in `index.js` outlives `runToolLoop`. Adapter returns `partialResults`; the caller (proxy) injects them later. This split is correct but worth documenting |
| SSE response synthesis after interception | Adapter has `parseConversationTurn` for the inbound side; the outbound rewrite (when `intercepted: true`) still happens in `index.js` |
| Tool routing via classifier | `classifyBlock` still hard-codes which tool names are interceptable. Stage 3 moves this into the YAML rule set. |

## Acknowledged remaining leaks

| Leak | Module | Resolved in |
|---|---|---|
| Tool-name literals in pipeline gate + label extraction | `interceptor.js` (lines 1109, 1144-1163) | Stage 2 (move to adapter when SSE assembly migrates) |
| Tool-name literals in `NATIVE_HANDLERS` table | `executor/dispatcher.js` | Stage 3 (canonical name registry when second agent lands) |
| Tool-name literals in `classifyBlock` | `interceptor.js` | Future adapter; legitimate adapter territory |
| Secret-scan and budget rules execute in legacy code, not as Decisions | `interceptor.js` (secret), `index.js` (budget) | Stage 2 (policy as data) |
| TRANSFORM action is a dispatcher stub | `executor/dispatcher.js` | Stage 2 |

## What changed between v0.6.0 and Stage 1

No user-visible behavior changes. `occasio claude`, `occasio status`, `occasio demo`, the Saved banner, the dashboard, and the JSONL log shape are all identical to v0.6.0. The structural changes:

- 7 new files in `src/core/`, `src/adapters/`, `src/policy/`, `src/executor/`, `src/scanner/`, `src/audit/`
- New test sections ARCH-1 through ARCH-6 covering layer contracts and end-to-end flow
- New smoke test #14 verifying the auditor receives production tool calls
- This document
- `interceptor.js`: five tool-dispatch branches (Read/Glob/Grep/TodoWrite/TodoRead) collapsed into one pipeline-driven block; direct calls to `handleReadTool`/`handleGlobTool`/`handleGrepTool`/`handleTodoWriteTool`/`handleTodoReadTool` removed from the live path
- `index.js`: session-level `Auditor` created at startup; `sessionId` / `runId` / `auditor` plumbed through `interceptToolUse` so production traffic produces audit rows
- 1098 unit tests + 76 smoke tests, all passing (was 996 + 65 pre-Stage-1)

## Production audit log

Path: `~/.occasio/pipeline-events.jsonl`

One row per tool call that flows through the canonical pipeline. Format:

```json
{
  "ts": "2026-05-08T19:12:34.567Z",
  "event_id":     "uuid",
  "session_id":   "run uuid",
  "run_id":       "run uuid",
  "agent":        "claude-code",
  "protocol":     "anthropic-http",
  "direction":    "inbound",
  "kind":         "tool_call",
  "tool_name":    "Read",
  "action":       "LOCAL",
  "reason":       "ok",
  "policy_source":"default",
  "executor":     "native",
  "result_kind":  "local",
  "exit_code":    0
}
```

This is the foundation for Stage 2's tamper-evident audit (hash-chained log, SIEM-compatible export). Today it is plain JSONL, append-only, local file.
