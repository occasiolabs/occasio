# Occasio Architecture

A high-level map of the request pipeline and where each module lives.
Use this as the orientation document before reading individual files.

## Pipeline

Every tool call from a coding agent travels the same five-stage pipeline,
regardless of the upstream protocol (Anthropic SSE, MCP, computer-use).
Each stage produces input for the next; nothing skips the auditor.

```
            agent (Claude Code, MCP client, computer-use loop)
                                  |
                                  v
   +--------------+    raw events      +-----------------+
   |   Adapter    | -----------------> |  Boundary event |
   | src/adapters |                    |   src/core/     |
   +--------------+                    +-----------------+
                                              |
                                              v
                                      +-----------------+
                                      |     Policy      |
                                      |   src/policy/   |
                                      +-----------------+
                                              |
                                       Decision { action,
                                       reason, transform,
                                       executor }
                                              |
                                              v
                                      +-----------------+
                                      |   Dispatcher    |
                                      |  src/dispatch/  |
                                      +-----------------+
                                              |
                                       Result { passThrough,
                                       blocked, transformed,
                                       exitCode, ... }
                                              |
                                              v
                                      +-----------------+
                                      |    Auditor      |
                                      | src/audit/      |
                                      +-----------------+
                                              |
                                              v
                                      +-----------------+
                                      |     Attest      |
                                      |  src/attest/    |
                                      +-----------------+
                                              |
                                              v
                                in-toto + Sigstore bundle
```

## Stages

### 1. Adapter — `src/adapters/`

Each upstream protocol has its own adapter (`claude-code.js`,
`mcp-server.js`, `computer-use.js`). Adapters turn raw transport frames
(SSE deltas, JSON-RPC, screenshots) into a canonical `BoundaryEvent`
defined in `src/core/boundary-event.js`. Downstream stages know nothing
about the protocol of origin — that is the whole point of the boundary.

### 2. Policy — `src/policy/`

`engine.js` is a pure function over `(event, policy)` returning a
`Decision`. `loader.js` parses the YAML-subset policy file with hot
reload via watcher. `pattern-store.js` and `pathset.js` provide path
matching and deny-list semantics. The engine itself does no I/O — every
side effect happens in the dispatcher.

### 3. Dispatcher — `src/dispatch/`

Routes a Decision to one of three executors:

- `executors/cloud.js` — forward to the upstream LLM provider.
- `executors/local.js` — execute interceptable tools locally
  (Read, Glob, Grep, TodoWrite, bounded shell reads).
- `executors/block.js` — return a deny response without making the call.

Transforms (redaction, distillation) run before execution and are
recorded as part of the Result.

### 4. Auditor — `src/audit/`

`jsonl-auditor.js` appends one tamper-evident row per
`(event, decision, result)` tuple to `~/.occasio/pipeline-events.jsonl`.

Key properties:

- Each row carries `prev_hash` (SHA-256 of the previous row's `hash`)
  and `hash` (SHA-256 of the row minus the hash field).
- The first row's `prev_hash` is `GENESIS` (64 zero hex digits).
- Field order in the row literal is canonical and load-bearing. The
  Python walker in `docs/audit_walker.py` mirrors that order so chain
  verification does not depend on trusting Occasio's own code.
- `audit_schema: 1` versions every new row. Verifier accepts legacy
  schema-less rows; unknown future versions log a warning but do not
  flip ok=false.
- `loadPrevHash()` reads only the trailing 64KB of the log so bootstrap
  on a million-row chain stays O(window) instead of O(file).
- On a partial trailing line (crash mid-append), `loadPrevHash` fails
  hard with `AUDIT_CORRUPT`. Use `occasio audit repair --file <path>`
  to truncate the partial line; a `.bak` is written first.

Subcommands:

```
occasio audit verify [--file <path>]
occasio audit repair --file <path> [--dry-run]
```

### 5. Attest — `src/attest/`

At the end of a session (or on demand), the attest module builds an
in-toto statement covering the chain segment between two hashes and
signs it with Sigstore (keyless Fulcio + Rekor). The browser viewer in
`integrations/attest-view/` can re-verify the bundle.

## Cross-cutting concerns

- **Tool-name registry** (`src/core/tool-names.js`) holds canonical
  tool identifiers. Adapters emit only canonical names. New tools must
  be registered there first.
- **Boundary events** (`src/core/boundary-event.js`) are the only
  cross-stage data type. If a stage needs a new field, add it to the
  boundary event rather than passing it through a side channel.
- **Cost & ledger** (`src/cost/`) tracks tokens, model prices, and
  per-session spend. The pipeline emits cost events into the same
  audit log, chained with the rest.
- **Policy hot-reload** records a `policy_loaded` audit row whose hash
  links into the same chain — a policy swap is a first-class event.

## What lives where

| Concern               | Path                          |
|-----------------------|-------------------------------|
| HTTP proxy            | `src/index.js`, `bin/`        |
| Anthropic SSE         | `src/adapters/claude-code.js` |
| MCP server            | `src/adapters/mcp-server.js`  |
| Policy DSL            | `src/policy/loader.js`        |
| Policy engine         | `src/policy/engine.js`        |
| Dispatcher            | `src/dispatch/`               |
| Local tool execution  | `src/dispatch/executors/local.js` |
| Audit chain           | `src/audit/jsonl-auditor.js`  |
| Audit repair          | `src/audit/repair.js`         |
| Audit verifier        | `src/audit/verifier.js`       |
| Attestation           | `src/attest/index.js`         |
| Cost/ledger           | `src/cost/`                   |

## What is intentionally NOT in this diagram

- Telemetry: there is none, by design.
- Background daemons: audit writes happen synchronously on the
  request-handling path. A queue-based async writer is a roadmap item
  (`src/audit/queue.js` is reserved) but has not landed.
- Database: every persisted artifact is an append-only file. No SQL,
  no migrations to manage at runtime.

## Reading order for new contributors

1. `src/core/boundary-event.js` — what flows through the pipeline.
2. `src/policy/engine.js` — pure-function decisions.
3. `src/audit/jsonl-auditor.js` — the hash-chain invariant.
4. `src/dispatch/index.js` — how Decisions become Results.
5. `test-audit-chain.js` — the scenarios the auditor must survive.

After those five files the rest of the codebase reads quickly.
