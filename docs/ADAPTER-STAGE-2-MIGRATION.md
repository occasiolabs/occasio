# Adapter Stage-2 Migration

Stage 1 (already complete) moved the cross-cutting pipeline plumbing —
boundary events, processToolEvent, tool-name canonicalisation — into
`src/core/`. The result is an interceptor that still owns dispatch logic
but no longer owns the canonical event-construction or the
decision/effect bookkeeping.

Stage 2 separates **tool execution** from **dispatch routing**. The goal
is that `src/interceptor.js` shrinks into a thin router whose only job is
to map an incoming Anthropic SSE tool_use block to a per-tool *native
handler*, and that those native handlers live in their own files under
`src/executor/native-handlers/`. Every native handler is a pure function
of `(input, sessionContext) → { output, exitCode, … }` with no
dispatch-loop awareness.

## What has moved so far

| Step | Module | Origin | Destination | Status |
|---|---|---|---|---|
| 1 | TodoWrite / TodoRead native handlers | `src/runtime.js` | `src/executor/native-handlers/todo.js` | ✅ |
| 2 | Read native handler (+ `MAX_OUTPUT`, `READ_SKIP_EXTENSIONS`, `readFileNative`) | `src/runtime.js` | `src/executor/native-handlers/read.js` | ✅ this commit |

`src/runtime.js` re-exports the moved symbols, so every existing import
path (`src/interceptor.js`, tests, the MCP server) continues to work
without a code change.

## What is still pending

The order below reflects the cleanest dependency boundary at each step:
moving a handler **without** also moving its tests and without breaking
`executeLocalTool()` is the constraint that controls sequencing.

| Step | Module | Origin | Proposed destination | Notes |
|---|---|---|---|---|
| 3 | Glob native handler | `src/runtime.js` `handleGlobTool`, `globToRegex` | `src/executor/native-handlers/glob.js` | Self-contained except for `path` and `fs` calls. |
| 4 | Grep native handler | `src/runtime.js` `handleGrepTool` | `src/executor/native-handlers/grep.js` | Self-contained. Shares `head_limit` / `offset` semantics with Glob — extract the small helper once both are moved. |
| 5 | Bash / PowerShell native dispatch | `src/interceptor.js` `nativeHandle` + `extractShellReadPaths` | `src/executor/native-handlers/shell.js` | The exec path is still Decision-shape mismatched (Stage-1 caveat). Don't move until `nativeHandle` returns a canonical Decision. |
| 6 | `executeLocalTool()` wrapper | `src/runtime.js` | `src/executor/index.js` | Once steps 2–5 are done, the wrapper becomes the executor module's public surface. `runtime.js` is then a thin compatibility shim and can be deprecated. |
| 7 | Remove `runtime.js` shim | — | — | After two minor versions with `runtime.js` re-exporting from `executor/`, drop the file. |

## Why incremental

A single big move would either: (a) keep `runtime.js` as a frozen
re-export forever, which obscures the real module graph; or (b) update
every import site in one commit, which is hostile to bisection. The
per-handler approach lets us validate each step against the full test
suite (`npm test`, all 2632 + 86 + 58 + 26 + 6 = 2808 tests passing as
of this commit) before moving the next.

## Test hygiene

`test-interceptor.js` is currently ~10kLoC and groups its tests by
section number, not by handler. As each handler moves out of
`runtime.js`, the tests in that section should also relocate to a
dedicated `test-native-handlers.js` (or `test-native-<handler>.js` if
the volume warrants splitting further). The TodoWrite/TodoRead tests
are the first candidates — they cluster around section "9. TodoWrite"
and "9b. TodoRead" in `test-interceptor.js`.
