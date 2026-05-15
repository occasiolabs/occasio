# Stage-2 Step 5 — Shell native-handler extraction plan

Step 5 of `docs/ADAPTER-STAGE-2-MIGRATION.md`. Not yet executed because the
work is structurally bigger than Steps 1–4: `nativeHandle` is not a single
handler but an in-line dispatcher with ~30 command branches across Bash and
PowerShell. Splitting it cleanly requires a sub-plan.

This document is the sub-plan. It must be approved (or revised) before any
extraction code is written.

## What is in scope

The starting point is `nativeHandle(cmd)` inside `src/interceptor.js`, plus
the helpers `runCompound`, `parseFlagsAndPath`, `stripQuotes`, and the
PowerShell-specific normalisation in `expandPsEnvVars`.

The compound-chain code (`runCompound`, `isCompoundHandleable`, the
`cd`/`Set-Location` cwd-prefix logic) is interleaved with the per-command
branches. It cannot move independently — handlers and the compound runner
share the same `cwd` tracking convention.

## What is NOT in scope

- Bash/PowerShell dispatch routing through `pipeline.processToolEvent`.
  This is already in place via `src/executor/dispatcher.js`
  (`NATIVE_HANDLERS[CANONICAL.SHELL_BASH]` wraps `nativeHandle` and returns
  the dispatcher-shaped `{ output, exitCode, native }` Result). The
  "Decision-shape mismatch" caveat in the original migration doc is
  partially stale: the dispatcher already canonicalises the return value.
  What remains is whether `nativeHandle`'s own internal `null`-on-no-match
  signal needs to become a Decision (`PASS` to fall back, `LOCAL` to handle).
  Step 5 does NOT change that contract — it only relocates the code.
- The legacy `runLocally` exec path. That is the cloud-fallback subprocess
  for shell commands the proxy decided not to intercept. Out of scope.
- Decision-shape unification across all dispatch surfaces. That is a
  Stage-3 concern (per ARCHITECTURE.md "tool-name canonicalisation" note).

## Sub-step plan

The constraint at each step is the same as in Steps 1–4: every step must
keep `npm test` green, must keep `runtime.js` / `interceptor.js` as
re-export shims, and must produce one refactor commit + one test commit.

| Sub-step | Module | Origin (src/interceptor.js) | Destination | Notes |
|---|---|---|---|---|
| 5a | shell-read handlers | `cat` / `bat` / `type`, `Get-Content`, `head`, `tail` branches | `src/executor/native-handlers/shell-read.js` | Smallest blast radius. All four share `parseFlagsAndPath` and `readFileNative` (already in read.js). |
| 5b | shell-stat handlers | `test -f|-e|-d`, `Test-Path` branches | `src/executor/native-handlers/shell-stat.js` | Self-contained. No shared helpers beyond `path.resolve`. |
| 5c | shell-list handlers | `dir`, `Get-ChildItem`, `find -name` branches | `src/executor/native-handlers/shell-list.js` | Uses an internal recursive `walk()` — needs to keep `SKIP` consistent with `GLOB_SKIP` from `glob.js` (or import it). |
| 5d | shell-search handler | `Select-String` branch | `src/executor/native-handlers/shell-search.js` | Single-file search. Comment in source explicitly says glob expansion is intentionally NOT supported here — keep that limit. |
| 5e | shell-git handler | `git status` / `git log` / `git -C <path>` / bare-git branches + `isBareGitReadOnly` / `isGitCSegment` | `src/executor/native-handlers/shell-git.js` | Largest single family. Shares `runOneShellCommand` exec helper with `runCompound` — must be lifted to a small shared util (`src/executor/native-handlers/shell-exec.js`) first. |
| 5f | shell-compound runner | `runCompound`, `isCompoundSegment` family, `cd`/`Set-Location` cwd-prefix logic, echo-segment passthrough | `src/executor/native-handlers/shell-compound.js` | Depends on 5a–5e being done first: the runner dispatches to per-family handlers and tracks cwd across segments. Pull that orchestration out only after the families are stable. |
| 5g | thin router | reduced `nativeHandle` becomes pure dispatch: lookup head → call family handler | `src/executor/native-handlers/shell.js` | Final step. Once the family handlers are in their own files, `nativeHandle` shrinks to ~30 lines. Move it into `shell.js`; `src/interceptor.js` re-exports for back-compat as everywhere else. |

Estimated effort: 5a-5d ≈ half-day each (well-trodden pattern). 5e is the
biggest — git semantics, multiple test sections in `test-interceptor.js`,
needs the shared exec helper first. 5f and 5g are smaller but order-dependent.

## Why this order

- **Read-only-on-files first (5a, 5b)**. Lowest risk. Handlers are pure
  filesystem reads; tests are stable; no shared state.
- **Searching/listing next (5c, 5d)**. Still read-only; just larger output.
- **Git last among families (5e)**. Touches the live `git` binary in tests
  (via `execFileSync`), shares an exec helper with the compound runner. The
  shared helper must move first.
- **Compound runner after families (5f)**. The runner orchestrates the
  families. If extracted earlier, it would re-cross the boundary back into
  `interceptor.js` to call branches that haven't moved. Cleaner to wait.
- **Router last (5g)**. By then `nativeHandle` is a pure routing function
  and the rename + relocation is mechanical.

## Test relocation

Each refactor commit pulls the corresponding section of `test-interceptor.js`
into a new module-mirroring file under `test-native-handlers.js`. Routing
tests (`isInterceptable`, `isNativeHandleable`, `isPowerShellNativeHandleable`)
stay in `test-interceptor.js`. Compound-chain tests stay until 5f.

## Stop conditions / abort criteria

- If any sub-step requires changing handler behaviour (not just relocation),
  revert and re-plan. A behavioural fix and a structural move must not ride
  on the same commit.
- If `nativeHandle`'s `null`-on-no-match signal needs to become a Decision
  during the move, abort and address that as Stage-3 work first. The Step 5
  scope is "relocation without behaviour change".
- The `parseFlagsAndPath` and `stripQuotes` helpers may turn out to be
  shared by more than one family. If so, lift them to a `shell-parse.js`
  helper module before the family extractions, not during.

## After Step 5

`src/interceptor.js` should be ≤ 600 lines (currently 1095, was 1098 before
the `anthropicRequest` removal). The remaining content will be:

- `parseSSE` (Anthropic SSE protocol)
- `interceptToolUse` orchestration (the main exported entrypoint)
- `runLocally` (legacy exec fallback)
- `buildFollowUpHeaders` (HTTP plumbing)
- `runOneRound`, `blocksToContent`, `classifyBlock`, `isInterceptable`,
  `isNativeHandleable`, `isPowerShellNativeHandleable` (routing helpers)
- `FALLBACK_REASONS`, `LOCAL_BASH_CMDS` (constants)

That is the natural shape of an SSE-protocol interceptor — what is left
after extracting the per-tool execution. At that point `runtime.js` can be
deprecated (it would be a pure re-export shim) and dropped in a minor
version.
