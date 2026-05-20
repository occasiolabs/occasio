# Roadmap — next sessions

Living document. Tracks what's worth doing next, in order of impact.
Updated 2026-05-15 after the security-evaluation session.

## Where we are

v0.8.4. After today's work:

- Stage-2 native-handler extraction is **4 of 5 done** (Todo, Read, Glob,
  Grep moved to `src/executor/native-handlers/`). Only Shell is left and
  has its own sub-plan.
- `lint:all` is clean across 72 src files; pretest-gated.
- Public-API surface is snapshot-locked.
- First-party threat model exists; fuzz harness exists; three real
  fuzz-discovered bugs are fixed.

What's *not* yet true:

- Anomaly thresholds still come from synthetic baselines.
- MCP regression tests are not in the default `npm test`.
- The launch package (npm publish, screenshots, Mac validation) is
  unfinished per the v0.6.1 launch memo — still unfinished at v0.8.4.
- `src/interceptor.js` is 1093 lines; Shell extraction would cut it to
  ~600 and let `src/runtime.js` deprecate.

## Tier A — single biggest unlocks

These are the things that move the needle furthest for the smallest
investment. Pick one per session.

### A1. Real-world anomaly calibration

The detector positions occasio as "EDR for AI agents." Today its
thresholds are guesses against synthetic data. **One bad first
demo with false-positives every five minutes burns the pitch.**

Plan: collect 200–500 real Claude Code sessions across a few projects
(your own usage is enough), feed through `localfirst preflight`, plot
the deny-rate / tool-rate / error-rate distributions, set the multipliers
empirically. Document FP-rate in `docs/ANOMALY-CALIBRATION.md`.

Effort: 1–2 sessions.
Unblocks: credible compliance pitch; honest "EDR" claim.

### A2. Launch package finalisation (npm publish)

Per memory, this has been "one step away" since v0.6.1. Now v0.8.4.
The repo is publish-ready; the *act* of publishing isn't done. Until
it is, every internal refactor is invisible to the outside world.

Manual items (per memory):
- Screenshots for README
- Launch email / HN / discord posts
- Mac validation (Windows-only tested today)
- `npm publish --access public` to `@occasiolabs/occasio`

Effort: half a session — but mostly non-coding (validation, content).
Unblocks: outside-world feedback loop.

### A3. Stage-2 Step 5 — Shell handler extraction

Mechanical but high-LOC. Sub-plan exists in
`docs/STAGE-2-STEP-5-SHELL-PLAN.md`. Seven sub-steps (5a–5g);
realistically 2–3 sessions.

After this, `interceptor.js` is ≤ 600 lines, `runtime.js` can be
deprecated, and the codebase has a clean uniform handler model.

Effort: 2–3 sessions.
Unblocks: deprecating runtime.js shim; lower friction for future
shell-classifier work.

**Sequence recommendation:** A1 first (smallest, highest external
leverage), then A2 (capitalise on the calibration story in the launch
post), then A3 (internal cleanup once external traction matters less).

## Tier B — meaningful but not blocking

### B1. MCP regression suite in `npm test`

`test-mcp-server.js` exists but runs only via `npm run test:mcp`.
Means a refactor touching MCP can pass CI and break in production.
Fold it into the default test script (or add a parallel CI job).

Effort: 30 minutes.

### B2. Symlink-following control in `handleReadTool`

Threat-model B4 residual risk #2. `fs.readFileSync` follows symlinks
without policy check; an agent can point a symlink at a sensitive file
inside a `deny_paths`-protected directory and the resolved-path check
runs *after* the read. Fix: `fs.lstatSync` + reject `isSymbolicLink()`
unless an explicit allow.

Effort: half a session, including tests.

### B3. Per-round rate limit

Threat-model B1/B4 residual #1. No per-connection cap; a buggy or
malicious agent can issue 10k tool calls per round and burn through
budget. Add a per-`runOneRound` count cap (default 50, env-tunable).

Effort: half a session.

### B4. Entropy-based secret detection

Threat-model B1/B2 residual #3. `scanSecrets` is pattern-only. Add a
Shannon-entropy heuristic for token-shaped strings (≥20 chars,
entropy ≥4.5 bits/char, no whitespace). Logged separately so a single
false-positive doesn't poison the whole detection signal.

Effort: half a session.

## Tier C — nice to have, low urgency

- Exact pin `sigstore` (currently `^3.1.0`) — supply-chain hygiene.
- Mutation testing of `classifyBlock` via `stryker` or hand-rolled
  AST mutator — catches whitelist regressions.
- Type-checking via `// @ts-check` on `src/core/` and `src/attest/`
  without going full TypeScript.
- Per-handler benchmarks (`npm run bench`) — track perf regressions.
- Drop `src/runtime.js` shim after Step 5 ships and one minor version
  passes (per Stage-2 plan Step 7).

## What is explicitly *not* on this list

- Adding new agent integrations (Cline, OpenCode, Aider). The
  adapter pattern supports it but only after Step 5 lands and the
  Decision contract is uniform.
- Web dashboard rewrite. The current dashboard works; UI investment
  beats engine investment only after launch.
- Multi-tenant / hosted mode. Out of scope for a local-first proxy.

## Decision protocol for adding to this list

A new item joins if (a) it closes a documented residual risk in
`docs/THREAT-MODEL.md`, or (b) a user reports it as a blocker, or
(c) a regression test demands it. Speculative features wait.

## Tracking

Each tier item, when started, gets its own working doc in `docs/` with
the same structure as `STAGE-2-STEP-5-SHELL-PLAN.md`: what's in scope,
what's not, sub-steps, abort criteria. No item is "in progress" without
a plan doc.
