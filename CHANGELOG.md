# Changelog

## [0.8.0] — 2026-05-11  Path-1 ↔ path-2 defense symmetry + Claude-in-Claude self-test stack

The first release where LocalFirst can validate its own governance claims
against a real Claude Code subordinate session — and where every defense
class (deny_paths, redact-secrets, distill-output, max_output_tokens) is
enforced symmetrically at both the tool-call gate AND the outbound auto-
context body. Two real bypasses surfaced via the new self-test stack and
were fixed in the same release.

### Fixed — security (auto-context bypass class)

The pre-existing tool-call gate (path-1) intercepted `tool_use` blocks the
cloud model emitted. But Claude Code (and other agent runtimes) inject
synthetic `tool_use Read` + `tool_result <file content>` pairs into the
OUTBOUND request body as agentic context BEFORE the model has had a chance
to call any tool. Those tool_results never triggered path-1 because no
model-initiated call happened. Two concrete bypasses found by the new
`localfirst harness` against a real subordinate session:

- **deny_paths bypass.** A denied file was read via auto-context and its
  bytes reached the model anyway. Closed by a new path-2 gate in
  `src/outbound-policy.js::enforceOutboundDenyPaths`.
- **redact-secrets bypass.** An AKIA-shaped fixture in an auto-context
  tool_result was forwarded unredacted. Closed by
  `enforceOutboundSecretRedaction`. Behaviour chosen: always **REDACT**,
  never request-block — strict-mode block stays at path-1.

`enforceOutboundShaping` completes the trio with path-2 distill-output and
max_output_tokens enforcement. Defense matrix:

| Class             | Path-1 (tool-call) | Path-2 (outbound auto-context) |
|-------------------|--------------------|--------------------------------|
| deny_paths        | ✓                  | ✓ (new)                        |
| redact-secrets    | ✓                  | ✓ (new)                        |
| distill-output    | ✓                  | ✓ (new)                        |
| max_output_tokens | ✓                  | ✓ (new)                        |

Audit reasons: `outbound-context-path-denied`, `outbound-secret-redacted[-strict]`,
`outbound-shaping-<step>+<step>`. Each path-2 enforcement writes its own
audit row with `direction: 'outbound'` so `localfirst report` and the
independent Python walker see both gates uniformly.

### Added — self-test infrastructure

**`localfirst harness`.** End-to-end governance validation against a real
Claude Code subordinate. Spawns `localfirst claude --print <prompt>` with
scratch policy + scratch audit chain in `os.tmpdir()`, never touches the
user's real `~/.localfirst/`. Authenticates via Claude Code's bundled
auth — no `ANTHROPIC_API_KEY` required when the user is signed in via
Claude Pro. Nine v1 scenarios: `deny-read`, `deny-shell-bypass`,
`symlink-bypass`, `redact-secrets-live`, `context-budget-live`,
`encoded-output` (discovery), `plain-text-context` (discovery),
`tool-chain-read-write-read` (discovery), and `mcp-deny-read` (protocol-
level, $0 per run). Each scenario also runs an independent audit-chain
verifier so a defended-but-chain-broken outcome is correctly FAILed.

**`localfirst redteam`.** Autonomous adversarial tester. A second LLM
(default Haiku 4.5) is given an exfiltration goal and a 4-tool surface
(`send_prompt`, `read_audit_log`, `read_subject_response`, `done`) to
probe the subordinate. Tester's verdict is recorded but NOT trusted —
an independent verifier walks the audit chain + transcript and emits the
true verdict. Tester-hallucinated-exploit cases ("said yes, found
nothing") are surfaced as their own signal. Hard caps: `--max-turns`,
`--tester-budget` (USD). Peer dep on `@anthropic-ai/sdk`, dynamic
require with install hint if missing.

**`localfirst selftest`.** Eight in-process governance checks on a
scratch policy and scratch audit chain. Synthetic boundary events
(no LLM), runs in <1 s. Covers `read_file` deny, shell-bash deny,
shell-powershell deny, allow-path positive, secret BLOCK under strict
mode, redact-secrets TRANSFORM, audit-chain verify, chain shape sanity.

### Added — context-control / observability

**`localfirst boundary`.** Per-request three-column view: tool output
**produced**, tool output that **re-entered** the model, tool output
**prevented** from re-entering and why (`distill_clip` / `redact_secrets` /
`context_budget` / `block`). Backed by new `bytes` / `kept_bytes` /
`prevention_reason` fields on every recorded tool call.

**`localfirst baseline`.** Per-project behaviour baseline. `learn` mines
the last N days of logs scoped to the current cwd into
`~/.localfirst/baseline/<cwd-hash>.json`; `compare` walks the most recent
session and surfaces anomalies: `sensitive_path` (HIGH — covers `~/.ssh`,
`~/.aws`, `*/credentials`, `*.env*`, `/etc/(shadow|passwd|sudoers)`,
even on cold start), `new_path` / `new_tool` (medium), `new_shell_verb`
(HIGH for `curl`/`wget`/`ssh`/`rm`/`sudo`, medium otherwise),
`volume_spike` (>1.5× p95).

**`localfirst replay --attribute`.** Per-run token attribution. Answers
"who ate the context window?" without persisting request bodies. Splits
the run's input tokens into tool_contributions (per canonical tool
category, approx), cache_reuse (exact), residual (system + user + carry-
over). Plus a four-line prevented-from-re-entering breakdown derived
from existing JSONL fields.

**Per-tool context budget.** `policy.yml` `tools.<name>.max_output_tokens`.
Applied as the FINAL clip after any TRANSFORM/distill so the budget can
further trim already-shaped output. Validator errors on non-positive-
integer values — a silently-dropped budget is a cost-control gap.

### Added — continuous adversarial testing

**`.github/workflows/redteam.yml`.** Two-tier CI workflow.

- **Free tier** (every push to `main`, every PR, nightly 04:00 UTC, $0 per
  run): unit tests + smoke + selftest + `mcp-deny-read` cross-protocol
  scenario. MCP scenario costs zero — JSON-RPC against the local MCP
  server, no LLM in the loop.
- **LLM tier** (nightly + manual dispatch, gated on `ANTHROPIC_API_KEY`
  secret, ~$2-3 per night): full agent-driven scenario battery with
  spend bounded by per-scenario `--max-budget-usd` + 120-180s timeouts.
  Discovery probes (`encoded-output`, `plain-text-context`,
  `tool-chain-read-write-read`) flagged `continue-on-error` so a future
  bypass surfaces as a warning rather than hard-failing the workflow.
- 365-day artifact retention on LLM-tier results — a full year of
  per-night governance audit recoverable via `gh run download`.

Drift guard: a unit test asserts every scenario referenced in the
workflow YAML is a real entry in `SCENARIOS` in `src/harness.js`.

### Removed

- `src/localrouter.js` (Ollama / local-LLM routing). Undocumented in the
  v0.7.1 reframe; out of scope for the new context-control product
  story.
- `demos/01-local-interception.md`, `demos/02-secret-detection.md`,
  `demos/03-cost-ledger-replay.md`. v0.5-era framing, superseded by the
  cross-protocol demo at `docs/demos/mcp-block.md` which is the only
  demo the README now links to.

### Changed

- README `## Demos` section now links only to the cross-protocol mcp-
  block demo. The three legacy demos and their stale framing are gone.
- `ARCHITECTURE.md` introduction neutralised; the "Stage 1" in-progress
  framing is replaced with a stable architectural overview.
- `package.json` adds `npm run test:mcp` for `test-mcp-server.js` (MCP
  input normalization regression tests), making the MCP test surface
  discoverable alongside `npm test` and `npm run smoke`.

### Notes

- 2372 unit / 113 smoke / 8 selftest assertions, all green.
- Live-validated all five defense scenarios + the MCP cross-protocol
  scenario from a real Claude Code subordinate session via
  `localfirst harness`.
- `localfirst --version` now prints `localfirst v0.8.0`.

## [0.7.1] — 2026-05-11  Context-control framing + four observability features

A substantive release. The headline shifts from "govern, audit, prove" to
**"control what re-enters the model after every tool call."** Audit/compliance
becomes the evidence layer, not the lead. Four user-visible commands ship the
new framing end-to-end, and one critical enforcement bypass is closed.

### Fixed (security)

**deny_paths shell-mediated read bypass.**
- Before this release, `deny_paths` and `allow_paths` were only evaluated for
  the typed tool surface (`read_file`, `find_files`, `grep`). A `Bash { cat
  <denied-path> }` or PowerShell `Get-Content <denied-path>` skipped the path
  check entirely, was routed through the bash/powershell allowlist, and read
  the file. `Read` returned `(blocked by policy)` while `cat` returned the
  bytes — a direct contradiction of the documented governance claim.
- `src/policy/shell-path.js` (new) extracts file operands from the shell
  command shapes the native handler actually executes (`cat`, `bat`, `type`,
  `head`, `tail`, `Get-Content`), including `cd <dir> && <read>` and
  `Set-Location <dir>; <read>` compound chains.
- The engine now consults `deny_paths` / `allow_paths` against every
  extractable shell read operand before classifier dispatch. A denied operand
  blocks the whole shell command.
- 21 new unit tests (Section 35) + 1 smoke test (Section 17) cover the closed
  bypass. GOVERNANCE's "deny rule consulted before any routing decision, so
  it cannot be bypassed" sentence is again truthful.

### Added — control plane

**`localfirst boundary` (Feature 1).**
- Per-request three-column view: tool output **produced**, tool output that
  **re-entered** the model's next request, tool output **prevented** from
  re-entering and why. Reads the existing JSONL log and projects it through
  `buildBoundaryView`; renders a colour-coded table per request.
- New data primitives recorded on every tool call: `bytes` (raw, unchanged),
  `kept_bytes` (post-shaping), `prevention_reason` (`distill_clip` /
  `redact_secrets` / `context_budget` / `null`). Backward-compatible — older
  log entries without `kept_bytes` render as "kept fully".
- `--last N`, `--entry N`, `--run <prefix>`, `--json`, `--scope today|all`.

**Per-tool context budget — `max_output_tokens` (Feature 2).**
- New `policy.yml` field on any tool entry. Applied as the FINAL clip after
  any TRANSFORM/distill so the budget can further trim already-shaped
  output. Mirrors the existing distill marker convention with
  `[LocalFirst: ~Nt cut by context_budget (max Mt). …]` so the reason
  is visible to the model and to `localfirst boundary`.
- Validator (`policy validate`) errors on non-positive-integer values —
  silently dropping a budget rule is treated as a cost gap, not a warning.
- Hot-reload applies on the very next tool call (existing policy loader
  contract).

**`localfirst baseline` (Feature 3).**
- Per-project-cwd behaviour baseline. `baseline learn` mines the last N days
  of logs scoped to the current project, persists a frequency profile to
  `~/.localfirst/baseline/<cwd-hash>.json` (paths, tool categories, shell
  verbs, session size quantiles).
- `baseline compare` walks the most recent session against the baseline and
  surfaces anomalies: `sensitive_path` (HIGH, fires even on cold start;
  hardcoded list covers `~/.ssh`, `~/.aws`, `~/.gcloud`, `~/.azure`,
  `~/.gnupg`, `*/credentials`, `*/secrets`, `*.env*`, `/etc/shadow|passwd|
  sudoers`, `*/private/*`), `new_path` / `new_tool` (medium), `new_shell_
  verb` (HIGH for `curl`, `wget`, `ssh`, `rm`, `sudo`, `npm`, `pip`, …),
  `volume_spike` (>1.5× p95 baseline session size).
- Baselines are local-only, no export, no telemetry.

**`localfirst replay --attribute` (Feature 4).**
- Per-run token attribution. Answers "who ate the context window?" without
  persisting request bodies. Three classes: **tool contributions** (Σ
  kept_bytes / 4, approximate, marked '~'), **cache reuse** (Σ cache_read_
  tokens, exact, Anthropic-reported), **residual** (Σ input_tokens − tool_
  kept_total — covers system prompt + user messages + cross-request tool_
  result carry-over). Plus a four-line "prevented from re-entering"
  breakdown derived from existing JSONL fields.
- Counterfactual line shows what the run would have cost without LocalFirst
  shaping.

### Added — self-verification

**`localfirst selftest`.**
- Eight in-process governance checks on a scratch policy and scratch audit
  chain in `os.tmpdir()`. Never touches the user's `~/.localfirst`. Covers
  read_file deny, shell_bash/shell_powershell deny (the new bypass class),
  allow-path positive, secret BLOCK under strict mode, redact-secrets
  TRANSFORM, audit-chain verify, chain shape sanity (≥3 BLOCK + ≥1
  TRANSFORM). Single command, exit 0 on green / 1 on red.

### Changed — public framing

- **README headline.** "Govern, audit, prove" → "Control what re-enters the
  model after every tool call." "What it does" rewritten as five sections in
  the new priority order: per-tool decision → local execution → shape &
  redact → cross-protocol → audit as evidence layer. "How it works" rewritten
  so the control point comes first; legacy v0.5-era proxy/cache framing is
  gone.
- **Cross-platform quickstart.** README quickstart no longer Windows-only;
  PowerShell and bash/zsh `register` flows shown side by side.
- **`GOVERNANCE.md` opening** aligned to the same framing.
- **`package.json` description** rewritten so npmjs.com search and
  `npm info` carry the new positioning.
- **Modes section** replaced by "Overrides" — clarifies that `--preset
  strict|off` are session-level overrides on top of `policy.yml`, not the
  durable surface.

### Removed

- **`src/localrouter.js`** (Ollama / local-LLM routing). Undocumented in the
  v0.7.0 reframe, ran a 1.5 s probe on every request even when no Ollama
  daemon was present, produced confusing `qwen2.5:7b` entries in `localfirst
  inspect`. The product story is now "control what re-enters the model after
  a tool call" — outbound prompt redirection is a separate problem and out
  of scope. If demand returns, reintroduce behind an opt-in flag with
  explicit policy.yml syntax.
- **`RELEASE.md`** — stale v0.6.2 checklist that contradicted current state.

### Notes

- **VERSION constant** in `src/index.js` synced to `package.json` (was
  `0.6.2` while `package.json` already said `0.7.0` — the banner lied).
  Adds a one-line value to the `--version` output and the session banner.
- **Tests.** 1923 → 2194 main (+271), 87 → 113 smoke (+26), 8/8 selftest
  scenarios, `npm run check-validation` PASS. Live-validated on the
  maintainer's Windows 11 workstation 2026-05-11.
- **Audit chain.** Multi-writer caveat from v0.6.5 still applies — running
  the Claude Code proxy and the MCP server simultaneously against the same
  `~/.localfirst/pipeline-events.jsonl` will break the SHA-256 chain. The
  maintainer rotated the broken local chain on 2026-05-11; a hardening pass
  (PID file or named-pipe single-writer guard) is queued for a later release.

## [0.7.0] — 2026-05-10  License: MIT → Apache-2.0

A licensing-only release. **No functional changes**, no new features, no
schema changes, no behavioural differences from v0.6.6.

### Changed

- **License changed from MIT to Apache License 2.0**, effective this release
  forward. Apache-2.0 is open source with the same freedoms as MIT plus an
  explicit patent grant — self-hosting, forking, embedding, modification,
  and commercial use all remain permitted at no cost.
- `LICENSE` replaced with the canonical Apache-2.0 text (verbatim, unmodified).
- `NOTICE` added per Apache-2.0 §4(d) attribution conventions.
- `LICENSE` and `NOTICE` now ship inside the npm tarball (`files` array).
- Package metadata updated: `package.json` now declares `Apache-2.0`.
- README license section updated.

### Important — past releases

Versions **0.6.6 and earlier** of `@localfirst-ai/localfirst` were published
under the MIT License. **Those releases remain MIT in perpetuity.** This
change governs v0.7.0 and all subsequent releases only; no attempt is made
(and none is legally possible) to retroactively alter the license of prior
published releases.

### Contributing

Contributions are accepted under Apache-2.0. Please sign off commits per the
[Developer Certificate of Origin](https://developercertificate.org/) using
`git commit -s`.

## [0.6.6] — 2026-05-10  Policy File as First-Class Product

A documentation-and-discoverability release that elevates `policy.yml` from a
config artefact to the durable product surface buyers leave a pilot with.
Five small additions; **no** new policy primitives, **no** new top-level
audit fields, **no** schema-based replacement of the existing validator,
**no** template sprawl.

### Added

**Published JSON Schema for `policy.yml`.**
- `schemas/localfirst-policy.schema.json` — JSON Schema draft 2020-12,
  covering every field the loader normalizes. The `$id` is
  `https://localfirst.ai/schemas/localfirst-policy.schema.json`. The schema
  ships in the npm tarball alongside `bin/`, `src/`, and `policy-templates/`.
- A test asserts every key the schema declares is also recognised by
  `src/policy/validate.js`'s `KNOWN_TOP_LEVEL` set, and vice versa. Drift
  between the two is caught at test time.
- The existing procedural validator is **not** replaced. `validate.js`
  enforces security-first error severity (silently dropped deny entries
  are errors, not warnings); a generic schema validator would lose that
  subtlety. The schema is published as the editor / IDE / third-party-tool
  contract; the validator is published as the runtime contract.

**Three starter templates: `dev-default`, `strict`, `finance`.**
- `policy-templates/{dev-default,strict,finance}.yml` are real files,
  inspectable in source control. Each carries the
  `# yaml-language-server: $schema=...` directive so editors with YAML
  language-server support get autocomplete and inline validation out of the
  box.
- `localfirst policy init --template <name>` selects one. Default remains
  `dev-default` (byte-identical to the previous starter). Unknown names exit
  non-zero with the list of valid names.
- `dev-default.yml` is the previous embedded `STARTER_POLICY` lifted out as a
  real file. `strict.yml` adds `deny_paths` for common credential locations
  plus a placeholder `allow_paths` and conservative `deny_patterns`.
  `finance.yml` adds `deny_patterns` for SWIFT/BIC, IBAN, US SSN, internal
  ticket-ID shapes, and JWT.

**`policy_loaded` synthetic audit event.**
- The proxy and the MCP server now emit one row to `pipeline-events.jsonl`
  on first policy load, and on every hot-reload that changes the policy
  file's bytes. The row uses the existing field order (no schema widening)
  with `kind: "policy_loaded"`, `tool_name: "policy_loaded"`,
  `tool_inputs: { policy_hash, policy_path, version }`, `action: "INFO"`,
  `reason: "policy-loaded"`. Per the v0.6.6 design note, `result_kind` is
  intentionally absent on these rows — a policy-load event has no
  dispatcher Result.
- The hash is SHA-256 of the **raw policy file bytes** (not the normalized
  policy object), so comments and whitespace count. The audit row is
  directly traceable to a specific file content under source control.
- Idempotent: `loader.load()` only fires the change callback when the hash
  transitions, never on every per-request load.
- The Python independent walker at `docs/audit_walker.py` works
  unchanged — `policy_loaded` is just another `kind` value to it. v0.6.6
  parity-tested both verifiers against a mixed-kind chain.

**Draft SOC 2 control mapping.**
- `docs/compliance-mapping.md` (NEW) maps `finance.yml` stanzas to SOC 2
  Common Criteria. Conservative scope: only stanzas whose link to a control
  is **directly evidenced by an audit row**. Two mappings (CC6.1 logical
  access; CC7.2 system monitoring); one section explicitly listing
  criteria deliberately *not* mapped to avoid overclaim.
- Flagged as **DRAFT** pending compliance-practitioner review. Conservative
  scope is the second-best protection in the meantime.

**README + GOVERNANCE + PILOT positioning rewrites.**
- All headline text now references the cross-protocol claim — Claude Code
  *and* MCP traffic governed by the same `policy.yml` — and points at the
  v0.6.5 demo at `docs/demos/mcp-block.md` as the artefact behind it.
- The repository URLs in `package.json` are updated from the previous
  `SynthexCapital/localfirst` org to `localfirst-ai/localfirst`.
- Discipline: every claim in the rewritten paragraphs points at an
  artefact in the repo. Test 34's link guard fails if any of those
  artefacts go missing.

### Documentation

- `docs/AUDIT.md` §1 documents the `policy_loaded` row kind explicitly,
  including the `result_kind`-absent design note. §6 "what this proves
  and does not prove" replaces the previous "v0.6.4 does not yet emit"
  caveat with the v0.6.6 behaviour.

### Notes

- All flags default off / empty; existing v0.6.5 deployments behave
  identically until `policy.yml` is edited.
- Tests: existing 1923 + new Section 34 = passing on
  `node test-interceptor.js`.
- Both verifiers (Node `localfirst audit verify`, Python
  `docs/audit_walker.py`) parity-checked on a mixed-kind chain that
  includes `policy_loaded` rows.

## [0.6.5] — 2026-05-10  One MCP Proof — Cross-Protocol Governance

A deliberately narrow release. v0.6.5 routes the existing LocalFirst MCP server
(`bin/localfirst-mcp`) through the same canonical pipeline (`policy.evaluate
→ dispatcher.dispatch → auditor.record`) that already governs the Claude Code
adapter. The architectural claim being proved is small but load-bearing:
**the same `policy.yml` governs Claude Code's `Read` and an MCP client's
`read_file`, byte-for-byte unchanged**. Audit rows from MCP traffic now land
in `pipeline-events.jsonl` with `protocol: "mcp"` and `localfirst report`
surfaces them under `blocked_accesses[]`.

### Fixed (behavior change)

**MCP traffic is now policy-governed.**
- Before v0.6.5, `src/mcp-server.js` called `executeLocalTool` directly,
  bypassing `policy.evaluate` and `auditor.record`. `deny_paths`, `allow_paths`,
  and `deny_patterns` were silently ignored on the MCP path; nothing landed in
  the canonical audit chain.
- v0.6.5 routes MCP `tools/call` requests through `pipeline.processToolEvent`.
  A denied call now returns `(blocked by policy)` to the MCP client with
  `isError: true`, and writes a single BLOCK row to `pipeline-events.jsonl`.
- **This is a behavior change.** Any environment where MCP calls were touching
  paths that `policy.yml` denies (but were succeeding because the MCP path was
  ungoverned) will now block. This is the correct behavior; it is a
  retroactive closure of a known governance gap.

### Added (small)

- **`agent` attribution from MCP `initialize.clientInfo.name`.** Audit rows
  from MCP traffic carry the calling agent's self-identification (e.g.
  `claude-ai` for Claude Desktop, `cursor`, `continue`). Falls back to
  `mcp-client` when the client omits `clientInfo`.
- **`docs/demos/mcp-block.md`.** A reproducible end-to-end capture of the
  cross-protocol proof: policy file, MCP requests, captured responses,
  verbatim audit row, both verifiers, and `localfirst report` output.
- **MCP-side AuditWriteError handling.** The MCP server inherits the v0.6.4
  fail-fatal contract: an audit-write failure aborts the MCP server with
  `[localfirst-mcp][audit-fatal]` on stderr.

### Concurrency note (deferred hardening)

`mcp-server.js` runs as a child process of the MCP client (e.g. Claude
Desktop) and writes to the same `pipeline-events.jsonl` as the Claude Code
proxy. v0.6.5 **assumes single-writer discipline** — only one of the two
appenders is active at a time. On Windows in particular, two concurrent
appenders to the same file can interleave and corrupt the chain. A dedicated
slice will harden concurrent audit writing if the MCP path proves valuable.
Until then: run the Claude Code proxy or the MCP server, not both
simultaneously, against the same audit file.

### Documentation

- `docs/demos/mcp-block.md` — the captured demo artefact.
- `CHANGELOG.md` — this entry.

### Notes

- No new policy primitives. No new audit fields. No new transforms. No CLI
  surface changes.
- No second MCP integration. No transparent forwarder. No README / GOVERNANCE
  positioning rewrite yet — that is sequenced after this proof exists.
- Tests: 1923 passing (1902 → 1923; 21 new tests in Section 33 cover schema
  parity, BLOCK row shape with `protocol: "mcp"`, allowed-flow regression,
  fallback to `mcp-client` agent, hash-chain integrity across mixed-protocol
  rows, and the existing `mcp-experiment.jsonl` adoption-log regression
  guard).
- Both verifiers agree on the maintainer's now-33-row reference log:
  `localfirst audit verify` → `Chain intact (33 rows verified)`,
  `python docs/audit_walker.py …` → `OK: 33 rows verified`.

## [0.6.4] — 2026-05-10  Hardening — Fail-Loud Audit, Supervisor Templates, Independent Walker

A small, deliberately featureless release. v0.6.4 raises the credibility floor
of the governance story without expanding what LocalFirst does. Three changes,
no new policy primitives, no CLI surface changes.

### Fixed (behavior change)

**Audit-write failures are now session-fatal.**
- Before v0.6.4, `auditor.record()` swallowed `fs.appendFileSync` errors in an
  empty catch. A disk-full or permissions failure could silently drop an audit
  row while the corresponding tool dispatch succeeded — meaning a successful
  cloud call could exist without a matching audit entry. That is incompatible
  with the governance promise.
- `auditor.record()` now returns `{ ok: true }` on a successful append or
  `{ ok: false, error, droppedRow }` on failure. `prev_hash` is only advanced
  on success, so a failed write cannot poison the in-memory chain.
- `pipeline.process()` promotes `ok: false` into a new `AuditWriteError`.
- The proxy's request handler in `src/index.js` catches `AuditWriteError`,
  writes the dropped row JSON to stderr with a `[localfirst][audit-fatal]`
  marker (so a supervisor / log scraper can recover it forensically), closes
  the listening socket, and exits non-zero after a 250 ms grace period.
- **This is a behavior change.** Environments that had a latent
  audit-unwritability problem in v0.6.3 will now surface it as a proxy crash
  rather than silently lose rows. That is the correct behavior; pair the
  proxy with one of the supervisor templates below.

### Added (operational)

**Supervisor templates under `bin/supervisor/`.**
- `localfirst.service` — systemd unit (user scope), `Restart=always`.
- `com.localfirst.proxy.plist.template` — launchd template (user scope), with
  `{{LOCALFIRST_BIN}}` placeholder for the absolute binary path.
- `install-windows-task.ps1` — registers a Windows Scheduled Task that runs
  at logon, restarts within 1 minute of exit, scoped to the current user
  (no elevation required).
- `bin/supervisor/README.md` — install commands and removal commands per
  platform, plus an honest validation status table.
- **Validation status:** Windows scheduled-task path is **manually validated**
  on Windows 11 + PowerShell 7. systemd and launchd templates are shipped but
  **not yet manually validated** by the maintainers; please open an issue if
  a pilot deployment finds problems so we can fix the template rather than
  let each pilot re-derive it.

### Documentation

**`docs/AUDIT.md` and `docs/audit_walker.py` — independent verifiability.**
- A standalone Python walker (~30 LOC, stdlib only) that re-walks the SHA-256
  hash chain over `pipeline-events.jsonl` without using any LocalFirst code.
- The doc specifies the row format, the canonical serialization rules, and
  the genesis sentinel precisely enough that any third-party verifier can
  reproduce LocalFirst's own `localfirst audit verify`.
- **Parity gate.** v0.6.4 verifies that `audit_walker.py` and
  `localfirst audit verify` agree byte-for-byte on the maintainer's 31-row
  reference log. The release was gated on this check passing; a regression
  on it is treated as audit-credibility-critical.
- The doc is linked from `GOVERNANCE.md`. It is intentionally explicit about
  what the chain does *not* prove (omitted rows, policy version in force,
  rows lost during a write outage that fail-fatal does not yet rescue).

### Notes

- No new policy primitives. No new audit fields. No new transforms. No CLI
  surface changes beyond the version bump.
- Tests: 1902 passing (1858 → 1902; 44 new tests cover fail-fatal contract,
  pipeline propagation, supervisor template structure, AUDIT-doc field-order
  parity with the auditor source, and walker invariants).

## [0.6.3] — 2026-05-10  Governance Milestone — Path Control, Custom Patterns, Audit Inputs, Report

This release closes the loop between *policy* and *evidence*. LocalFirst now captures
the full input to every tool call in the tamper-evident audit log, enforces
deny / allow lists on filesystem paths, lets you declare custom regex patterns that
extend the secret scanner, and ships a one-command compliance report. Together these
turn LocalFirst from a routing layer into a governance layer that an enterprise
buyer can reason about.

### Added

**Tool input capture in the audit log (ARCH-27)**
- Every `pipeline-events.jsonl` entry now records the normalized tool input alongside
  the existing decision fields. Path-bearing tools (`read_file`, `find_files`, `grep`)
  capture the resolved absolute path; shell tools capture the command. The audit
  hash chain extends over the new field, so any post-hoc edit is detectable by
  `localfirst audit`.
- Inputs are normalized at the boundary so the same logical action produces the same
  entry regardless of which agent issued it.

**Path-based access control — `deny_paths` / `allow_paths` (ARCH-27)**
- New top-level policy keys. `deny_paths` blocks any access under listed prefixes
  even when the tool would otherwise run locally; `allow_paths`, when non-empty,
  restricts access to only those prefixes.
- Comparisons run on the symlink-resolved absolute path (case-insensitive on
  Windows). A symlink that points into a denied directory is still denied.
- Blocks are surfaced as a `path-denied` / `path-not-allowed` BLOCK Decision and
  recorded in the audit log with `reason: path-denied`.

**Custom `deny_patterns` for the secret scanner (ARCH-27)**
- `deny_patterns:` is a mapping of `label: "regex-string"` entries that extend the
  built-in scanner. Patterns are compiled at load time; invalid regex entries are
  reported by `localfirst policy validate` rather than silently dropped.
- Use cases: internal JWT formats, ticket / case identifiers, project-specific
  tokens, locale-specific PII patterns.

**`localfirst report` — one-command governance summary**
- Aggregates the recent audit log into a buyer-readable report: counts of LOCAL vs
  PASS vs BLOCK decisions, distinct deny reasons, secrets caught, paths denied,
  and the audit-chain integrity status. Designed to be paste-ready for a
  compliance review or pilot conversation.

**Starter policy now demonstrates the new fields**
- `localfirst policy init` generates a starter file that includes commented-out
  examples for `deny_paths`, `allow_paths`, and `deny_patterns`. The defaults are
  still no-ops, so the file is safe to commit unedited.

### Changed
- `policy validate` now flags missing / non-string entries in `deny_paths` /
  `allow_paths` as **errors** (not warnings): a silently dropped deny entry is a
  silent security gap, not a cosmetic issue.
- `engine.evaluate` runs the path check before the routing check, so deny lists
  cannot be bypassed by a permissive `tools:` block.

### Fixed

**BLOCK enforcement at the adapter pre-flight (Slice E)**
- The Claude Code adapter previously collapsed the policy engine's tri-state
  Decision into a binary `handled = (action === 'LOCAL')`, which silently
  routed BLOCK Decisions to the cloud as "tool not handled" passthroughs.
  Net effect: deny_paths / deny_patterns / secret-block events on the tool-call
  path produced no synthetic refusal and no audit-log BLOCK row, so
  `localfirst report` structurally always reported `paths_blocked: 0`.
- The classifier now treats every dispatchable Decision (LOCAL / BLOCK /
  TRANSFORM) as handled by the local pipeline; only PASS and unregistered
  tool names fall through to the cloud. With this change, denied tool calls
  are dispatched through `pipeline.processToolEvent`, the dispatcher's BLOCK
  branch returns `{ blocked: true, response, reason }`, the auditor writes a
  `result_kind: "block"` row to `pipeline-events.jsonl`, and the agent sees
  the `(blocked by policy)` synthetic tool_result. `localfirst report` now
  surfaces the block under `summary.paths_blocked` and `blocked_accesses[]`.
- Single-file change in `src/adapters/claude-code.js`; downstream layers
  (engine, dispatcher, pipeline, auditor, report) were already correct.
  The Cline adapter inherits the fix because it delegates to
  `claudeCode.runToolLoop`.

### Notes
- All flags default off / empty; existing v0.6.2 deployments behave identically
  until `policy.yml` is edited.
- Tests: 1858 passing on `node test-interceptor.js` (25 new tests covering the
  BLOCK enforcement path: single denied read, `[denied, allowed]` mixed batch,
  `[denied, Bash]` partial batch with BLOCK + cloud, audit-row shape consumed
  by the report filter, and a regression guard for unblocked LOCAL traffic).

## [0.6.2] — 2026-05-09  Policy System — Transform, Chain, Validate, Init

This release ships the complete **policy system**: a single `~/.localfirst/policy.yml`
is now the authoritative document for *both* routing decisions (LOCAL / PASS / BLOCK)
*and* output shaping (TRANSFORM). The TRANSFORM action is wired end-to-end, composable,
observable, and live-reloading. A full authoring loop ships alongside it:
`init → edit → validate → show` — all changes take effect on the very next tool call.

### Added

**TRANSFORM is a real, dispatched action (ARCH-17 / ARCH-18)**
- Previously the distill / redact flags were applied unconditionally after every local
  tool call, bypassing whatever the dispatcher had decided.  `runOneRound` now respects
  the TRANSFORM decision: when the dispatcher returns a TRANSFORM result it uses that
  output directly; the legacy `distill()` fallback only runs when no transform was
  applied.  This closes the gap between policy and execution.
- `policy.yml` `tools:` entries can now specify `action: TRANSFORM` with a named
  `transform:` field (e.g. `transform: distill-output`), making per-tool shaping a
  first-class policy decision alongside LOCAL / PASS.
- Per-tool TRANSFORM takes precedence over global flags; global flags remain working
  shortcuts for sessions that don't need per-tool granularity.
- TRANSFORM metadata (`transform`, `secretsRedacted`, `distilled`, `savedTokens`) flows
  through toolsRun, is written to the daily log, and is recorded in the audit chain.

**Transform chaining — redact → distill in one pass (ARCH-20)**
- When both `redact_secrets_in_tool_results: true` and `distill_tool_results: true` are
  active (or both are implied by global + per-tool flags), LocalFirst automatically
  chains them: secrets are redacted first (security guarantee), then the redacted output
  is distilled (efficiency).  No extra config needed.
- `TRANSFORM_CHAIN(['redact-secrets', 'distill-output'])` is a first-class Decision type.
  The dispatcher runs the handler once and applies each step in sequence, so no tool
  call touches the network twice.
- The audit log records `transform: "redact-secrets+distill-output"` as a single
  stable, readable string; `secrets_redacted` and `distilled` are both populated.

**Per-tool transform observability (ARCH-21)**
- The dashboard Level 3 tool panel now shows per-tool transform badges:
  `⚠ N secrets redacted` (red-orange) when redaction ran, `✂ −Nkt` (yellow) when
  distillation ran with a token-savings figure, and `→ transform-name` as a fallback
  for custom / unknown transforms.  Plain LOCAL tools show nothing — no noise for
  simple sessions.
- The `localfirst status` command and exit banner now include a
  `Transforms: N tool results shaped` line when any transforms ran this session.
- `session.json` gains a `tools_transformed` counter; each log entry carries
  `tools_transformed` per-request.

**`localfirst policy show` — inspect the active policy (ARCH-19)**
- Displays the full active policy: global flags and per-tool routing decisions,
  annotated as `(default)` or `← override`.
- Warns when a `tools:` block is present (it replaces all built-in defaults) and
  lists the tools that will now PASS to the cloud.
- Warns when a tool entry references an unknown transform name.
- `localfirst policy show --diff` prints only values that differ from defaults —
  useful for quickly auditing what a policy file actually changes.

**`localfirst policy validate` — lint before it silently misbehaves (ARCH-23)**
- Parses `~/.localfirst/policy.yml` (or `--file <path>`) and reports every issue
  that would cause a silent failure at runtime.
- **Errors** (exit 1): unknown `action` value, `TRANSFORM` missing `transform` field,
  wrong type for a boolean flag, `tools:` not a mapping, tool entry not a mapping.
- **Warnings** (exit 0): unknown top-level key, unknown transform name, unknown
  classifier name (entry will silently PASS at runtime), unknown field in a tool entry.
- Output is structured: each issue is shown with its dotted key path and a plain-English
  explanation.

**`localfirst policy init` — strong first-run experience (ARCH-24)**
- `localfirst policy init` writes a commented starter `~/.localfirst/policy.yml` with
  all four flags at their built-in defaults and worked per-tool routing examples in
  comments.
- Safe by default: refuses to overwrite an existing file without `--force`.
- Supports `--file <path>` to write to a custom location; creates parent directories
  automatically.
- The generated file validates with zero errors and produces a policy identical to the
  built-in defaults — a safe no-op until the user edits it.
- After writing, prints next-step hints: `policy show` and `policy validate`.

**policy.yml hot-reload — no proxy restart needed (ARCH-22)**
- `load()` now reads the file's `mtimeMs` on every call.  If the mtime matches the last
  read — including `null === null` for a persistently absent file — the cached policy is
  returned instantly.  When the mtime changes (file written, created, or deleted) the
  policy is re-read and re-normalized on the very next tool call.
- Chose `statSync` over `fs.watch`: deterministic (reload happens on the next call, not
  asynchronously), no background thread, no cleanup, sub-millisecond cost per call.

### Complete authoring loop

```
localfirst policy init              # create ~/.localfirst/policy.yml
$EDITOR ~/.localfirst/policy.yml    # edit
localfirst policy validate          # catch errors before they bite
localfirst policy show              # confirm what is actually active
# proxy picks up changes immediately — no restart
```

### Fixed

- TRANSFORM results were silently discarded: `runOneRound` called `distill()` on all
  outputs unconditionally even when the dispatcher had already applied a TRANSFORM.
  Fixed: `distill()` is now skipped when `r.transformed` is true; the dispatcher's
  shaped output is used as-is.

### Tests

1472 → 1638 tests (166 new across ARCH-17–24):
- ARCH-17 (31): runOneRound transform wiring, toolsRun metadata, observability
- ARCH-18 (37): normalizeToolEntry TRANSFORM, engine dispatch, YAML round-trip, alias translation
- ARCH-19 (26): policy show CLI, formatToolEntry, isToolOverride, --diff mode, index.js wiring
- ARCH-20 (36): TRANSFORM_CHAIN factory, dispatcher chain execution, engine chain decisions
- ARCH-21 (23): session tracking, dashboard badges, CLI banner, chained result metadata
- ARCH-22 (16): mtime-based reload, file creation/deletion/modification detection
- ARCH-23 (57): validatePolicy all error/warning paths, runValidateCli, KNOWN_* coverage
- ARCH-24 (38): runInitCli create/guard/force, STARTER_POLICY parse clean, index.js wiring

---

## [0.6.1] — 2026-05-09  Tamper-Evident Audit Log + Multi-Agent Support (Stage 3)

### Added

**Tamper-evident audit log (`pipeline-events.jsonl`)**
- Every cross-boundary event is now hash-chained: each row carries `prev_hash` (GENESIS sentinel for the first row) and `hash` (SHA-256 of the serialized row without the hash field)
- Chain is continuous across process restarts — the auditor reads the last hash from the existing file on startup
- New command: `localfirst audit [verify] [--file <path>]` — verifies the full chain; reports legacy rows (written before hash support), chain breaks, and individual hash mismatches
- Any modification to any field in any row is detected: a tampered row triggers an error on that row and a cascade error on all subsequent rows (prev_hash mismatch)
- New module: `src/audit/verifier.js` — `verifyFile()` returns `{ ok, total, legacy, chained, errors, firstHash, lastHash }`

**Multi-agent support (Stage 3 architecture)**
- Second agent live-validated: Cline routes through the same canonical pipeline as Claude Code without any changes to the policy engine, dispatcher, scanner, or audit layers
- Canonical tool-name registry (`src/core/tool-names.js`): pipeline interior speaks agent-agnostic names; adapters translate at the boundary
- Agent routing: `x-localfirst-agent` HTTP header selects the adapter; SSE content fingerprinting is the fallback when the header is absent
- Policy-as-data (`policy.yml`): `tools:` block drives every LOCAL/PASS/BLOCK routing decision; built-in classifiers (`bash-allowlist`, `read-input-validator`, etc.) are named and configurable
- New adapters: `src/adapters/cline.js` + `src/adapters/claude-code.js` (refactored); `src/proxy/agent-router.js`

### Fixed
- Mid-loop fallback counter now preserves `toolsRun` across rounds so the per-request counter correctly credits earlier rounds

### Tests
- 1222 → 1271 (49 new tests in ARCH-14 covering hash-chain structure, tamper detection, legacy rows, restart continuity, verifier surface)

---

## [0.6.0] — 2026-05-07  Native Tool Interception (Read, Glob, Grep, TodoWrite, TodoRead)

### Added

**Native Read interception**
- `Read` tool calls are now handled in-process — no shell spawn, no I/O round-trip
- File content is read directly from disk; path traversal and binary-file guards are enforced
- `tools_local_count` and the live manifest include Read tool calls

**Native Glob interception**
- `Glob` tool calls handled entirely in-process using pure-JS pattern matching (`globToRegex`)
- Supports `**` recursive segments, `*` wildcards, `?` single-char wildcards, and `{a,b}` brace expansion
- Results are sorted by modification time (newest first), matching Claude Code's native sort order
- Falls back to delegating to Claude Code if the pattern is unsupported

**Native Grep interception**
- `Grep` tool calls handled in-process for all standard output modes: `files_with_matches` (default), `content`, `count`
- Supports `glob` file filter, `-i` case-insensitive, `-n` line numbers, `context`/`-C`/`-A`/`-B` window, `head_limit`, `offset`, `type` extension filter
- `multiline: true` requests fall back to Claude Code (multiline-dotall regex requires native ripgrep)
- Invalid regex returns a structured error output rather than crashing

**Native TodoWrite / TodoRead interception**
- `TodoWrite` and `TodoRead` are handled in-process with a session-scoped in-memory store
- `TodoWrite` replaces the store atomically; `TodoRead` returns the current JSON
- The store persists across all `interceptToolUse` calls within a session (`sessionTodoStore` in index.js)
- Both tools are always interceptable; neither requires a shell process

**Pre-send manifest (live terminal output)**
- A compact ▶ line is printed before each cloud-forwarded request showing model, message count, and estimated payload size (`~Xkt`)
- A ↑ line is printed at each `anthropicRequest` call within the interceptor showing local tool counts and payload estimate
- `⚡ local` prefix when tools are handled locally; `🛑 blocked` for blocked requests

### Fixed

- **`parseFileTokens` now works with modern Claude Code** — rewrote to use `tool_use` / `tool_result` pair correlation instead of the `--- path ---` delimiter format that Claude Code stopped emitting. File token breakdowns in `localfirst inspect` now populate correctly.
- **`Saved:` metric now honest** — `localfirst status` previously labelled Anthropic's own prompt-cache savings as "Saved by LocalFirst." Now split into `Cache: $X (Anthropic prompt cache)` (dim) and `Saved: $X (LAO / distill)` (green, only shown when non-zero). Same fix applied to the session exit summary and doctor session display.
- **`🛑` vs `⚠` in ledger and replay** — non-blocked requests that touched a secret now show `⚠` (warning) instead of `🛑` (blocked). `🛑` is reserved for `event_type: blocked` only.

### Tests

550 tests passing (63 new: 42 Glob tests in section 20, 57 Grep tests in section 21, 51 TodoWrite/TodoRead tests in section 23, 13 parseFileTokens tool_use/result-pair tests added to section 5 — existing delimiter tests retained).

---

## [0.5.3] — 2026-05-07  Cloud-Payload Visibility

### Added

**`localfirst inspect` — per-request cloud-boundary manifest**
- `localfirst inspect` shows the last request; `--last N`, `--entry N`, `--run <id>`, `--scope today`
- For each request type shows a structured boundary view:
  - `cloud_sent` / `trimmed`: files in context (names + estimated token counts), messages in request, cache stats, distilled tool results
  - `local_only`: commands executed locally with sizes and native/exec flag, note that results were forwarded to Anthropic, distilled outputs flagged
  - `blocked`: secrets detected with label + line numbers, rule-blocked files
  - `budget_exceeded`: limit and spend at time of block
- All labels distinguish exact values (provider-reported tokens) from estimates (LocalFirst file analyzer)

**`lao_dropped` now logged**
- Previously only printed to terminal; now persisted in every log entry as `lao_dropped: string[]`
- Visible in `localfirst inspect` and `localfirst replay --detail`

**`outbound_message_count` now logged**
- Message count in the actual forwarded request body (post-LAO) added as `outbound_message_count`
- Shown in `localfirst inspect` for cloud_sent/trimmed entries

**`replay --detail` boundary sub-lines**
- Each event in detail view gets an indented boundary annotation:
  - `local_only`: shows commands run + "→ results forwarded to Anthropic"
  - `trimmed`: shows LAO-dropped file names
  - `cloud_sent`: shows files in context (first 3 names)
  - `blocked`: shows secret labels
  - `budget_exceeded`: shows spend vs. limit
- `budget_exceeded` now counted in run stats and shown in run header

### Tests

336 tests passing (42 new: 40 boundary-facts tests in section 17, 2 replay buildRunStats tests).

---

## [0.5.2] — 2026-05-07  Budget and Spend Control

### Added

**Session budget (`--budget N`)**
- `localfirst claude --budget 1.00` sets a per-session dollar cap
- Requests are blocked (HTTP 402) once the session cost meets or exceeds the budget limit
- Warning fires once at 80 % of budget (the threshold before the next request is blocked)
- Budget is shown in the startup banner, `localfirst status`, and the session exit summary
- Blocked budget attempts are logged with `event_type: budget_exceeded`, including `budget_limit` and `budget_spent` fields
- `localfirst ledger --summary` counts `budget_exceeded` events in a dedicated row
- `localfirst status` shows spend vs. limit with colour coding (green < 80 %, yellow 80–99 %, red ≥ 100 %)
- New pure-function module `src/budget.js` (`budgetStatus`, `fmtBudget`) — no I/O, fully testable

**Output distillation v2 (raw inspectability, from previous pass)**
- `distill()` now returns `rawContent` when distilled; raw output written to `~/.localfirst/distilled/YYYY-MM-DD.jsonl`
- Test-runner distillation: `npm test`, `jest`, `vitest`, `pytest`, `cargo test`, `go test` — smart extraction keeps failure lines + summary
- `localfirst distill` CLI: list today's distilled entries; `--entry N` shows raw content

### Tests

294 tests passing (31 new: 28 budget-enforcement tests in section 16, 3 distiller-export tests).

---

## [0.5.1] — 2026-05-07  Replay, Ledger, and Output Distillation

### Added

**Replay and run audit (`localfirst replay`)**
- Groups today's log entries by `run_id`, ordered by `iso` timestamp
- Summary view: one header per run — start/end time, duration, event counts by type (cloud/local/blocked/trimmed), cost, savings
- `--detail`: sequential per-event table with timestamp, event type, model, token counts, cost, and annotations (tools local, distilled, LAO, secrets detected, rule-blocked)
- `--run <id-prefix>`: full event detail for one specific run
- `--last N`: show last N runs (default: 3)

**Token ledger (`localfirst ledger`)**
- `event_type` on every log entry: `cloud_sent` | `local_only` | `blocked` | `trimmed`
- `run_id` (UUID) per `localfirst claude` session — ties all log entries to their originating run
- `iso` field (full ISO-8601) on every entry — session scope filter is now cross-midnight safe
- Blocked requests now written to main JSONL log in addition to the blocked audit file
- `--last N`, `--summary`, `--scope session|today`

**Output distillation**
- Clips high-volume tool output before it re-enters the model:
  - `grep` / `rg`: 50 lines
  - `find`, `ls`, `dir`, `Get-ChildItem`: 100 lines
  - `git log`: 100 lines
- Clipped output appends: `[LocalFirst: N total — showing first M. Full output not re-sent to model.]`
- `distill_tokens_saved` and `distill_cost_saved` tracked in log entries, `session.json`, ledger summary, dashboard, and session exit summary
- Dashboard tool rows show `✂ distilled` label with tooltip when output was clipped

### Tests
- 231 tests (up from 197): section 12 (ledger — 18 tests), section 13 (distiller — 35 tests), section 14 (replay — 28 tests)

---

## [0.5.0] — 2026-05-06  Week 2: Trust, Measurability, Clarity

### Added
- `localfirst doctor` — diagnostic command: checks Node ≥18, claude CLI, log dir writable, port 8081 available, Python (LAO), LAO scorer script, PowerShell profile (Windows)
- `--preset strict|balanced|off` — named policy presets replacing cryptic `--mode` flag
- Real savings tracking: `cache_savings` (Anthropic prompt-cache) and `lao_cost_saved` (context trimming) in session.json and per-request log entries
- Per-request cache savings inline in terminal: `· cache 8.5k (-$0.0024)`
- Session summary and `localfirst status` show itemized savings breakdown (cache + LAO)

### Fixed
- Dangerous flag `-D` (git force-delete branch) was not caught — classifier lowercased before Set lookup, missing the uppercase `-D` entry
- Session summary `Local:` line always showed 0% — was reading `local_tokens`/`cloud_tokens` which were removed in v0.4.1
- `localfirst status` referenced removed field names

### Tests
- 144 tests (up from 101): routing coverage (section 9), LAO helpers (section 10), policy preset mapping (section 11)

---

## [0.4.1] — 2026-05-06  Week 1: Trust Hardening

### Added
- `localfirst help` command with full usage text
- `--block-secrets` shorthand flag (alias for `--preset strict`)
- Startup banner: version, mode label, log file path
- `LOG_SCHEMA_VERSION = 1` constant — frozen log entry structure, every entry includes `v: 1`
- `↩ fallback: <reason>` terminal line when interception falls back to cloud
- `fallbackReason` field in non-intercepted interceptor return value

### Fixed
- **C1 (Windows spawn)**: `spawn('claude')` now uses `shell: true` on win32 — without this, `claude.cmd` silently failed to launch
- **C2 (Windows paths)**: `isNativeHandleable()` used `SHELL_META` (includes `\`) which blocked every Windows absolute path. Split into `SHELL_COMPOSITION` (no backslash) for the native handler check
- **C3 (Cost overclaiming)**: tool_use round (Anthropic call #1) tokens now included in displayed cost; "saved $X" display removed — those tokens are charged, not saved
- **H1 (git config write risk)**: `git config` was in `git_safe_subcommands` — it's a write command. Removed
- **H2 (env/printenv bypass)**: `env` and `printenv` were in `always_local` — they expose API keys through the interceptor. Removed
- Secret `token` pattern narrowed: requires `access|bearer|auth` prefix (bare `TOKEN=` no longer fires)
- `register` command now writes canonical `localfirst claude @args` entrypoint; auto-upgrades legacy `--intercept` form

### Tests
- 101 tests (up from 83): trust fixes C1/C2/C3/H1/H2 regressions, Windows path coverage, git subcommand coverage

---

## [0.3.0] — Initial release

- HTTP proxy on port 8081 between Claude Code and api.anthropic.com
- Native JS file-read handlers: `cat`, `head`, `tail`, `Get-Content`, `type`, `ls`, `dir`, `Get-ChildItem`, `find -name`, `test -f`, `Test-Path`
- Classifier with git subcommand awareness (safe: `log`, `status`, `diff`, ...; unsafe: `push`, `commit`, ...)
- Secret scanning: 8 pattern types with line-number reporting and redacted snippets
- LAO context optimizer: trims low-relevance file tool_results from oversized contexts (Python 3 required)
- Prompt cache injection: `cache_control: ephemeral` on system prompt and last large user message
- Per-request file token breakdown (Level 1), secret details (Level 2), tool runs (Level 3)
- Session tracking: requests, tokens, cost, intercepted count
- Live web dashboard on port 3001 (`--dashboard` flag)
- Local LLM routing to Ollama for simple queries (`LOCALFIRST_MODEL`, `OLLAMA_HOST`)
