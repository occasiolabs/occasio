# Changelog

## [0.12.1] — 2026-06-24

### The proof path is one artifact, one command, strict-fail when evidence is missing

The public way to verify an Occasio run is now a single portable file,
`run.occasio.json`, checked by one command. The older multi-file flow
(`attestation.json` + `.sigstore.json` + an external chain) is retired as the
public path and kept only as documented legacy. The same single file is now
re-verifiable in a second language, so "independently verifiable" finally holds
for the format that actually ships. See [`docs/VERIFY.md`](docs/VERIFY.md).

### Added
- **Strict verification (fail-closed).** `occasio verify --strict`, plus the
  granular `--require-signature` / `--require-policy-binding` /
  `--require-git-state`. The default stays lenient (fast local check); strict is
  the CI path, where the three previously soft checks (signature, policy binding,
  git state) become hard failures instead of being skipped.
- **Independent Python verifier for the bundle.** `docs/verify_bundle.py` mirrors
  all six checks of the Node verifier (`src/bundle/verify.js`), including the
  strict requirements, reusing the already cross-language-pinned building blocks
  (`audit_walker._v8_json` for manifest/row hashes, `canonicalize` for predicate
  and git_state). `test-bundle-xlang.js` asserts Node and Python agree on the same
  `run.occasio.json`: an honest bundle passes both, and each single-point tamper
  (chain / policy / git / manifest) fails at the same check in both.

### Changed
- **Cutover to the single-file evidence bundle.** The GitHub Action now produces
  `occasio bundle --sign`, self-verifies it with `occasio verify --strict`, and
  uploads a single `run.occasio.json` evidence artifact. `occasio attest verify`
  is deprecated and points to `occasio verify`. Docs (`VERIFY.md`,
  `reference-pipeline.md`, `launch/ci-snippet.md`, `python-verifier.md`, the
  Action README) re-pointed to the one-file, one-command, six-checks flow.

### Fixed
- **Preflight test time bomb.** `test-interceptor.js` log fixtures derive their
  date from `now` instead of a hard-coded `2026-05-09`, which would have started
  failing 30 days out.

## [0.12.0] — 2026-06-05

### Identity gate — an agent may *request* an identity, not assume one

Built for the incident where an agent asked only for a deploy command reaches for
the server's `env` / `ssh`es into it on its own. A new policy posture denies the
commands an agent uses to *exfiltrate* an identity and gates the commands it uses
to *borrow* one (ssh / cloud / root) behind an explicit, single-use, human-approved
handshake — every decision recorded to the tamper-evident chain. Additive: existing
policies are unaffected; the `strict` template now carries the gate. See
[`docs/identity-gate.md`](docs/identity-gate.md).

### Added
- **Identity gate.** `deny_commands` (env/secret dumps, secret-name greps) and
  `identity_approval` (`ssh`/`scp`/`paramiko`, `az`/azure-HTTP/IMDS,
  `sudo`/`systemctl`/`pkexec`/`doas`/`su`) policy keys. File/credential protection
  is **path-based** (`deny_paths` globs `**/.env`, `**/environ`, `**/id_rsa`) so it
  holds for the Read/Glob/Grep tools *and* any shell verb, with a verb-agnostic
  backstop. Redaction is the best-effort value floor under it.
- **The approval handshake (human-vs-agent).** A borrow is a `pending` BLOCK; a
  human authorizes out-of-band with `occasio approvals approve <id> --once` → a
  single-use, TTL-capped (300s/3600s), **HMAC-signed** token bound to the exact
  `command_hash` → the agent's re-attempt passes through once and is consumed. The
  asymmetry is **enforced**: an agent shell command that mutates the control plane
  (`approvals approve|deny`, `identity set`) is hard-BLOCKed, so the agent cannot
  self-approve. Audit lifecycle `identity_borrow_request/approved/consumed/denied`.
- **PreToolUse hook — a second enforcement point.** `occasio hook` gates shell
  tool calls *inside* Claude Code for execution that does not flow through the
  proxy; fail-closed, and a no-op when the proxy is verified active. Install with
  `occasio hook --install`. Verified end-to-end against real Claude Code.
- **New commands:** `occasio identity set|show`, `occasio approvals
  list|show|approve|deny`, `occasio gate "<cmd>" [--enforce]`, `occasio hook`.
- **`occasio init`** now works as the 60-second-start alias for `occasio policy
  init`, and **`--template strict` installs the identity gate** (was the old
  secret-only strict; `strict-identity-gate` stays a back-compat alias).
- **Cross-language proof for the new rows:** `identity_borrow_*` and
  `control_plane_blocked` events verify under both the Node verifier and the
  Python walker.

### Fixed
- **Cross-language audit verification.** The independent Python walker
  (`docs/audit_walker.py`) reproduces V8's `Number::toString` instead of
  `json.dumps`, which diverged for small floats (request-row sub-`$0.0001` costs:
  V8 `0.00003` vs `3e-05`) and falsely rejected real chains. New
  `test-audit-xlang.js` pins Node≡Python over an adversarial number/string battery.
- **`occasio hook --install` matcher** is now `"Bash"` — a raw `"Bash|PowerShell"`
  is not a valid match for the `Bash` tool, so the hook silently never fired.

### Security
- Threat model stated precisely (`docs/identity-gate.md`): the control-plane guard
  is a command *pattern* (a renamed binary or programmatic call evades it);
  single-use is enforced by store integrity, not the HMAC (`uses` is unsigned). The
  boundary for both is OS-level store isolation — the stated, deferred hardening
  path. `npm audit`: 0 vulnerabilities.

## [0.11.0] — 2026-06-01

### Evidence, policy governance, and explainability

This release turns the audit chain into something you can hand to a third party
and check in one command, and gives the policy layer the governance + preview
surfaces it was missing. Everything is additive and backward-compatible: two new
chain row kinds verify under the existing JSON and Python walkers via the
unknown-kind passthrough, and the two new behaviours are opt-in / default-off.

### Added
- **Git-state attestation.** Runs record `git_state` rows (run start/end: HEAD,
  branch, dirty, changed/untracked files, diff hash) into the tamper-evident
  chain. `occasio attest` lifts them into `subject.git_state`, and `attest verify`
  cross-checks the claim against the chain. Capture is best-effort — a non-git
  directory or missing git binary records `is_repo:false` and never aborts a run.
- **Portable evidence bundle + one-command verify.** `occasio bundle --run <id>
  --out run.occasio.json` packs the attestation, the run's chain slice, a
  policy.yml snapshot, an optional Sigstore bundle, and a SHA-256 manifest into
  one self-contained file. New top-level `occasio verify <file>` runs six offline
  checks (schema, manifest, chain-slice integrity, policy binding, git-state vs
  chain, signature) and exits non-zero on tamper — a drop-in CI gate. Verifies
  against embedded data only; never reads the producer's absolute chain path.
  Bundles embed absolute producer paths (internal-audit artifact — review before
  public sharing). See [`docs/VERIFY.md`](docs/VERIFY.md).
- **Per-round volume limits.** Opt-in `limits:` block in `policy.yml`
  (`max_tool_calls_per_round` / `max_bash_calls_per_round` /
  `max_bytes_to_model_per_round`), enforced in the Claude-Code round loop before
  any cloud call. On violation: a synthetic "run halted" turn + a tamper-evident
  `limit_exceeded` chain row. Absent ⇒ unenforced (existing policies unaffected).
- **Richer explainable secret scanning + `occasio scan`.** New prefix / JWT /
  `.env` / Shannon-entropy detectors with an allowlist (UUID, pure-hex, fixtures)
  and hash-only redaction ledger. `occasio scan --file|--stdin` prints
  explainable findings (detector · confidence · reason · location, value masked),
  exit 1 on findings. Live use is opt-in via `entropy_secret_detection: true`
  (**default off** — the pattern scanner remains the default). See
  [`docs/SCAN.md`](docs/SCAN.md).
- **Forward preflight simulator.** `occasio preflight simulate
  --read/--grep/--glob/--bash/--ps/--from/--mined [--strict]` predicts allow/block
  for candidate actions through the same policy engine the runtime uses, before
  the agent runs; `--strict` exits 1 if any action would block. The existing
  backward-looking miner (`occasio preflight`) is unchanged. See
  [`docs/PREFLIGHT.md`](docs/PREFLIGHT.md).
- **Signed policy lock + diff.** `occasio policy lock [--sign]` writes
  `policy.lock.json` (raw-byte `policy_hash` + machine-independent summary,
  optional Sigstore signature with a dedicated `…policy-lock+json` payload type).
  `occasio policy diff` shows semantic drift from the lock (exit 1 on drift);
  `policy lock --verify --against` checks signature + payload + hash. See
  [`docs/POLICY.md`](docs/POLICY.md).
- **`occasio explain` → matched rule + how to unblock.** A BLOCK now resolves
  back to the concrete policy rule (e.g. `deny_paths[0]: ~/.ssh`, with the
  `policy.yml` line) and suggested next actions; `limit_exceeded` explains the
  cap (name/max/actual). Read-only re-derivation against the current policy,
  flagged best-effort when the policy hash changed since the decision.

### Added — chain row kinds
- `git_state` and `limit_exceeded` rows (kinds 4 and 5). Both verify unchanged
  under `occasio audit verify` and the independent Python walker
  (`docs/audit_walker.py`) via the schema-agnostic unknown-kind passthrough.

### Docs
- New: [`docs/POLICY.md`](docs/POLICY.md), [`docs/SCAN.md`](docs/SCAN.md),
  [`docs/PREFLIGHT.md`](docs/PREFLIGHT.md). Updated: `docs/AUDIT.md` (new row
  kinds), `docs/VERIFY.md` (one-file bundle). `scripts/demo-release.js`
  (`npm run demo:release`) drives the full evidence/policy/scanner flow and
  asserts the tamper-fails beat.

### Verification
- `npm test` green. New per-feature suites: git-state 37, bundle 31, limits 35,
  policy-lock 24, explain 27, detectors 30, preflight-simulate 22 assertions.
  CLI smokes cover honest + tamper paths (bundle verify exit≠0 on tamper, policy
  drift exit 1, scan exit 1 with no plaintext, preflight `--strict` exit 1).
  Zero new runtime dependencies.

## [0.10.0] — 2026-05-28

### Audit chain — single source of truth for user-visible counters

Before this release, surfaces that show session counters (`status`, `ledger`,
`replay`, `report`) read from `~/.occasio/session.json` and
`~/.occasio/logs/YYYY-MM-DD.jsonl` — plain JSON files with no integrity
protection. The hash-chained audit log at `~/.occasio/pipeline-events.jsonl`
ran beside them but was not consulted by these commands. Result: the
"tamper-evident" claim held only for `audit verify`, not for any number a
user actually saw in the CLI. This release routes all counter-bearing
surfaces through the chain.

### Added
- New audit-chain event kind `request` (one row per cloud-bound or
  intercepted request) carrying cost, tokens, cache savings, and
  per-request tool counts. Lockfile-protected append, stable canonical
  field order, additively safe for existing chains (older verifiers
  accept the new kind via the standard unknown-kind passthrough).
  Independent Python walker (`docs/audit_walker.py`) is schema-agnostic
  and verifies the new kind without changes.
- `src/models/events.js` — single read-only façade over the chain. All
  inspect commands route through it: `loadEvents({kind, runId, today,
  since, until, cwd})`, plus `groupByRun`, `summarize`, `buildRunStats`,
  `buildToolStats`. 60 unit tests in `test-events.js`.
- `occasio ledger --scope all` — new option spanning every chain
  `request` row (previously only `session` and `today` were supported).
- `test-drift-guard.js` — fixture-based cross-surface invariant test
  that asserts `status` / `ledger --summary` / `replay` show identical
  counters for the same chain. Anti-test verified: artificially
  inflating `status`'s counts makes the guard fail with a clear pointer
  at the bypassed read path. Registered in `npm test`.

### Changed
- `status`, `ledger`, `replay`, `report` now derive every counter, cost,
  and token total from the hash-chained audit log. `session.json` is
  still read transitionally for config-only fields (mode, start, budget,
  log_file) — those move out in a follow-up cleanup.
- `replay --attribute` still reads `logs/*.jsonl` directly: this view
  depends on per-tool `kept_bytes` data that is not yet attested in the
  chain. The header line now carries a `(legacy)` marker. A future
  refactor that attests tool-detail in the chain will eliminate this
  legacy path.
- `boundary` and `inspect` intentionally **not** migrated. They surface
  per-request detail (`tools[]`, `lao_dropped[]`, `file_tokens[]`,
  `secrets[]`) that lives only in `logs/*.jsonl` and is not part of the
  drift problem these commands compete on. They remain legacy
  detail-views over `logs/*` until tool-level data is also attested.

### Fixed
- **Security: chain race on default-configured auditor.** `createAuditor`
  default changed from `{ lock: false }` to `{ lock: true }`. Production
  spawns two concurrent writers against the default chain file (HTTP
  proxy in `bin/occasio.js` + MCP server in `bin/occasio-mcp.js`), and
  the prior `lock: false` default produced silent `prev_hash` divergence
  under contention — silently breaking the integrity claim on real
  workloads. `test-audit-lock-worker.js` now uses the production default
  (no explicit `{ lock: true }`) so the test fails if anyone flips the
  default back.
- **Privacy: cross-session prompt leak in `occasio recap`.** Previously
  rendered the most-recent Claude-Code session-file user/assistant
  exchange into the recap of any historical run, regardless of how old
  that run was. The conversation block is now removed entirely — recap
  shows only what the audit chain attests (tools, decisions, costs).
  Help text documents the change.
- Stderr warning from a failed chain write now strips ANSI escapes and
  control characters from `error.message` before printing, so a hostile
  or malformed `Error` cannot inject terminal sequences into the user's
  console.

### Added — defensive tests
- `test-audit-chain.js #20` pins the canonical key order and recomputed
  hash for a deterministic `kind:"request"` row. Any reorder of the row
  literal in `src/audit/jsonl-auditor.js` is now caught — old chains
  would otherwise stop verifying against new code without notice.

### Phase 5: `session.json` reduced to a run pointer

Closes the truth-source unification. `session.json` no longer carries
any per-request counters; it is a pointer to the active run holding
`run_id`, `start`, `cwd`, `mode`, `budget`, `log_file` (plus `model`
once observed). A fresh-session pointer is ~227 bytes (six fields),
down from ~615 bytes (22 fields). The proxy exit summary and the
`occasio doctor` "Last session" line, the last two readers of the
legacy counters, now also derive from the chain via `events.js`.

### Anti-SaaS proof surface: `occasio doctor --paranoid`

A new diagnostic that scans the installed source for outbound network
primitives and classifies every callsite (`proxy-bound`, `llm-endpoint`,
`signing-infra`, `local-loopback`, `hardcoded-host`, `unclassified`).
Also runs a telemetry self-audit against a curated catalogue of 40
known observability SDKs, checks `package.json` deps for any of those
packages, and embeds the audit-chain integrity status. Output is
screenshot-grade ANSI; `--json` produces a structured form. Exit code
is non-zero if any critical finding appears.

The LLM-endpoint allowlist is intentionally narrow: only hosts
referenced as string literals in the current `src/` tree (today:
`api.anthropic.com`). A future provider adapter adds its host together
with the adapter code, in the same PR, with review. This keeps the
list honest as architectural commitment rather than a roster of
endorsed providers.

`test-paranoid.js` block 5 asserts zero critical findings against the
real source tree, so a future contribution that introduces a hardcoded
outbound URL or a telemetry SDK fails in CI. The Anti-SaaS claim is
machine-checked. Signing the paranoid report (`--sign`) ships in v0.10.1.

### Unified snapshot for `occasio` with no arguments

Running `occasio` with no args used to silently launch the Claude
proxy. It now prints a unified live snapshot (active-run pointer,
chain-sourced accounting, tool coverage, last five chain events,
in-window anomalies, next-command hints) and exits. The proxy still
launches via the explicit `occasio claude` form, and the `claude`
shell alias registered by `occasio register` continues to forward
through it unchanged.

### Anti-SaaS positioning docs

- `docs/WHY-LOCAL.md`: data-flow diagram, "what does not happen"
  inventory, and concrete verification path via `doctor --paranoid`.
- `docs/COMPARE.md`: deployment-model comparison across LangSmith,
  Helicone, Langfuse Cloud and self-host, Honeyhive, Arize Phoenix
  self-host, and Occasio. Descriptive table, not a feature shootout.
- `docs/SUSTAINABILITY.md`: Apache 2.0 commitment, three revenue
  streams (consulting, curated policy bundles, enterprise support),
  explicit non-streams (no telemetry, no managed cloud, no data
  monetisation), and the architectural reason the model holds together.
- README headline now leads with the local-first identity and links
  to all three. `ARCHITECTURE.md` and `AUDIT.md` synced to the new
  truth-source reality (three row kinds, `request` row field order,
  truth-source-unification subsection).

### Fixed (continued)
- **Doctor ANSI color reset bleed**: `occasio policy doctor` now wraps
  every coloured emission with an explicit `\x1b[0m` reset via a small
  `safe()` helper. The internal reset inside `col.X()` lands mid-line
  and is sufficient for VT100, but Windows Terminal carries colour
  state across line breaks without a terminal-side reset; the previous
  suggestion's colour bled into the next. `test-doctor-ansi.js` is a
  regression guard.

### Supply-chain triangle positioning

- `docs/SUPPLY-CHAIN-TRIANGLE.md`: one-pager naming the three
  complementary specs (SLSA Provenance, CycloneDX AI-BOM, Occasio
  agent-attestation/v1) and pointing at each one's canonical verifier.
  README now links to it after the "Verify the local-first claim"
  section. Occasio is the runtime behavioural leg.
- `docs/VERIFY.md`: third-party verifier guide for an Occasio
  attestation bundle. Three paths (CLI, Python walker, separate
  cosign + canonical verification), what each step proves, common
  failure modes.

### New surfaces

- **`occasio doctor --paranoid --sign`**: Sigstore-sign the paranoid
  report. Reuses the OIDC token acquisition pattern from
  `src/attest/sign.js` but signs the report directly (no in-toto
  wrapper). Writes `paranoid-report-<ts>.json` and
  `paranoid-report-<ts>.sigstore.json` to cwd, prints the Rekor URL.
  Requires GitHub Actions OIDC env or `--oidc-token <jwt>`. Custom
  DSSE payload type `application/vnd.occasio.paranoid-report+json`.
- **`occasio doctor --paranoid --watch <s>`**: install a same-process
  monkey-patch on `http.request`, `https.request`, `net.connect`,
  `net.createConnection`, and `dgram.createSocket` for `s` seconds.
  Every outbound attempt is observed with timestamp, host, port,
  transport, and aggregated by destination. Observation buffer capped
  at 10000 with a `dropped` surplus counter to bound memory.
- **`occasio explain <event_id|prefix>`**: locate a single chain row
  (full id or unique hex prefix) and render its action, reason,
  policy_source, the active policy_loaded snapshot at decision time
  (path, hash, version), normalised inputs, and chain pointers.
- **`occasio receipt`**: emit a small shareable summary (target
  1 to 2 KB) of one run. Carries run_id, accounting totals, tool
  stats, and chain commitment (first_hash + last_hash). Deliberately
  excludes tool inputs, cwd, prompts, response bodies, and any
  identifier beyond the run_id. With `--sign`, the receipt is
  Sigstore-signed. Documented caveat: signed receipts embed the
  OIDC identity claim (workflow URL for GitHub Actions); strip
  `signature.identity` before public redistribution if the audience
  is untrusted.
- **`occasio bom export`**: CycloneDX 1.6 ML-BOM emitter. Components
  include one machine-learning-model entry per observed model, one
  library entry per invoked tool, one data entry per accessed file
  path, and a service entry per LLM endpoint. The dependencies
  graph links the run to its parts. Pairs with `agent-attestation/v1`
  for the runtime composition + behaviour pair.
- **`occasio compliance export`**: bundle one run for auditor review.
  Writes five artefacts (chain.jsonl, receipt.json, bom.cyclonedx.json,
  framework-mapping.json, summary.md) into a single directory.
  Frameworks supported: `nist-ai-rmf`, `eu-ai-act`, `soc2`, `generic`.
  Framework mapping is intentionally a skeleton (clearly documented
  as such); full coverage ships as paid policy bundles per
  `docs/SUSTAINABILITY.md`.
- **`occasio live`**: terminal-second-window watcher on the active
  session. Re-renders on every chain append plus every 5 seconds for
  the timestamp tick. Shows active run, chain-sourced counters
  (cost, requests, tool stats), and the last 12 chain events with
  action colouring. Exits cleanly on Ctrl-C.

### Consistency layer

- All new commands accept `--help` / `-h` and print a uniform usage
  block (one-line description, usage line, flags list, example).
- Flag names normalised across commands: `--run <id>`, `--out <path>`,
  `--json`, `--sign`, `--oidc-token <jwt>`.
- New entries added to the README Commands table for `occasio`
  (no args), `doctor --paranoid`, `live`, `explain`, `receipt`,
  `bom export`, `compliance export`.

### Sharing / privacy notes documented in source

- `bom.cyclonedx.json` and `chain.jsonl` carry absolute file paths
  from the run. Intended for internal audit. The summary.md cover
  sheet in compliance bundles carries a prominent "Sharing note"
  block directing users to `receipt.json` as the path-free public
  sharing surface. Module-level note added to `src/bom/cyclonedx.js`.
- `signature.identity` in signed receipts can reveal the producer's
  GitHub workflow URL (and, for some OIDC providers, user email).
  Documented in `src/cli/receipt.js` module header with a
  redaction recipe.

### npm publish workflow

- `.github/workflows/publish.yml`: GitHub Release trigger publishes
  `@occasiolabs/occasio` to npm with `--provenance`. Requires
  `permissions: id-token: write`. The published tarball carries a
  Sigstore-signed attestation linking it to this exact workflow run
  and commit SHA. Closes the "reproducible verify" recipe printed
  by `occasio doctor --paranoid`.

### Tests

- `test-paranoid.js` block 6 covers `network-watch` shape.
- `test-new-commands.js` (50 assertions across five blocks): smoke
  coverage for explain, receipt, bom export, compliance export, and
  live render. Wired into `npm test`.

## [0.9.2] — 2026-05-25

### Added
- `occasio eyes --sanitize` and `occasio claude --eyes --sanitize` — display-time
  identity scrubber for the Eyes browser/TUI view, so screencasts and
  screenshots of real sessions can be shared without leaking the user's home
  path, OS username, git `user.email` / `user.name`, hostname, or
  identity-carrying env vars (`USER`, `USERNAME`, `LOGNAME`, `HOME`,
  `USERPROFILE`). All identifiers are discovered at runtime — no hardcoded
  personal strings live in the source, guaranteed by a self-leak meta-test in
  `test-eyes.js` that refuses to ship if any real-identity value appears in
  `src/eyes/sanitize.js`.
- Substitution is deterministic via HMAC-SHA256 with a per-session
  `crypto.randomBytes(16)` salt held in memory only; pseudonyms have shape
  `/home/user-XX`, `user-XX`, `user-XX@example.invalid`, `User XX`, `host-XX`.
  Home-path tails are normalized to forward slashes so Windows screenshots
  render cleanly (`/home/user-7c/Desktop/proj`).
- Server-side scrubbing on every `/api/*` endpoint plus an
  `X-Eyes-Sanitized: 1` response header and a `sanitized: true` flag in
  `/api/exchanges` so DevTools never sees raw identity. The browser UI shows
  a cyan dot and `(sanitized)` badge in the sidebar.
- Disk capture under `~/.occasio/eyes/` is *unchanged* — `--sanitize` is a
  display filter, not a recording mode. The same Eyes log can be replayed
  unsanitized.
- 23 new tests covering discovery, determinism, length-sorted substitution,
  Windows-path-tail normalization, payload deep-walk, and an HTTP-roundtrip
  test that asserts the `X-Eyes-Sanitized` header.

### Fixed
- `--eyes` startup hint now prints `occasio eyes` instead of the
  dev-only `node bin/occasio.js eyes`, so npm-installed users see a
  command that actually works for them.
- Two source files used a maintainer username as an illustrative
  path/comment (`README.md` sanitize section, `src/cli/conversation.js`
  cwd-encoding comment). Replaced with generic placeholders so the
  source does not itself leak identity. The maintainer's real name in
  the `NOTICE` file is legitimate copyright attribution and is unchanged.

### Documented limits (`occasio eyes --help` and README)
- `--sanitize` does **not** cover: project paths outside `$HOME` (e.g.
  `D:\Work\Acme\…`), git remote URLs in tool outputs (`org/repo` in
  `github.com:org/repo`), file contents (a name in a comment or commit
  message), the Claude Code TUI welcome banner (which prints before any
  HTTP traffic and bypasses Eyes entirely — crop manually), or timezone
  hints in timestamps.

## [0.9.1] — 2026-05-21

### Changed
- README restructure for a dev-first reading flow. New tagline and lead
  paragraph that open with what the local proxy does, instead of opening
  with the "cryptographically verifiable behavioral attestation" framing.
  Section order now goes Two-ways → Quickstart → Live visibility (eyes)
  → Commands → Four layers → Architecture → Verification → Why now, so
  the dev path (install → see → reference) runs before the depth and
  compliance sections.
- "Live visibility — for developers" gains an `occasio eyes --demo`
  screenshot at the top of the README (`docs/img/eyes-demo.png`) with a
  caption that calls out the synthetic demo data and the "(demo)" badge
  in the UI.

### Notes
- No source code, CLI behaviour, schema, or wire format changed in this
  release. README + CHANGELOG + one new image only.

## [0.9.0] — 2026-05-21

### Added
- `occasio eyes` — local browser UI on http://127.0.0.1:3002 that shows
  what Claude Code sends to and receives from Anthropic per HTTP exchange.
  Sidebar groups exchanges by user prompt; main pane has Request / Response /
  Tools / Diff / Headers / Raw / Session / Stats tabs. Capture is opt-in via
  `--eyes` on the proxy and writes to `~/.occasio/eyes/` with a
  content-addressed blob store for dedup. Live SSE updates, native scrollbar,
  native text selection + copy.
- `occasio claude --eyes` — opt-in proxy flag that captures, per HTTP
  exchange: the post-transform outbound body, a pre-transform snapshot (for
  diff view), sanitized request + response headers (auth / x-api-key /
  cookie / set-cookie masked), the inbound response (SSE-parsed), the
  LAO-dropped tool_result bodies in full, and the local tool outputs
  (Read / Glob / Grep / Bash bytes the interceptor handled).
- Session-cost view in the Eyes UI: aggregate token usage across all
  exchanges with attribution between Anthropic's own system prompt and
  your content (bytes-ratio apportionment). Shows actual vs uncached cost,
  cache hit-rate, fresh vs cached input tokens, system-prompt bytes shipped.
- Live "now sending" flash overlay, per-file aggregate sidebar ("which
  files have I sent to the cloud?"), session sparkline showing outbound
  size over time, byte-decomposition stacked bar (system / history / new
  this turn / tools-framing), inline "view original" buttons on redacted
  tool_results.
- API endpoints (all 127.0.0.1 only): `GET /api/exchanges`,
  `GET /api/exchanges/:seq`, `GET /api/content/:sha256`, `GET /api/files`,
  `GET /api/session-cost`, `GET /events` (SSE).

### Changed
- README gains a "Live visibility — for developers" section that positions
  Eyes as the developer-facing companion to the audit/compliance pillar.
  Includes a Dashboard-vs-Eyes comparison table to disambiguate the two
  browser UIs.

### Scope cut
- Eyes capture is off by default; `--eyes` must be passed explicitly.
  Default-off is intentional: full payload bytes (file contents,
  conversation history) land on disk, and we want opt-in consent before
  persisting them.
- Browser UI binds 127.0.0.1 only with no auth — convenient for local use,
  never exposed off-box. A multi-user deployment would need an auth layer.
- Content store ringbuffer: 20 most recent payloads kept, 2 MB per-blob cap.
  Older sessions don't leak forward (session-start wipes the dir).

## [0.8.6] — 2026-05-16

### Added
- `occasio demo audit` — hero demo for the auditor scenario. Synthesizes a
  12-row CI-run audit chain, builds an unsigned attestation predicate,
  answers the framed auditor question with row-level evidence (BLOCK hashes
  on the asked path), and re-verifies the artifact with the independent
  Python verifier (`docs/attest_verify.py`) to demonstrate cross-language
  agreement on the chain. Anonymized TEMP-path display so the demo is
  screen-recording safe (no leaked username).
- `occasio recap` — markdown session summary sized to paste into a new
  Claude prompt. Reads `pipeline-events.jsonl` (tool calls, decisions,
  files touched) and Claude Code's own per-project session JSONL
  (last user message + last assistant reply). Flags: `--last N`,
  `--run <id>`, `--format md|text|json`.
- `--recap` flag on `occasio claude` — opt-in previous-session banner
  printed at startup. Compact 4-line summary so the user (and the next
  agent via on-screen context) has a memory anchor before the next prompt.
  Default off to avoid surprising existing users.
- CI-gated end-to-end Sigstore round-trip (`test-attest-e2e.js`,
  `.github/workflows/attest-e2e.yml`). Runs only when
  `OCCASIO_E2E_SIGSTORE=1` inside a GitHub Actions job with
  `permissions: id-token: write`. Locally it prints a SKIP line.
- EDR synthetic baselines: `scripts/edr-synthetic.js` generates
  hash-chained pipeline-events.jsonl matching one of four profiles
  (low-activity, bursty, secret-heavy, denied-heavy).
  `docs/edr-calibration.md` gains a 4×4 false-positive matrix.
  `occasio anomalies --threshold-multiplier <n>` lets operators
  raise/lower the deny-rate and file-read-volume thresholds.
- `test-anomaly.js` asserts a zero-HIGH FP smoke on the low-activity
  profile and that the multiplier suppresses marginal alerts.

### Fixed
- Proxy port now defaults to OS auto-assignment instead of hard-coded 8081,
  so multiple `occasio claude` sessions can run in parallel without
  EADDRINUSE. Explicit overrides (`OCCASIO_PORT=N`, `--port N`) still pin
  a fixed port. `occasio doctor` skips the port probe when no explicit
  port is set. Note: `~/.occasio/session.json` is still a single shared
  file — parallel sessions co-exist port-wise but will overwrite each
  other's session totals; a follow-up will scope session state per run.

### Changed
- `src/cli/help.js` reorganised into five use-case namespaces (Setup,
  Run, Inspect, Audit, Detect) plus a 60-second start. Each command
  now carries a maturity tag (stable / beta / alpha).
- Test-attest mock bundle hardened to mirror the real sigstore-js v3
  bundle shape (certificate.rawBytes, tlogEntries.integratedTime,
  dsseEnvelope.signatures); a future refactor that depends on a
  fictional field will now fail loudly.

### Scope cut
- The E2E test signs against **prod** Sigstore Fulcio + Rekor (one
  public Rekor entry per CI run). The dedicated staging instance is
  intermittently available and changes shape between sigstore-js
  releases, which would make this gate flaky. Workflow runs only on
  main pushes and `workflow_dispatch` — never on PR pushes.

## [0.8.4] — 2026-05-15  Audit pillar hardening

Internal hardening of the audit chain; no API breaks.

### Added

- `loadPrevHash()` now tail-reads instead of walking the full file — O(1)
  startup on large logs.
- Crash recovery: a partial trailing line (interrupted append) is detected
  on load and surfaces a clear instruction to run `occasio audit repair`.
- `occasio audit repair --file <path> [--dry-run]` — truncates a
  crash-partial trailing line, writes a `.bak` before mutating.
- `audit_schema=1` field on new rows. Forward-compatible: the Python
  walker (`docs/audit_walker.py`) is field-agnostic and continues to
  verify the chain over rows with or without the field.
- Opt-in file locking for multi-process writers (`proper-lockfile`).
  Off by default; enable via env var when multiple agents share one log.
- ESLint scoped to `src/audit` and `src/attest` (`npm run lint`).
- Test suites: H1 (loadPrevHash tail-read), H2 (crash-recovery surface),
  H3 (attest policy-read loud-fail), H4 (locking semantics).
- `CONTRIBUTING.md` and `docs/ARCHITECTURE.md`.

## [0.8.1] — 2026-05-14  Behavioral attestation v1 + EDR + Computer-Use scaffold

Three new top-level capabilities, all building on the v0.8.0 audit chain
as the evidence layer. Two of them ship reference implementations of
emerging open standards (in-toto Attestation Framework, RFC 8785 JSON
Canonicalization); the third (Computer-Use governance) is the only
template for that surface that exists in any vendor's product today.

### Added — AI-Agent Behavioral Attestation v1

A signed, cryptographically verifiable predicate that commits to the
full audit-chain slice for one agent session: every tool call, every
block, every transform, every redacted secret, plus the active policy's
hash and rules digest. Signed via Sigstore keyless using GitHub Actions
OIDC — no key management.

- `occasio attest --run-id <uuid>` — build an attestation predicate
- `occasio attest --sign` — Sigstore-sign via GitHub OIDC (CI)
- `occasio attest verify <file>` — three-step independent verification

Two reference verifiers ship:

- Node: `occasio attest verify` (full pipeline + Sigstore)
- Python: `python docs/attest_verify.py` (stdlib + optional `sigstore-python`)

Cross-language byte-equivalence on the predicate canonicalization step
is asserted in the test suite under `xlang:` and `xlang-float:` cases.
Both `canonicalize` implementations explicitly reject non-integer numbers
so a future schema cannot silently introduce divergence.

Companion artifacts:

- `schemas/agent-attestation-v1.json` — authoritative JSON Schema
- `spec/agent-attestation/v1/README.md` — predicate type specification
- `integrations/attest-action/` — GitHub Action that signs, self-verifies,
  uploads as artifact, and posts a PR Check Run
- `integrations/attest-view/` — static drag-and-drop browser viewer
- `docs/python-verifier.md` — independent Python verifier doc

### Added — Anomaly detection layer (EDR)

Four detectors over a time window of the audit chain:

- `deny-rate` — BLOCK rate spike vs historical baseline
- `file-read-volume` — distinct-file-read burst (recon pattern)
- `unknown-tool-input` — previously-unseen `tool_inputs` key shape
- `secret-redact-rate` — redaction rate spike or first-time leak

`occasio anomalies` runs all four against the active chain with
human or `--json` output. Exit codes: 0 / 1 / 2 / 3 = no signal / low /
medium-or-high / detector error. Detector crashes are separated from
real alerts (`result.errors`) so compliance reviewers don't see
engineering bugs in their alert stream.

Thresholds calibrated against a real 3-day audit chain;
`scripts/calibrate-anomaly-detectors.js` re-runs the calibration
against any chain. `docs/edr-calibration.md` records the empirical
baseline and what was tuned vs the starter values.

### Added — Computer-Use policy engine + dry-run CLI

Policy + decision engine for Anthropic Computer Use tool surface
(`computer.screenshot`, `computer.type`, `computer.mouse_move`, `bash`,
etc.). Same governance vocabulary as the rest of Occasio:
`deny_keyboard_patterns`, `deny_command_patterns`, plus a built-in
always-on lethal-command blacklist (sudo, recursive root delete, mkfs,
fork-bomb). PCRE-style inline flag prefixes `(?i)`/`(?m)` translated to
JS RegExp flags so policy authors use familiar syntax.

`occasio computer-use --dry-run --from <jsonl>` applies a policy to
synthetic Computer-Use traffic and reports each decision. Live proxy
adapter wiring is deferred until at least one design partner is on it;
the dry-run CLI exists today.

### Added — Demo commands

Production CLIs that exercise full pipelines against synthetic data in
seconds, with no external dependencies:

- `occasio demo attest` — end-to-end attestation pipeline (30 s)
- `occasio demo anomalies` — EDR smoke test, all four detectors fire

### Added — Reference Pipeline + EDR walkthrough

- `docs/reference-pipeline.md` — copy-paste GitHub Actions workflow,
  end-to-end PR-to-signed-Check-Run-to-viewer walkthrough
- `docs/edr-demo.md` — reproducible defense-in-depth demo: real Claude
  Code attacking a denied path under your policy, all blocks held,
  EDR fires HIGH ×100–×1000 over baseline
- `examples/workflows/attest-on-pr.yml.example` — copy-paste workflow

### Changed

- `package.json` description and keywords repositioned around behavioral
  attestation (agent-attestation, sigstore, in-toto, eu-ai-act, edr).
  Discoverable on npm-search for the new buyer audience.
- `package.json` `files` array now includes `docs/` and `spec/`. The
  Python verifier (`docs/attest_verify.py`), audit walker, predicate
  spec, and the EDR / reference-pipeline walkthroughs all ship in the
  npm tarball — running `occasio attest verify` after `npm install`
  no longer requires cloning the GitHub repo for the reference
  materials.
- `package.json` `bin` adds `occasio-mcp` as a first-class command.
  MCP-server invocation no longer needs the full node_modules path in
  `mcp_config.json` — `occasio-mcp` is on `PATH` after global
  install.
- README rewritten to lead with the value promise instead of the
  interception technique. Four-layer architecture diagram, runnable
  demos above the fold, "Why now" section linking to EU AI Act / NIST
  AI RMF / SOC 2 AI controls.

### Fixed

- Cross-language float-divergence in `canonicalize` (JS / Python /
  browser). Was a footgun that would have shipped to the in-toto
  submission and silently broken predicate equivalence the moment
  anyone added a float field to the schema. Now hard-rejected on all
  three sides with matching error messages.
- Sigstore-claim precision in README, spec, and python-verifier doc.
  Old wording suggested the test suite cross-verified Sigstore; it
  does not — the test mocks signing. Real-OIDC round-trip is now
  self-verified by the reference Action in CI.
- Anomaly-detector severity inflation. Calibration against a real
  chain showed `unknown-tool-input` and `secret-redact-rate` produced
  too many MEDIUM-severity false positives on normal usage. Tuned:
  non-privileged-key novelty is now LOW; cold-start single-redactions
  are LOW (bursts of ≥5 stay MEDIUM); privileged-key novelty stays
  HIGH; deny-rate and file-read-volume defaults unchanged.

### Tests

2607 unit tests (up from 2372). Notable additions:

- `attest:` block — schema shape, sign round-trip with mocked Sigstore,
  tamper detection on predicate / chain / bundle
- `canonicalize:` block — RFC 8785 subset properties, key reorder
  round-trip, float rejection
- `xlang:` and `xlang-float:` blocks — Python verifier spawned from
  Node, agrees byte-for-byte
- `anomaly:` block — each detector cold-start + positive case +
  crash-to-errors-channel
- `attest-action:` blocks — input validators, post-check escapers,
  end-to-end XSS scenario for the Check Run summary

## [0.8.0] — 2026-05-11  Path-1 ↔ path-2 defense symmetry + Claude-in-Claude self-test stack

The first release where Occasio can validate its own governance claims
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
`occasio harness` against a real subordinate session:

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
audit row with `direction: 'outbound'` so `occasio report` and the
independent Python walker see both gates uniformly.

### Added — self-test infrastructure

**`occasio harness`.** End-to-end governance validation against a real
Claude Code subordinate. Spawns `occasio claude --print <prompt>` with
scratch policy + scratch audit chain in `os.tmpdir()`, never touches the
user's real `~/.occasio/`. Authenticates via Claude Code's bundled
auth — no `ANTHROPIC_API_KEY` required when the user is signed in via
Claude Pro. Nine v1 scenarios: `deny-read`, `deny-shell-bypass`,
`symlink-bypass`, `redact-secrets-live`, `context-budget-live`,
`encoded-output` (discovery), `plain-text-context` (discovery),
`tool-chain-read-write-read` (discovery), and `mcp-deny-read` (protocol-
level, $0 per run). Each scenario also runs an independent audit-chain
verifier so a defended-but-chain-broken outcome is correctly FAILed.

**`occasio redteam`.** Autonomous adversarial tester. A second LLM
(default Haiku 4.5) is given an exfiltration goal and a 4-tool surface
(`send_prompt`, `read_audit_log`, `read_subject_response`, `done`) to
probe the subordinate. Tester's verdict is recorded but NOT trusted —
an independent verifier walks the audit chain + transcript and emits the
true verdict. Tester-hallucinated-exploit cases ("said yes, found
nothing") are surfaced as their own signal. Hard caps: `--max-turns`,
`--tester-budget` (USD). Peer dep on `@anthropic-ai/sdk`, dynamic
require with install hint if missing.

**`occasio selftest`.** Eight in-process governance checks on a
scratch policy and scratch audit chain. Synthetic boundary events
(no LLM), runs in <1 s. Covers `read_file` deny, shell-bash deny,
shell-powershell deny, allow-path positive, secret BLOCK under strict
mode, redact-secrets TRANSFORM, audit-chain verify, chain shape sanity.

### Added — context-control / observability

**`occasio boundary`.** Per-request three-column view: tool output
**produced**, tool output that **re-entered** the model, tool output
**prevented** from re-entering and why (`distill_clip` / `redact_secrets` /
`context_budget` / `block`). Backed by new `bytes` / `kept_bytes` /
`prevention_reason` fields on every recorded tool call.

**`occasio baseline`.** Per-project behaviour baseline. `learn` mines
the last N days of logs scoped to the current cwd into
`~/.occasio/baseline/<cwd-hash>.json`; `compare` walks the most recent
session and surfaces anomalies: `sensitive_path` (HIGH — covers `~/.ssh`,
`~/.aws`, `*/credentials`, `*.env*`, `/etc/(shadow|passwd|sudoers)`,
even on cold start), `new_path` / `new_tool` (medium), `new_shell_verb`
(HIGH for `curl`/`wget`/`ssh`/`rm`/`sudo`, medium otherwise),
`volume_spike` (>1.5× p95).

**`occasio replay --attribute`.** Per-run token attribution. Answers
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
  `occasio harness`.
- `occasio --version` now prints `occasio v0.8.0`.

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

**`occasio boundary` (Feature 1).**
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
  `[Occasio: ~Nt cut by context_budget (max Mt). …]` so the reason
  is visible to the model and to `occasio boundary`.
- Validator (`policy validate`) errors on non-positive-integer values —
  silently dropping a budget rule is treated as a cost gap, not a warning.
- Hot-reload applies on the very next tool call (existing policy loader
  contract).

**`occasio baseline` (Feature 3).**
- Per-project-cwd behaviour baseline. `baseline learn` mines the last N days
  of logs scoped to the current project, persists a frequency profile to
  `~/.occasio/baseline/<cwd-hash>.json` (paths, tool categories, shell
  verbs, session size quantiles).
- `baseline compare` walks the most recent session against the baseline and
  surfaces anomalies: `sensitive_path` (HIGH, fires even on cold start;
  hardcoded list covers `~/.ssh`, `~/.aws`, `~/.gcloud`, `~/.azure`,
  `~/.gnupg`, `*/credentials`, `*/secrets`, `*.env*`, `/etc/shadow|passwd|
  sudoers`, `*/private/*`), `new_path` / `new_tool` (medium), `new_shell_
  verb` (HIGH for `curl`, `wget`, `ssh`, `rm`, `sudo`, `npm`, `pip`, …),
  `volume_spike` (>1.5× p95 baseline session size).
- Baselines are local-only, no export, no telemetry.

**`occasio replay --attribute` (Feature 4).**
- Per-run token attribution. Answers "who ate the context window?" without
  persisting request bodies. Three classes: **tool contributions** (Σ
  kept_bytes / 4, approximate, marked '~'), **cache reuse** (Σ cache_read_
  tokens, exact, Anthropic-reported), **residual** (Σ input_tokens − tool_
  kept_total — covers system prompt + user messages + cross-request tool_
  result carry-over). Plus a four-line "prevented from re-entering"
  breakdown derived from existing JSONL fields.
- Counterfactual line shows what the run would have cost without Occasio
  shaping.

### Added — self-verification

**`occasio selftest`.**
- Eight in-process governance checks on a scratch policy and scratch audit
  chain in `os.tmpdir()`. Never touches the user's `~/.occasio`. Covers
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
  daemon was present, produced confusing `qwen2.5:7b` entries in `occasio
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
  `~/.occasio/pipeline-events.jsonl` will break the SHA-256 chain. The
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

Versions **0.6.6 and earlier** of `@occasiolabs/occasio` were published
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
- `schemas/occasio-policy.schema.json` — JSON Schema draft 2020-12,
  covering every field the loader normalizes. The `$id` is
  `https://occasio.ai/schemas/occasio-policy.schema.json`. The schema
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
- `occasio policy init --template <name>` selects one. Default remains
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
- The repository URLs in `package.json` now point at
  `occasiolabs/occasio`.
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
- Both verifiers (Node `occasio audit verify`, Python
  `docs/audit_walker.py`) parity-checked on a mixed-kind chain that
  includes `policy_loaded` rows.

## [0.6.5] — 2026-05-10  One MCP Proof — Cross-Protocol Governance

A deliberately narrow release. v0.6.5 routes the existing Occasio MCP server
(`bin/occasio-mcp`) through the same canonical pipeline (`policy.evaluate
→ dispatcher.dispatch → auditor.record`) that already governs the Claude Code
adapter. The architectural claim being proved is small but load-bearing:
**the same `policy.yml` governs Claude Code's `Read` and an MCP client's
`read_file`, byte-for-byte unchanged**. Audit rows from MCP traffic now land
in `pipeline-events.jsonl` with `protocol: "mcp"` and `occasio report`
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
  verbatim audit row, both verifiers, and `occasio report` output.
- **MCP-side AuditWriteError handling.** The MCP server inherits the v0.6.4
  fail-fatal contract: an audit-write failure aborts the MCP server with
  `[occasio-mcp][audit-fatal]` on stderr.

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
  `occasio audit verify` → `Chain intact (33 rows verified)`,
  `python docs/audit_walker.py …` → `OK: 33 rows verified`.

## [0.6.4] — 2026-05-10  Hardening — Fail-Loud Audit, Supervisor Templates, Independent Walker

A small, deliberately featureless release. v0.6.4 raises the credibility floor
of the governance story without expanding what Occasio does. Three changes,
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
  writes the dropped row JSON to stderr with a `[occasio][audit-fatal]`
  marker (so a supervisor / log scraper can recover it forensically), closes
  the listening socket, and exits non-zero after a 250 ms grace period.
- **This is a behavior change.** Environments that had a latent
  audit-unwritability problem in v0.6.3 will now surface it as a proxy crash
  rather than silently lose rows. That is the correct behavior; pair the
  proxy with one of the supervisor templates below.

### Added (operational)

**Supervisor templates under `bin/supervisor/`.**
- `occasio.service` — systemd unit (user scope), `Restart=always`.
- `com.occasio.proxy.plist.template` — launchd template (user scope), with
  `{{OCCASIO_BIN}}` placeholder for the absolute binary path.
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
  hash chain over `pipeline-events.jsonl` without using any Occasio code.
- The doc specifies the row format, the canonical serialization rules, and
  the genesis sentinel precisely enough that any third-party verifier can
  reproduce Occasio's own `occasio audit verify`.
- **Parity gate.** v0.6.4 verifies that `audit_walker.py` and
  `occasio audit verify` agree byte-for-byte on the maintainer's 31-row
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

This release closes the loop between *policy* and *evidence*. Occasio now captures
the full input to every tool call in the tamper-evident audit log, enforces
deny / allow lists on filesystem paths, lets you declare custom regex patterns that
extend the secret scanner, and ships a one-command compliance report. Together these
turn Occasio from a routing layer into a governance layer that an enterprise
buyer can reason about.

### Added

**Tool input capture in the audit log (ARCH-27)**
- Every `pipeline-events.jsonl` entry now records the normalized tool input alongside
  the existing decision fields. Path-bearing tools (`read_file`, `find_files`, `grep`)
  capture the resolved absolute path; shell tools capture the command. The audit
  hash chain extends over the new field, so any post-hoc edit is detectable by
  `occasio audit`.
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
  reported by `occasio policy validate` rather than silently dropped.
- Use cases: internal JWT formats, ticket / case identifiers, project-specific
  tokens, locale-specific PII patterns.

**`occasio report` — one-command governance summary**
- Aggregates the recent audit log into a buyer-readable report: counts of LOCAL vs
  PASS vs BLOCK decisions, distinct deny reasons, secrets caught, paths denied,
  and the audit-chain integrity status. Designed to be paste-ready for a
  compliance review or pilot conversation.

**Starter policy now demonstrates the new fields**
- `occasio policy init` generates a starter file that includes commented-out
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
  `occasio report` structurally always reported `paths_blocked: 0`.
- The classifier now treats every dispatchable Decision (LOCAL / BLOCK /
  TRANSFORM) as handled by the local pipeline; only PASS and unregistered
  tool names fall through to the cloud. With this change, denied tool calls
  are dispatched through `pipeline.processToolEvent`, the dispatcher's BLOCK
  branch returns `{ blocked: true, response, reason }`, the auditor writes a
  `result_kind: "block"` row to `pipeline-events.jsonl`, and the agent sees
  the `(blocked by policy)` synthetic tool_result. `occasio report` now
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

This release ships the complete **policy system**: a single `~/.occasio/policy.yml`
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
  active (or both are implied by global + per-tool flags), Occasio automatically
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
- The `occasio status` command and exit banner now include a
  `Transforms: N tool results shaped` line when any transforms ran this session.
- `session.json` gains a `tools_transformed` counter; each log entry carries
  `tools_transformed` per-request.

**`occasio policy show` — inspect the active policy (ARCH-19)**
- Displays the full active policy: global flags and per-tool routing decisions,
  annotated as `(default)` or `← override`.
- Warns when a `tools:` block is present (it replaces all built-in defaults) and
  lists the tools that will now PASS to the cloud.
- Warns when a tool entry references an unknown transform name.
- `occasio policy show --diff` prints only values that differ from defaults —
  useful for quickly auditing what a policy file actually changes.

**`occasio policy validate` — lint before it silently misbehaves (ARCH-23)**
- Parses `~/.occasio/policy.yml` (or `--file <path>`) and reports every issue
  that would cause a silent failure at runtime.
- **Errors** (exit 1): unknown `action` value, `TRANSFORM` missing `transform` field,
  wrong type for a boolean flag, `tools:` not a mapping, tool entry not a mapping.
- **Warnings** (exit 0): unknown top-level key, unknown transform name, unknown
  classifier name (entry will silently PASS at runtime), unknown field in a tool entry.
- Output is structured: each issue is shown with its dotted key path and a plain-English
  explanation.

**`occasio policy init` — strong first-run experience (ARCH-24)**
- `occasio policy init` writes a commented starter `~/.occasio/policy.yml` with
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
occasio policy init              # create ~/.occasio/policy.yml
$EDITOR ~/.occasio/policy.yml    # edit
occasio policy validate          # catch errors before they bite
occasio policy show              # confirm what is actually active
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
- New command: `occasio audit [verify] [--file <path>]` — verifies the full chain; reports legacy rows (written before hash support), chain breaks, and individual hash mismatches
- Any modification to any field in any row is detected: a tampered row triggers an error on that row and a cascade error on all subsequent rows (prev_hash mismatch)
- New module: `src/audit/verifier.js` — `verifyFile()` returns `{ ok, total, legacy, chained, errors, firstHash, lastHash }`

**Multi-agent support (Stage 3 architecture)**
- Second agent live-validated: Cline routes through the same canonical pipeline as Claude Code without any changes to the policy engine, dispatcher, scanner, or audit layers
- Canonical tool-name registry (`src/core/tool-names.js`): pipeline interior speaks agent-agnostic names; adapters translate at the boundary
- Agent routing: `x-occasio-agent` HTTP header selects the adapter; SSE content fingerprinting is the fallback when the header is absent
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

- **`parseFileTokens` now works with modern Claude Code** — rewrote to use `tool_use` / `tool_result` pair correlation instead of the `--- path ---` delimiter format that Claude Code stopped emitting. File token breakdowns in `occasio inspect` now populate correctly.
- **`Saved:` metric now honest** — `occasio status` previously labelled Anthropic's own prompt-cache savings as "Saved by Occasio." Now split into `Cache: $X (Anthropic prompt cache)` (dim) and `Saved: $X (LAO / distill)` (green, only shown when non-zero). Same fix applied to the session exit summary and doctor session display.
- **`🛑` vs `⚠` in ledger and replay** — non-blocked requests that touched a secret now show `⚠` (warning) instead of `🛑` (blocked). `🛑` is reserved for `event_type: blocked` only.

### Tests

550 tests passing (63 new: 42 Glob tests in section 20, 57 Grep tests in section 21, 51 TodoWrite/TodoRead tests in section 23, 13 parseFileTokens tool_use/result-pair tests added to section 5 — existing delimiter tests retained).

---

## [0.5.3] — 2026-05-07  Cloud-Payload Visibility

### Added

**`occasio inspect` — per-request cloud-boundary manifest**
- `occasio inspect` shows the last request; `--last N`, `--entry N`, `--run <id>`, `--scope today`
- For each request type shows a structured boundary view:
  - `cloud_sent` / `trimmed`: files in context (names + estimated token counts), messages in request, cache stats, distilled tool results
  - `local_only`: commands executed locally with sizes and native/exec flag, note that results were forwarded to Anthropic, distilled outputs flagged
  - `blocked`: secrets detected with label + line numbers, rule-blocked files
  - `budget_exceeded`: limit and spend at time of block
- All labels distinguish exact values (provider-reported tokens) from estimates (Occasio file analyzer)

**`lao_dropped` now logged**
- Previously only printed to terminal; now persisted in every log entry as `lao_dropped: string[]`
- Visible in `occasio inspect` and `occasio replay --detail`

**`outbound_message_count` now logged**
- Message count in the actual forwarded request body (post-LAO) added as `outbound_message_count`
- Shown in `occasio inspect` for cloud_sent/trimmed entries

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
- `occasio claude --budget 1.00` sets a per-session dollar cap
- Requests are blocked (HTTP 402) once the session cost meets or exceeds the budget limit
- Warning fires once at 80 % of budget (the threshold before the next request is blocked)
- Budget is shown in the startup banner, `occasio status`, and the session exit summary
- Blocked budget attempts are logged with `event_type: budget_exceeded`, including `budget_limit` and `budget_spent` fields
- `occasio ledger --summary` counts `budget_exceeded` events in a dedicated row
- `occasio status` shows spend vs. limit with colour coding (green < 80 %, yellow 80–99 %, red ≥ 100 %)
- New pure-function module `src/budget.js` (`budgetStatus`, `fmtBudget`) — no I/O, fully testable

**Output distillation v2 (raw inspectability, from previous pass)**
- `distill()` now returns `rawContent` when distilled; raw output written to `~/.occasio/distilled/YYYY-MM-DD.jsonl`
- Test-runner distillation: `npm test`, `jest`, `vitest`, `pytest`, `cargo test`, `go test` — smart extraction keeps failure lines + summary
- `occasio distill` CLI: list today's distilled entries; `--entry N` shows raw content

### Tests

294 tests passing (31 new: 28 budget-enforcement tests in section 16, 3 distiller-export tests).

---

## [0.5.1] — 2026-05-07  Replay, Ledger, and Output Distillation

### Added

**Replay and run audit (`occasio replay`)**
- Groups today's log entries by `run_id`, ordered by `iso` timestamp
- Summary view: one header per run — start/end time, duration, event counts by type (cloud/local/blocked/trimmed), cost, savings
- `--detail`: sequential per-event table with timestamp, event type, model, token counts, cost, and annotations (tools local, distilled, LAO, secrets detected, rule-blocked)
- `--run <id-prefix>`: full event detail for one specific run
- `--last N`: show last N runs (default: 3)

**Token ledger (`occasio ledger`)**
- `event_type` on every log entry: `cloud_sent` | `local_only` | `blocked` | `trimmed`
- `run_id` (UUID) per `occasio claude` session — ties all log entries to their originating run
- `iso` field (full ISO-8601) on every entry — session scope filter is now cross-midnight safe
- Blocked requests now written to main JSONL log in addition to the blocked audit file
- `--last N`, `--summary`, `--scope session|today`

**Output distillation**
- Clips high-volume tool output before it re-enters the model:
  - `grep` / `rg`: 50 lines
  - `find`, `ls`, `dir`, `Get-ChildItem`: 100 lines
  - `git log`: 100 lines
- Clipped output appends: `[Occasio: N total — showing first M. Full output not re-sent to model.]`
- `distill_tokens_saved` and `distill_cost_saved` tracked in log entries, `session.json`, ledger summary, dashboard, and session exit summary
- Dashboard tool rows show `✂ distilled` label with tooltip when output was clipped

### Tests
- 231 tests (up from 197): section 12 (ledger — 18 tests), section 13 (distiller — 35 tests), section 14 (replay — 28 tests)

---

## [0.5.0] — 2026-05-06  Week 2: Trust, Measurability, Clarity

### Added
- `occasio doctor` — diagnostic command: checks Node ≥18, claude CLI, log dir writable, port 8081 available, Python (LAO), LAO scorer script, PowerShell profile (Windows)
- `--preset strict|balanced|off` — named policy presets replacing cryptic `--mode` flag
- Real savings tracking: `cache_savings` (Anthropic prompt-cache) and `lao_cost_saved` (context trimming) in session.json and per-request log entries
- Per-request cache savings inline in terminal: `· cache 8.5k (-$0.0024)`
- Session summary and `occasio status` show itemized savings breakdown (cache + LAO)

### Fixed
- Dangerous flag `-D` (git force-delete branch) was not caught — classifier lowercased before Set lookup, missing the uppercase `-D` entry
- Session summary `Local:` line always showed 0% — was reading `local_tokens`/`cloud_tokens` which were removed in v0.4.1
- `occasio status` referenced removed field names

### Tests
- 144 tests (up from 101): routing coverage (section 9), LAO helpers (section 10), policy preset mapping (section 11)

---

## [0.4.1] — 2026-05-06  Week 1: Trust Hardening

### Added
- `occasio help` command with full usage text
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
- `register` command now writes canonical `occasio claude @args` entrypoint; auto-upgrades legacy `--intercept` form

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
- Local LLM routing to Ollama for simple queries (`OCCASIO_MODEL`, `OLLAMA_HOST`)
