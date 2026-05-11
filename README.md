# LocalFirst

> Control what re-enters the model after every tool call.

When an AI agent runs a tool — reads a file, runs `grep`, executes a shell command — its output usually goes straight back into the model's next request. Eight hundred lines of `grep` results, a 50k-line log file, a tool result containing an API key: all of it re-enters the context window and is forwarded to the cloud. LocalFirst sits at that boundary on the developer's own machine and decides, per call, **what gets in**.

```powershell
npm install -g @localfirst-ai/localfirst
localfirst register   # one-time: alias 'claude' to go through LocalFirst
claude                # Claude Code, now with LocalFirst active
```

---

## What it does

**Per-tool decision before the result reaches the model.** Every tool call flows through a single decision: `LOCAL` (run in-process on the developer's machine — the call's content is not forwarded to the cloud), `PASS` (forward unchanged), `BLOCK` (return a synthetic refusal — the action never runs), `TRANSFORM` (run, then shape the output: redact secrets, clip long output to a summary). The decision is driven by one human-readable [`policy.yml`](policy-templates/dev-default.yml). Three starter templates ship: `dev-default`, `strict`, `finance`.

**Local execution where it makes sense.** `Read`, `Glob`, `Grep`, `TodoRead`/`TodoWrite`, and a curated set of read-only shell commands (`cat`, `head`, `tail`, `type`, `Get-Content`, `git status`, `git log --oneline -N`, `ls`/`dir`, `find -name`) are handled in-process. The file bytes never enter the outbound request, and the agent gets the result without a cloud round-trip. Routing is per-tool in the same policy file — flip a single line and a tool falls back to `PASS`.

**Shape and redact tool output before it re-enters the prompt.** `TRANSFORM` actions chain in security-first order: `redact-secrets` (strips API keys, JWTs, AWS credentials, custom `deny_patterns` regex) runs first; `distill-output` clips noisy tool output (`grep` to 50 lines, `find`/`ls`/`git log` to 100, test-runner output to fail-lines + summary) so the next request to the model carries the relevant subset and not the noise. Both transforms are recorded per row so the difference between what the tool produced and what entered the next request is auditable, not invisible.

**Same policy across protocols.** The Claude Code adapter (HTTP proxy on port 8081) and the MCP server (`bin/localfirst-mcp.js`) share one engine. A `deny_paths` rule produces byte-identical `BLOCK` rows for a Claude `Read` and an MCP `read_file` — the [v0.6.5 cross-protocol demo](docs/demos/mcp-block.md) captures both end to end.

**Audit chain as the evidence layer.** Every governed call appends one row to `~/.localfirst/pipeline-events.jsonl`, SHA-256-chained to the previous row from a fixed genesis sentinel. `localfirst audit verify` re-walks the chain; a 30-line standalone Python verifier at [`docs/AUDIT.md`](docs/AUDIT.md) does the same without LocalFirst's own code, so a buyer or auditor never has to trust the producer of the log. `localfirst report --days N` aggregates the chain into a buyer-readable summary; the SOC 2 Common-Criteria mapping at [`docs/compliance-mapping.md`](docs/compliance-mapping.md) is the same evidence, framed for compliance reviewers.

---

## Quickstart

Requires Node.js ≥ 18. Works on Windows, macOS, and Linux.

**Step 1 — Install**

```
npm install -g @localfirst-ai/localfirst
```

**Step 2 — Verify your setup**

```
localfirst doctor
```

Checks Node version, the `claude` CLI, port availability, Python (for optional context trimming), and your shell profile.

**Step 3 — Initialise a policy file (one-time)**

```
localfirst policy init
```

Writes `~/.localfirst/policy.yml` from the `dev-default` template. Use `--template strict` or `--template finance` for a tighter baseline. Inspect or lint it any time with `localfirst policy show` / `localfirst policy validate`.

**Step 4 — Register the `claude` alias (one-time)**

Windows (PowerShell):

```powershell
localfirst register
. $PROFILE    # or restart the terminal
```

macOS / Linux (bash or zsh):

```bash
localfirst register
source ~/.bashrc   # or ~/.zshrc, depending on your shell
```

After this, typing `claude` automatically routes through LocalFirst.

**Step 5 — Run Claude**

```
claude "read package.json and tell me the version"
```

You'll see a startup banner and per-call interception lines as LocalFirst evaluates each tool call against your policy, runs `LOCAL` calls in-process, and writes every governed call to the tamper-evident audit chain at `~/.localfirst/pipeline-events.jsonl`.

**Step 6 — Inspect the run**

```
localfirst status          # session totals
localfirst replay          # what happened in this run
localfirst ledger          # per-request log
localfirst report --days 1 # governance summary (LOCAL/BLOCK/TRANSFORM counts, chain integrity)
localfirst audit verify    # re-walk the hash chain end-to-end
```

---

## Commands

| Command | What it does |
|---|---|
| `localfirst claude [args]` | Start Claude Code with LocalFirst proxy active |
| `localfirst register` | Register `claude` shell alias (PowerShell profile on Windows, `.bashrc` / `.zshrc` on macOS/Linux) |
| `localfirst doctor` | Check Node, claude CLI, port, Python, shell profile |
| `localfirst status` | Session totals: requests, tokens, cost, what was intercepted |
| `localfirst inspect --last N` | Per-request boundary view: what was run locally, what was shaped, what reached the cloud |
| `localfirst ledger` | Per-request log (`--last N`, `--summary`, `--scope session\|today`) |
| `localfirst replay` | Run-level audit (`--detail`, `--run <id>`, `--last N`) |
| `localfirst dashboard` | Live browser dashboard at http://localhost:3001 |
| `localfirst clear` | Reset today's log and session |
| `localfirst clear --history` | Wipe all historical logs |
| `localfirst audit verify` | Re-walk the SHA-256 audit chain end to end |
| `localfirst report --days N` | Governance summary of the audit chain |
| `localfirst selftest` | Run 8 in-process governance self-checks on a scratch chain |
| `localfirst policy init` / `show` / `validate` | Authoring loop for `~/.localfirst/policy.yml` |

## Overrides

The durable control surface is `~/.localfirst/policy.yml`. Two presets stack on top of it as quick session-level overrides:

| Flag | Effect on top of `policy.yml` |
|---|---|
| `--preset strict` | Forces `block_secrets_in_tool_results` on for this session — any tool result containing a detected secret is blocked outright |
| `--preset off` | Disables interception entirely — pure passthrough, log only |
| `--budget <N>` | Hard cap: once session cost reaches $N, outbound requests return HTTP 402 |

Default behaviour without any flag is the policy file in effect (or `dev-default` semantics if no file exists).

---

## How it works

The control point is one decision per tool call: should the call's result be allowed to re-enter the model's next request — and if so, in what shape? Every other piece (`LOCAL`, `BLOCK`, `TRANSFORM`, audit row) is a consequence of that decision.

For Claude Code, LocalFirst binds a local HTTP proxy on port 8081 and sets `ANTHROPIC_BASE_URL` so the agent's traffic routes through it. For MCP clients, the same policy engine governs `bin/localfirst-mcp.js`. Both protocols share the same pipeline:

1. **Adapter parse.** The adapter for the calling protocol (`claude-code`, `cline`, or `mcp`) normalises the incoming tool call into a canonical event — `read_file`, `find_files`, `grep`, `shell_bash`, etc.
2. **Policy evaluation.** The engine consults `~/.localfirst/policy.yml` and returns one of four decisions per call:
   - `LOCAL` — run in-process on the developer's machine; the call's content is never sent to the cloud.
   - `PASS` — forward the call to the cloud unchanged.
   - `BLOCK` — return a synthetic `(blocked by policy)` refusal to the agent; the dangerous action never executes.
   - `TRANSFORM` — run locally, then apply a named transform (e.g. `redact-secrets`, `distill-output`, or both chained) before the result re-enters the model.
3. **Path and pattern enforcement.** `deny_paths` (e.g. `~/.ssh`, `~/.aws`) and `allow_paths` are checked on the symlink-resolved absolute path **before** routing, so deny rules cannot be bypassed by a permissive `tools:` block. `deny_patterns` extends the built-in secret scanner with custom regex (internal JWT shapes, ticket IDs, locale PII).
4. **Dispatch.** `LOCAL` and `TRANSFORM` calls run through the native handler set (file reads, glob, grep, todo, recognised read-only shell commands such as `git status` / `git log`). `BLOCK` returns the synthetic refusal. `PASS` is forwarded to the cloud.
5. **Audit.** Every governed call appends one row to `~/.localfirst/pipeline-events.jsonl`. Each row carries `prev_hash` and `hash` (SHA-256), chained from a fixed genesis sentinel. `localfirst audit verify` re-walks the chain; `docs/audit_walker.py` is a ~30-line independent Python verifier published for buyers who would rather not trust LocalFirst's own code.
6. **Hot reload.** Edits to `policy.yml` take effect on the very next tool call — no proxy restart. A `policy_loaded` audit row is written on every load whose file hash changes.

`localfirst report --days N` aggregates the chain into a buyer-readable summary: per-tool LOCAL / BLOCK / TRANSFORM counts, blocked paths, secrets caught, and the chain-integrity status over the period.

---

## Log format

All data is stored locally at `~/.localfirst/`:

```
~/.localfirst/
  logs/YYYY-MM-DD.jsonl        # per-request log (schema v2)
  session.json                 # running session totals + run_id
  blocked/YYYY-MM-DD-secrets.log  # blocked request audit log
```

Each JSONL entry includes:

| Field | Description |
|---|---|
| `event_type` | `cloud_sent` / `local_only` / `blocked` / `trimmed` |
| `run_id` | UUID for the `localfirst claude` session that produced this entry |
| `iso` | Full ISO-8601 timestamp |
| `model` | Model ID from the request |
| `input_tokens` / `output_tokens` | Provider-reported usage |
| `cache_read_tokens` / `cache_write_tokens` | Anthropic cache usage |
| `cost` | Computed cost in USD |
| `cache_savings` | Dollar savings from cache hits |
| `lao_cost_saved` | Dollar savings from LAO context trimming |
| `distill_cost_saved` | Dollar savings from output distillation |
| `tools_local_count` | Number of tool calls handled locally |
| `secrets` | Detected secrets (label, line number, redacted snippet) |

---

## Demos

- [Cross-protocol governance: same policy.yml governs Claude Code and MCP](docs/demos/mcp-block.md) — end-to-end capture of the same `deny_paths` rule producing identical `BLOCK` rows under both protocols, with both verifiers in agreement.

---

## Requirements

- **Node.js ≥ 18** — `node --version`
- **Claude Code** — `npm install -g @anthropic-ai/claude-code`
- **Python 3** (optional) — required for LAO context trimming; `localfirst doctor` will tell you if it's missing

---

## License

LocalFirst is open source under the [Apache License 2.0](LICENSE), including an explicit patent grant for safe enterprise use. Versions 0.6.6 and earlier were released under the MIT License and remain MIT in perpetuity for those releases.

Contributions are accepted under Apache-2.0; please sign off your commits per the [DCO](https://developercertificate.org/) (`git commit -s`).
