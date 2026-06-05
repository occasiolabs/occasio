# Occasio — Identity Gate

**One rule:** an AI agent may *request* an identity, it may not silently *assume* one.

The identity gate classifies identity-bearing shell commands and tool calls and
either **denies** them, **gates them behind human approval**, or allows them —
recording every decision into the tamper-evident audit chain. It is the `strict`
policy posture (`occasio init --template strict`, or `occasio policy init
--template strict`) and composed from three independent mechanisms.

## What enforces what

| Mechanism | Threat | Tool-agnostic? | Enforced in |
|---|---|---|---|
| `deny_paths` (globs + prefixes) | Reading a sensitive **file** (`.env`, ssh keys, `/proc/<pid>/environ`) | **Yes** — Read/Glob/Grep tools *and* any shell command | always |
| `deny_commands` | Genuine **command behaviours** with no file path (`printenv`, `env`, `set`, `declare -p`, `export -p`, grep-for-secret-names) | shell only | always |
| `identity_approval` | **Borrowing** an identity (`ssh`/`scp`, `az`/azure-HTTP, `sudo`/`pkexec`/`doas`/`su`, `paramiko`) — blocked until a human authorizes (single-use, short TTL) | shell only | always |
| `redact_secrets_in_tool_results` + `deny_patterns` | A secret **value** reaching the model in tool output | **Yes** — value-based, command/tool/path-agnostic | always (**best-effort**) |
| `block_secrets_in_tool_results` | Hard-refuse a turn whose output carries a secret | output scan | **`block_secrets` mode only** |

### Why files are path-based, not command-based

An earlier version "blocked" `.env` reads only because a command regex happened
to match the substring `env` — and the typed **Read tool** walked straight
through. Sensitive **files** are therefore matched on the resolved **path**
(`deny_paths` globs like `**/.env`, `**/environ`, `**/id_rsa`), which holds for
*every* tool and command, including a verb-agnostic backstop that tests every
path-like token in a shell command. This is verified to hold with
`deny_commands` removed entirely (see `test-identity-gate.js`).

`deny_commands` is reserved for behaviours that genuinely have **no file path**:
`printenv` / `env` / `set` / `declare -p` / `export -p` dump the live process
environment; grep-for-secret-names is a discovery pattern.

## The approval handshake — *who is who*

An identity borrow is not a flat deny; it is a handshake that distinguishes the
**agent** (which may *request* an identity) from the **human** (who *authorizes*
it). The distinction is enforced, not guessed from the prompt:

1. The agent emits e.g. `ssh azureuser@host` → **BLOCK**, and a `pending` record
   is written to `~/.occasio/approvals.jsonl` with an id. The agent sees:
   `Denied … Run: occasio approvals approve apr_… --once`.
2. **You** authorize, from **your own terminal** (which is not proxied):
   `occasio approvals approve apr_… --once`. This mints a **single-use**,
   short-TTL (default 300s, cap 3600s), **HMAC-signed** token bound to the *exact*
   command (`command_hash`, incl. the remote part), stamped with your identity
   (`occasio identity set --id <you>`; OS-user fallback).
3. The agent re-attempts the same command → the token is found → it **passes
   through** (Claude Code runs it) and the token is **consumed** (single-use). A
   second attempt, or any *different* command, is blocked again.

The chain records the whole handshake: `identity_borrow_request` →
`identity_borrow_approved` → `identity_borrow_consumed`, so a reviewer reads
`actor=ai_agent · delegator=<you> · approval.approved_by=<you>` — "the agent ran
ssh, authorized by you via apr_…". Verifiable, not guessed.

**The asymmetry is enforced.** An `actor=ai_agent` shell command that tries to
mutate the control plane (`occasio approvals approve|deny`, `occasio identity
set`) is **hard-BLOCKed** (`control_plane_blocked`), and `deny_paths ~/.occasio/**`
denies the agent direct read/write of the store. The agent cannot self-approve;
your terminal, being un-proxied, can. *That* is the human-vs-agent boundary.

After approval the command runs **client-side** (pass-through), so the returning
`tool_result` re-enters via the next request and the **redaction floor still
applies** — approval to *execute* is not approval to *leak*.

## Coverage — honestly

A static gate inspects the command **as written**, before the shell expands,
substitutes, or executes it. Two classes are therefore **provably outside** what
any denylist can enforce. We mark them `coverage: uncovered` rather than pretend.

### Enforced (any mode)
- Reading `.env`, `.env.*`, ssh private keys (anywhere), `/proc/<pid>/environ`
  via the Read/Glob/Grep tools or via `cat`/`less`/`tail`/`awk`/`cp`/`grep`/any
  shell verb → **BLOCK (`deny_paths`)**.
- `printenv` / `env` / bare `set` / `declare -p` / `export -p` → **BLOCK
  (`deny_commands`)**. `set -e` and `export FOO=1` are *not* blocked.
- `ssh`/`scp`/`paramiko`/`fabric`, `az`/`management.azure.com`/IMDS
  `169.254.169.254`, `sudo`/`systemctl`/`pkexec`/`doas`/`su` → **BLOCK pending
  human approval (`identity_approval`)**.

### Best-effort backstop (any mode) — redaction
- A read that carries a secret into the output **without touching a denied
  path** — `grep -ri secret /home`, `python3 -c "open('.env')"`,
  `node -e "...readFileSync('.env')"`, `find / -name '.e*' -exec cat {} \;`.
  The secret **value** is **redacted** before it re-enters the model
  (`redact_secrets_in_tool_results`, on in the strict template), on both the
  tool-result path and the outbound auto-context path. Every redaction emits a
  `secret_redacted` audit event with **`coverage: best-effort`** and
  `severity: low`, so it is never confused with an enforced deny.

  Redaction **raises the floor, it is not the boundary.** It is a value
  *detector*, with two honest limits:
  - **Encoding defeats it.** It must recognise the value; `base64`/`xxd`/`rev`
    of a *known path* are still hard-blocked by `deny_paths` (the path token
    survives), but an encode *inside* a pathless read (see crown-jewel below) is
    invisible to the matcher.
  - **False positives corrupt silently.** Over-redaction masks a value the agent
    needed — so redaction always leaves a visible `[REDACTED:label]` marker (the
    agent sees *something* changed) and the audit event records it. A silent
    redaction would be worse than a block.

  `block_secrets_in_tool_results` (a hard turn-refusal) still only fires in
  `block_secrets` mode; redaction is the mode-independent floor under it.

## Threat Model / Known Limitations

A static gate inspects a command as written, before the shell or an interpreter
expands and executes it. The following threats are therefore **out of scope for
the gate by construction** — they are stated here so coverage is honest, not as a
how-to. Each names the layer responsible instead: the **approval gate** (an actor
that needs human approval to act cannot act unattended) and a future
**egress-control** layer. The answer to each is a *different layer*, not a longer
denylist.

- **Direct environment read with encoded output (highest-value target).** An
  actor with shell or interpreter access can read the live process environment
  through a syscall (an interpreter reading its environment map) and emit the
  value in an encoded form (base64, hex, compression). This defeats both static
  layers *by construction*: there is no file path for `deny_paths` / `**/environ`
  to match, no classifiable verb for the command gate, and an encoded value is
  not recognisable to the redaction matcher. Narrow in surface, maximal in
  consequence — it targets precisely a secret that lives only in the
  environment. **Out of scope for the static gate; this is the threat the
  egress-control layer addresses:** the encoded blob cannot be recognised on the
  way *in*, but it can be denied on the way *out*.
- **Runtime path indirection.** Shell glob expansion, shell variables, and
  command substitution resolve to a denied path only at execution time; the gate
  sees the unexpanded token. Mitigated in depth by redaction (the value still
  passes through the result) and, for action, by the approval gate.
- **Hardlinks and same-command symlinks.** `realpath` resolves a *pre-existing*
  symlink into a denied path (that case **is** caught). A hardlink is a second
  name for the same inode and resolves to itself; a symlink created and read in
  the same command does not exist when the gate runs. Both are statically
  unresolvable.
- **Exfiltration without reading into context.** A secret can be sent outward
  (network egress) without ever entering the model's context, so read-blocking
  and redaction cannot help. `identity_approval` gates traffic to *known* cloud
  control planes, but arbitrary egress is the egress layer's job.
- **Approval forgery via an obfuscated-interpreter write to `~/.occasio` (privilege
  escalation).** The control-plane guard + `deny_paths ~/.occasio/**` close the
  *literal* paths (the CLI verbs, `echo > approvals.jsonl`, the typed Read/Write
  tools), and HMAC-signed tokens make a hand-written `approvals.jsonl` entry fail
  verification. But an `node -e` / `python -c` that builds the path *and* reads the
  HMAC key at runtime is the **same runtime-indirection residual** as the gate —
  and here it forges an approval, so the consequence is privilege escalation. On a
  single-user box the agent runs with the user's full rights, so no purely-software
  gate is absolute. **The real boundary is OS-level store isolation** (a separate
  uid / OS keychain the agent's uid cannot read) — the stated hardening path.

## Implementation: single source of truth

To prevent a gate from drifting onto its own weaker classifier (this happened
once — globs were added to the tool-call gate but not the outbound gate), all
gates share two modules:

- **Path classification** — `src/policy/path-match.js` (`pathMatchesEntry`, glob
  + prefix). Used by the inbound tool-call gate (`src/policy/engine.js`), the
  outbound auto-context gate (`src/outbound-policy.js`), and `occasio explain`.
- **Secret detection / redaction** — `src/analyzer.js` (`scanSecrets`,
  `redactSecrets`). Both redaction streams (path-1 dispatcher TRANSFORM and
  path-2 outbound) call it with the *same* `deny_patterns`, carried on the
  policy decision. A cross-gate parity test pins this.

Two modules are intentionally **separate** (different purpose, not drift):
`src/eyes/sanitize.js` is a screencast identity scrubber (home/user/hostname)
that never touches the model stream, and `src/scanner/detectors.js` is the
richer opt-in entropy/JWT detector behind `occasio scan` and
`entropy_secret_detection`, additive to the canonical scanner.

## Audit

Every identity decision writes one enriched row to
`~/.occasio/pipeline-events.jsonl` with `event_type`, `actor`, `delegator`,
`identity_requested`, `enforcement_point: "proxy"`, and `coverage`. A `coverage`
of `enforced` means the command provably did not execute and never reached the
agent. The gate never records `enforced` for a path it did not actually
intercept. See [`AUDIT.md`](AUDIT.md#identity-gate-enrichment-v2).

## Roadmap

- **Approval store + re-attempt** — **shipped** (see *The approval handshake*).
- **OS-level store isolation**: the real fix for approval forgery via an
  obfuscated-interpreter write — run the agent under a uid / put the store behind
  a keychain the agent cannot read.
- **Broker / human-execute mode** (per-rule, for the most sensitive targets):
  Occasio executes the approved command itself instead of passing it through.
- **PreToolUse hook**: a second enforcement point (`occasio gate`) inside the
  agent for execution that does not flow through the proxy.
- **Egress control**: the real backstop for the "exfil without reading" class.
