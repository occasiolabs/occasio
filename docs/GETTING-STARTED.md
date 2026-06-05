# Getting Started with Occasio (5 minutes)

**What you get:** your AI coding agent (Claude Code, Cline, …) keeps working as
usual — but it can't silently read your secrets or borrow your `ssh` / cloud / root
access. You approve those, and everything the agent did is in a tamper-evident log
you can verify offline.

Requires Node.js ≥ 18. Works on Windows, macOS, and Linux. No account, no cloud,
no telemetry — Occasio runs entirely on your machine.

---

## 1 · Install

```sh
npm install -g @occasiolabs/occasio
occasio doctor          # checks Node, the claude CLI, Python — fix anything red
```

## 2 · Turn on the identity gate

```sh
occasio init --template strict
```

Writes `~/.occasio/policy.yml` — the **strict** posture: deny secret / environment
reads, and gate `ssh` / `az` / `sudo` behind your approval. (Want a lighter start?
`occasio init` writes the `dev-default` policy instead.)

## 3 · Run your agent through Occasio

Zero setup — just prefix your normal command:

```sh
occasio claude "fix the failing test"
```

Everything the agent does now passes through the gate. To make it permanent so you
can type plain `claude`, run `occasio register` once (it adds a shell alias —
restart your shell afterwards).

## 4 · What happens when the agent reaches for something sensitive

It keeps working normally — Occasio only steps in at the dangerous moment:

- It reads `.env` or runs `printenv` → **blocked**. The secret never leaves your
  machine; the agent sees `[REDACTED]`.
- It tries `ssh deploy@prod` (or `az`, `sudo`) → **paused**, with:
  `Denied … requires human approval — occasio approvals approve apr_… --once`.

**You** decide, from your own terminal:

```sh
occasio identity set --id you            # one-time: who you are (for the audit trail)
occasio approvals approve apr_… --once   # authorize this one command, once
```

The agent's retry now goes through **once**, and is consumed. A different command,
or a second attempt, is blocked again. The agent **cannot approve itself** — that
is the whole human-vs-agent point.

## 5 · See it, and prove it

```sh
occasio eyes          # live browser view: what's leaving your machine, secrets redacted
occasio audit verify  # cryptographic proof of everything the agent did and was stopped from
```

The audit chain is independently verifiable — a bundled Python walker
(`docs/audit_walker.py`) re-checks it without trusting Occasio's own verifier.

## Optional · Guard sessions that don't go through the proxy

```sh
occasio hook --install   # a PreToolUse hook in Claude Code, as a second line of defense
```

This catches identity-borrow commands even when the agent isn't run through the
proxy. (See [`docs/hook-smoke-test.md`](hook-smoke-test.md) to verify it end-to-end.)

---

## Honest notes (so this is real, not marketing)

- **Approval is out-of-band on purpose.** *You* approve in your terminal; the agent
  cannot approve itself (the control plane is in its deny-zone, the token is
  HMAC-signed). That asymmetry *is* the human-vs-agent boundary.
- **It's a deterministic policy + verifiable audit, not a sandbox.** It stops the
  common, innocent mistakes (an agent "being helpful" and reaching for a secret or
  the server). A determined adversary using runtime tricks (encoded reads, a renamed
  binary) is a documented limit — the real boundary there is OS-level isolation. See
  [`docs/identity-gate.md`](identity-gate.md) for the full threat model.
- **`occasio register` edits your shell profile.** Restart the shell, or just use
  `occasio claude …` directly.

Every command above is verified against the published `@occasiolabs/occasio@0.12.0`.
