# Occasio PreToolUse hook

A second enforcement point for the identity gate — **inside Claude Code**, for
execution that does **not** flow through the Occasio proxy (Claude Code pointed
straight at Anthropic, a different provider, or a session where the proxy alias
isn't active). The proxy is the primary enforcement point; this hook covers the
rest.

## What it does

On every `Bash` / `PowerShell` tool call, Claude Code runs `occasio hook`, which:

1. **No-ops if the proxy is verified active** — only when a per-session token the
   proxy placed in Claude Code's own environment matches the token in
   `~/.occasio/session.json`. The agent can set neither, so it cannot fake this.
2. **Otherwise enforces** by delegating to `occasio gate --enforce` — the *same*
   decision the proxy uses (identity borrows → human approval, `deny_commands`,
   the control-plane deny-zone). A blocked borrow tells the agent to have a human
   run `occasio approvals approve <id>`; an approved one-time token passes through
   once and is consumed.
3. **Fails closed.** A blocking decision exits `2` (Claude Code blocks the tool and
   shows the message). Any internal error also denies — never a silent
   pass-through (a non-blocking exit code would let the tool run).

## Install

```sh
occasio hook --install      # merges the entry below into ~/.claude/settings.json
occasio doctor              # shows "PreToolUse hook: installed"
```

Requires `occasio` on PATH (`occasio register` installs the alias). To install by
hand, merge [`settings.snippet.json`](./settings.snippet.json) into
`~/.claude/settings.json` (or a project `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|PowerShell", "hooks": [ { "type": "command", "command": "occasio hook" } ] }
    ]
  }
}
```

## Scope and limits

- **Shell tools only** for now (`Bash`/`PowerShell`). Path-tool parity
  (Read/Glob/Grep vs `deny_paths`) is a follow-up.
- The hook is a deterministic gate, not a sandbox. The same honest residuals as
  the proxy apply (runtime indirection, egress) — see
  [`docs/identity-gate.md`](../../docs/identity-gate.md).
- Verified against the Claude Code PreToolUse contract (stdin JSON `tool_name` /
  `tool_input.command`; exit `2` blocks with stderr shown to Claude). If the
  contract changes, re-verify before relying on it.
