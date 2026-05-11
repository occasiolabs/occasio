# Demo 1: Local File Read Interception

**What it shows**: Your hardware handles file reads. No subprocess, no extra round-trip — the `⚡` icon is proof.

## Setup

```powershell
# Windows PowerShell
localfirst register        # one-time setup
# restart terminal
```

## Run

```powershell
claude "Read src/index.js and tell me what the VERSION constant is set to"
```

## Expected output

```
⚡ LocalFirst v0.6.1
  mode: intercept  (--preset strict to block secrets)  log: C:\Users\you\.localfirst\logs\2026-05-06.jsonl

10:30:14 ⚡ cat src/index.js                     ~1.4k tokens local

10:30:15 📦 1,012 in / 87 out  $0.0018 · sonnet-4-6

─── Session ────────────────────────────
  Requests:   1
  Tokens:     1.0k in · 0.1k out
  Cost:       $0.0018
  Local:      1 tool calls (1 requests intercepted)
────────────────────────────────────────
```

**What happened**:
1. Claude Code sent a request to Anthropic (without the file contents)
2. Anthropic returned `stop_reason: tool_use` asking for `cat src/index.js`
3. LocalFirst intercepted the SSE, ran `cat` natively (no subprocess), and sent the file contents to Anthropic directly in a follow-up call — bypassing the Claude Code subprocess loop
4. The file contents went to Anthropic in LocalFirst's follow-up call (not in Claude Code's original request) — the savings are in latency and tool-execution round-trip tokens, not in keeping files off Anthropic
5. The `⚡` icon confirms local execution; `📦` (vs `📤`) confirms interception occurred

## What to look for

- `⚡ local` prefix on tool lines = ran on your machine
- `~Xk tokens local` = size of output that stayed local
- `📦` icon on the summary line = at least one tool was intercepted
- Cost reflects only the Anthropic round-trips (no token inflation from file contents)

## Verify via logs

```powershell
$entry = Get-Content "$env:USERPROFILE\.localfirst\logs\$(Get-Date -Format yyyy-MM-dd).jsonl" |
         ConvertFrom-Json | Select-Object -Last 1
$entry.intercepted        # True
$entry.tools.Count        # 1
$entry.tools[0].cmd       # cat src/index.js
$entry.tools[0].native    # True  (no subprocess)
```
