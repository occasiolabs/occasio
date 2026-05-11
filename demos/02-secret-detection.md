# Demo 2: Secret Detection and Blocking

**What it shows**: LocalFirst scans every outbound request and (in strict mode) blocks it before anything reaches Anthropic.

## Setup

Create a file with a fake secret for testing:

```powershell
# Windows PowerShell — creates a test file with a fake (non-functional) token
"ACCESS_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | Set-Content test-secret.txt
```

## Run — warn mode (default)

```powershell
localfirst claude "Read test-secret.txt"
```

**Expected output**:
```
10:30:15 ⚡ cat test-secret.txt                  ~0.1k tokens local
10:30:15 ⚠️  github-pat (line 1)
10:30:15 📤 890 in / 45 out  $0.0009 · sonnet-4-6
```

The `⚠️` warning appears but the request proceeds. The file was read locally (⚡) so its contents never left your machine. The secret is in the *tool result* being sent back to Anthropic — the warning is accurate.

## Run — strict mode (blocking)

```powershell
localfirst claude --preset strict "What is in test-secret.txt?"
```

**Expected output**:
```
10:30:22 🛑 BLOCKED — nothing sent to Anthropic
  ⚠  github-pat  line 1
```

Claude Code receives HTTP 403 and will report an API error. Nothing was forwarded to Anthropic.

## Run — check the blocked log

```powershell
Get-Content "$env:USERPROFILE\.localfirst\blocked\$(Get-Date -Format yyyy-MM-dd)-secrets.log" |
  ConvertFrom-Json | Select-Object ts, model, secrets
```

**Expected**:
```
ts      : 10:30:22
model   : claude-sonnet-4-6
secrets : {@{label=github-pat; line=1; snippet=**************...}}
```

Snippets are redacted: all alphanumeric characters replaced with `*`.

## Cleanup

```powershell
Remove-Item test-secret.txt
```

## What to look for

| Indicator | Meaning |
|-----------|---------|
| `⚠️  label (line N)` | Secret detected, request proceeded (balanced mode) |
| `🛑 BLOCKED — nothing sent to Anthropic` | Request blocked (strict mode) |
| `📤` icon on summary line | Request went to Anthropic (possibly with secret warning) |
| `~/.localfirst/blocked/` | Audit log of every blocked request |

## Patterns detected

LocalFirst matches 8 high-confidence patterns. Short values and mid-word occurrences do not fire:
- `password=hunter2` → no match (too short, < 8 chars)
- `apiKeyValidator = "short"` → no match (< 16 chars after `=`)
- `MY_TOKEN_VALUE=...` → no match (bare TOKEN= without `access|bearer|auth` prefix)
- `ANTHROPIC_API_KEY=sk-ant-api03-...` → **match** (api-key pattern)
- `ACCESS_TOKEN=ghp_AAAA...` → **match** (github-pat pattern)
