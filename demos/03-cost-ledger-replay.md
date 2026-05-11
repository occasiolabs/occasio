# Demo 3: Cost Ledger and Run Replay

**What it shows**: After a Claude Code session, LocalFirst gives you a precise breakdown of what happened — what went to cloud, what stayed local, what was blocked, what was trimmed, and what it cost — organized by run.

## Setup

```powershell
localfirst register   # one-time
# restart terminal or: . $PROFILE
```

## Run a session

```powershell
claude "read src/index.js, then grep for TODO comments in src/"
```

Let Claude do a few tool calls. Exit with `/exit` or Ctrl+C.

## Inspect the run

### 1. Session summary (on exit)

When Claude exits, LocalFirst prints:

```
─── Session ─────────────────────────────
  Requests:   4
  Tokens:     12.4k in · 1.8k out
  Cost:       $0.0441
  Saved:      $0.0218 ($0.0190 cache + $0.0028 distill)
  Local:      6 tool calls (3 requests intercepted)
─────────────────────────────────────────
```

### 2. Replay — what happened in order

```powershell
localfirst replay
```

```
⚡ LocalFirst Replay
   2026-05-07  ·  1 run today

  ── Run a1b2c3d4…  ──  10:30:01 → 10:31:44  (1m 43s)  ──
     4 events:  2 cloud  ·  2 local  ·  12.4k in / 1.8k out
     $0.0441  saved $0.0218
```

For the full per-event table:

```powershell
localfirst replay --detail
```

```
⚡ LocalFirst Replay  —  Run a1b2c3d4…
   run_id: a1b2c3d4-...
   2026-05-07T10:30:01Z  →  2026-05-07T10:31:44Z  (1m 43s)

   1.  10:30:01  cloud_sent   sonnet-4-6        1.2k in /  230 out  $0.0042
   2.  10:30:03  local_only   —                 2 tools local (cat, grep)  · ✂ 312 distilled
   3.  10:30:45  cloud_sent   sonnet-4-6       11.2k in /    1.6k out  $0.0399  · cache 9.1k
   4.  10:31:44  local_only   —                 1 tools local (find)

  Total:  $0.0441  ·  saved $0.0218  ·  2 local
```

**Reading the table:**
- `cloud_sent` — request went to Anthropic; shows token counts and cost
- `local_only` — request was short-circuited; tool calls ran on your machine, no Anthropic charges for tool execution
- `· cache 9.1k` — 9,100 tokens served from Anthropic's prompt cache (cheaper than fresh input)
- `· ✂ 312 distilled` — 312 tokens of grep/find output were clipped before re-entering the model

### 3. Per-request log

```powershell
localfirst ledger
```

```
⚡ LocalFirst Ledger
   scope: session  ·  4 entries total

      1. 10:30:01  cloud_sent   sonnet-4-6        1.2k in /  230 out  $0.0042
      2. 10:30:03  local_only   —                 · 2 tools local  · 312 trimmed
      3. 10:30:45  cloud_sent   sonnet-4-6       11.2k in /  1.6k out  $0.0399
      4. 10:31:44  local_only   —                 · 1 tools local
```

```powershell
localfirst ledger --summary
```

```
⚡ LocalFirst Ledger  —  Summary
   scope: session

  Requests          4
    cloud_sent      2
    local_only      2
  Tokens in         12.4k
  Tokens out        1.8k
  Cost              $0.0441
  Saved             $0.0218  (cache $0.0190 + distill $0.0028)
  Tools local       3
  Distilled         312 tokens saved across tool outputs
```

### 4. Raw log access

Each entry in `~/.localfirst/logs/YYYY-MM-DD.jsonl` is machine-readable:

```powershell
$log = "$env:USERPROFILE\.localfirst\logs\$(Get-Date -Format yyyy-MM-dd).jsonl"
Get-Content $log | ForEach-Object { $_ | ConvertFrom-Json } |
  Select-Object ts, event_type, cost, cache_savings, distill_cost_saved, tools_local_count |
  Format-Table
```

```
ts       event_type  cost    cache_savings  distill_cost_saved  tools_local_count
-------- ----------  ------  -------------  ------------------  -----------------
10:30:01 cloud_sent  0.0042  0              0                   0
10:30:03 local_only  0       0              0.0028              2
10:30:45 cloud_sent  0.0399  0.019          0                   0
10:31:44 local_only  0       0              0                   1
```

## What to look for

| Indicator | Meaning |
|---|---|
| `local_only` event | Tool calls ran on your machine — no Anthropic charge for tool execution |
| `cloud_sent` with `· cache Xk` | Anthropic cache hit — tokens served at 10% of input rate |
| `· ✂ N distilled` | Tool output was clipped before re-entering model — tokens saved |
| `trimmed` event | Context was trimmed by LAO before send (requires Python 3) |
| `blocked` event | Request was blocked by secret gate (strict mode) |

## Notes

- Cost numbers come from Anthropic's own `usage` fields in the API response — not estimates
- Cache savings are `cache_read_tokens × (input_rate − cache_read_rate)` from provider pricing
- Distillation savings are estimated: saved bytes ÷ 4 × input token rate
- `localfirst doctor` confirms whether LAO (Python) is active
