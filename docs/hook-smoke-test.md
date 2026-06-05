# Hook smoke test — the one seam the test suite can't reach

**~10 minutes, your machine, real Claude Code.**

Occasio's automated tests prove the hook's *logic* (parity with the proxy,
fail-closed, single-use, the forged-token → enforce property) by driving
`occasio hook` over real stdin. The one thing they cannot exercise is **Claude
Code actually invoking the `PreToolUse` hook from `~/.claude/settings.json` and
honoring its exit code.** This runbook verifies exactly that seam.

## What this proves (and what it doesn't)

- **Proves:** with the hook installed, Claude Code calls `occasio hook` before a
  shell tool runs, and a `BLOCK` (exit 2) actually stops the command — for
  execution that does **not** go through the Occasio proxy.
- **Does not need to prove:** proxied traffic. When you run via `occasio claude`,
  the proxy is the enforcer and the hook deliberately no-ops. So this test runs
  Claude Code **un-proxied** on purpose — that's the case the hook exists for.

> Everything below runs in a throwaway HOME and targets `192.0.2.1` (TEST-NET-1,
> a documentation address that routes nowhere). Your real `~/.occasio` and
> `~/.claude` are never touched, and no real host is contacted.

## Prerequisites

- `occasio` on `PATH` (`occasio --version` works).
- Real Claude Code installed and logged in (`claude --version` works).
- Typing `claude` must run the **real** Claude Code, not the `occasio claude`
  alias. Check: `Get-Command claude` (PowerShell) / `type claude` (bash) should
  resolve to the Claude Code **binary**, not a shell function/alias. If `occasio
  register` aliased it, the test would run *proxied* (the hook then no-ops by
  design) — call the real Claude Code binary directly so the hook is the enforcer.

## Setup (sandboxed — no HOME hijack)

Point **only Occasio's own state** at a scratch dir via `OCCASIO_*` env vars, and
put the hook in a **project-level** `.claude/settings.json` (Claude Code runs
project hooks too — verified, no trust gate). Your real `~/.occasio`, `~/.claude`,
and Claude **login** stay untouched — so Claude Code does not re-authenticate and
no browser profile is created in the scratch.

> Earlier versions of this runbook repointed `HOME`. Don't — a fresh HOME makes
> Claude Code re-login, and the browser dumps a whole profile into your scratch.

PowerShell (Windows):

```powershell
$SCRATCH = Join-Path $env:TEMP "occasio-hook-smoke"
Remove-Item $SCRATCH -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $SCRATCH | Out-Null
Set-Location $SCRATCH

# sandbox ONLY Occasio's files — real ~/.occasio, real HOME, real login untouched
$env:OCCASIO_POLICY_FILE       = "$SCRATCH\policy.yml"
$env:OCCASIO_APPROVALS_FILE    = "$SCRATCH\approvals.jsonl"
$env:OCCASIO_APPROVAL_KEY_FILE = "$SCRATCH\approval-key"
$env:OCCASIO_IDENTITY_FILE     = "$SCRATCH\identity.json"
$env:OCCASIO_AUDIT_FILE        = "$SCRATCH\pipeline-events.jsonl"
$env:OCCASIO_CLAUDE_SETTINGS   = "$SCRATCH\.claude\settings.json"  # project hook config

occasio policy init --template strict   # identity-gated policy → $OCCASIO_POLICY_FILE
occasio hook --install                  # PreToolUse hook → the project .claude/settings.json
occasio doctor                          # expect: "PreToolUse hook — installed"
Get-Content (Join-Path $SCRATCH ".claude/settings.json")   # matcher "Bash" → occasio hook
```

bash (macOS/Linux): same, with `export OCCASIO_…="$SCRATCH/…"` and `cd "$SCRATCH"`.

The `OCCASIO_*` vars are inherited by Claude Code (you launch it from this shell)
and by the hook subprocess it spawns — so the hook reads the scratch policy/store,
never your real `~/.occasio`. You should see a `hooks.PreToolUse` entry with
`matcher: "Bash"` → `command: "occasio hook"`.

## The test — three acts

Start Claude Code **directly** (un-proxied) in the scratch dir:

```
claude
```

### Act 1 — the borrow is blocked by the hook

Prompt:

> Run this exact shell command: `ssh deploy@192.0.2.1 "echo hi"`

**Expected:** the command does **not** run. Claude Code shows a *hook* block —
e.g. `PreToolUse:Bash hook error: … Occasio: Denied: … requires human approval …
occasio approvals approve apr_… --once` — and **no** Yes/No prompt. ✅ This is the
seam: Claude Code invoked the hook and obeyed exit 2.

> **Tell the two apart.** A *hook block* is the "hook error: Denied …" message
> above, with no permission prompt. If instead you get Claude Code's own
> **"This command requires approval — Do you want to proceed? Yes/No"**, that is
> Claude Code's native permission system, **not** the hook — meaning the hook did
> not fire (see Troubleshooting). After an approval is consumed (Act 3), the hook
> returns 0 and you *do* fall through to that native Yes/No prompt — there it's
> the expected signal that the hook let it through.

Confirm out-of-band. Use the **same shell** (it still has the `OCCASIO_*` vars),
or a second terminal that re-exports them first:

```powershell
$SCRATCH = Join-Path $env:TEMP "occasio-hook-smoke"
$env:OCCASIO_APPROVALS_FILE = "$SCRATCH\approvals.jsonl"
$env:OCCASIO_AUDIT_FILE     = "$SCRATCH\pipeline-events.jsonl"
$env:OCCASIO_POLICY_FILE    = "$SCRATCH\policy.yml"
$env:OCCASIO_APPROVAL_KEY_FILE = "$SCRATCH\approval-key"
$env:OCCASIO_IDENTITY_FILE  = "$SCRATCH\identity.json"
occasio approvals list      # one pending apr_… for the ssh command
```

### Act 2 — you approve, out-of-band

```powershell
occasio identity set --id you
occasio approvals approve <apr_id> --once
```

### Act 3 — the retry passes through once, then is blocked again

Back in the Claude session, prompt:

> Run the same command again: `ssh deploy@192.0.2.1 "echo hi"`

**Expected:** this time the hook lets it through (one use), so Claude Code
actually runs `ssh` — which fails to connect to the dead `192.0.2.1` (a timeout /
"connection refused" from `ssh` itself is the **success** signal here: it means
the gate *allowed* it, not blocked it).

Ask once more:

> Run it a third time.

**Expected:** blocked again (the token was single-use). ✅

## Pass criteria

```powershell
occasio audit verify        # chain intact
occasio approvals list      # the apr_… now shows consumed
```

- Act 1: the first `ssh` was **blocked** (not executed). → Claude Code calls the
  hook and honors exit 2.
- Act 3: after approval the `ssh` **ran once** (reached the network and failed on
  the dead host), then the next attempt was **blocked**. → consume + single-use
  through the real seam.
- The chain contains `identity_borrow_request` then `identity_borrow_consumed`
  with `enforcement_point: hook`.

If all three hold, the settings.json → hook seam works end-to-end.

## Teardown

Trivial — the scratch holds only Occasio's files (no browser profile, nothing
locked). Exit any Claude session, then:

```powershell
Set-Location $env:TEMP            # don't delete a folder you're standing in
Remove-Item (Join-Path $env:TEMP "occasio-hook-smoke") -Recurse -Force
Get-ChildItem Env:OCCASIO_* | ForEach-Object { Remove-Item "Env:$($_.Name)" }
```

## Troubleshooting

- **You get Claude Code's native Yes/No prompt in Act 1 (not a hook block).** The
  hook didn't fire. Check, in order:
  - **`occasio --version` must be the build with the hook** (≥ the release that
    shipped `occasio hook`). A stale global install silently has no `hook` command.
    Run `occasio hook --help`; if it's unknown, your global occasio is too old —
    `npm i -g @occasiolabs/occasio@latest` (or point the hook command at a local
    build).
  - **The matcher must be exactly `"Bash"`.** A raw `"Bash|PowerShell"` is NOT a
    valid match for the `Bash` tool — Claude Code never fires the hook and fails
    open. Confirm with `/hooks` inside Claude Code (it should list one PreToolUse
    hook) and check `$SCRATCH\.claude\settings.json`.
  - **Restart Claude Code after editing settings** — hooks load at session start.
- **The `ssh` ran in Act 1 (not blocked).** You're likely proxied or un-gated:
  (a) you launched `occasio claude` instead of `claude` (the hook no-ops under the
  proxy — that's correct, but then you're testing the proxy); (b) `occasio` isn't
  on `PATH` for the hook subprocess (Claude Code couldn't spawn it → re-check
  `occasio --version`); (c) the `OCCASIO_*` vars weren't set in the shell you
  launched `claude` from, so the hook reads a different policy/store (re-run setup
  in that shell; `occasio policy show` should be the `strict` posture).
- **Hook errors instead of a clean block.** That's still fail-closed (it denies),
  but capture the stderr Claude shows and check `occasio gate "ssh deploy@192.0.2.1" --enforce`
  with the `OCCASIO_*` vars set.
- **Nothing in `approvals list`.** The borrow never reached the hook — see the
  first bullet.
