# Occasio supervisor templates (v0.6.4)

Occasio aborts with exit code 1 when it cannot append to its audit log
(`~/.occasio/pipeline-events.jsonl`). This is intentional — a missing
audit row must not coexist with a successful tool dispatch. To keep the
proxy available, pair it with a small supervisor that respawns it on exit.
The templates below are starting points, not a daemon we ship.

## Validation status

| Template | Platform | Status |
|---|---|---|
| `install-windows-task.ps1` | Windows 11 / PowerShell 7+ | **manually validated** |
| `occasio.service` | Linux / systemd | shipped, **not yet manually validated** by maintainers |
| `com.occasio.proxy.plist.template` | macOS / launchd | shipped, **not yet manually validated** by maintainers |

The Linux and macOS templates are structurally analogous to the Windows
one and use standard mechanisms; please open an issue if you hit a
problem so we can fix the template rather than letting each pilot
re-derive it.

## Linux (systemd, user scope)

```sh
mkdir -p ~/.config/systemd/user
cp occasio.service ~/.config/systemd/user/occasio.service
systemctl --user daemon-reload
systemctl --user enable --now occasio
systemctl --user status occasio
```

To remove:

```sh
systemctl --user disable --now occasio
rm ~/.config/systemd/user/occasio.service
```

## macOS (launchd, user scope)

The plist is a template: replace `{{OCCASIO_BIN}}` with the absolute
path to your `occasio` binary first.

```sh
LF_BIN="$(command -v occasio)"
sed "s|{{OCCASIO_BIN}}|$LF_BIN|g" com.occasio.proxy.plist.template \
  > ~/Library/LaunchAgents/ai.occasio.proxy.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.occasio.proxy.plist
launchctl print gui/$(id -u)/ai.occasio.proxy
```

To remove:

```sh
launchctl bootout gui/$(id -u)/ai.occasio.proxy
rm ~/Library/LaunchAgents/ai.occasio.proxy.plist
```

## Windows (Scheduled Task, user scope)

From a PowerShell prompt in this directory:

```pwsh
pwsh ./install-windows-task.ps1
```

This registers a task named `Occasio` that runs `occasio start` at
each logon and restarts the process within one minute if it exits.
(Windows Scheduled Tasks enforce a one-minute minimum on restart
intervals; if your threat model requires faster recovery, run a
foreground supervisor instead.) The
task scope is the current user; Occasio's audit log is per-user, so
there is no benefit to running it as SYSTEM.

To remove:

```pwsh
Unregister-ScheduledTask -TaskName Occasio -Confirm:$false
```

## Notes

- These templates supervise the proxy process. They do **not** verify
  the proxy is healthy beyond "the process exists." Pair with an
  external health-check (`curl http://127.0.0.1:<port>/healthz`) if your
  threat model requires it.
- The audit log itself is the source of truth for what was governed
  while the proxy was running. Gaps in the log (sessions that started
  with no rows) are a signal that the proxy was not running, not that
  governance was bypassed silently.
