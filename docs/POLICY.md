# Policy

`~/.occasio/policy.yml` is the single human-readable file that governs how Occasio
handles tool calls and tool results. It is enforced on the **Occasio-controlled
path** — the tool calls that route through the proxy/interceptor. It is not a
kernel sandbox: a process the agent spawns outside the proxy is outside this
policy. Within that boundary, the file below is authoritative.

Authoritative sources: the JSON Schema [`schemas/occasio-policy.schema.json`](../schemas/occasio-policy.schema.json),
the parser `src/policy/loader.js`, and the linter `src/policy/validate.js`.

## Fields

```yaml
version: 1

# Secret handling on tool results
block_secrets_in_tool_results: true     # block the request when a tool result contains a secret
redact_secrets_in_tool_results: false   # or replace the secret in place instead of blocking
distill_tool_results: false             # shave long tool outputs before they re-enter the model

# Cost gate (paired with --budget N at launch)
block_requests_over_budget: true

# Opt-in: also run the richer prefix/JWT/.env/entropy detectors (see docs/SCAN.md).
# Default OFF — the built-in pattern scanner is the default.
entropy_secret_detection: false

# Path access control (resolved absolute, case-insensitive on Windows; ~ expands to home).
# Applies to read_file / find_files / grep and shell-mediated reads (cat/Get-Content/…).
deny_paths:
  - ~/.ssh
  - ~/.aws
allow_paths: []          # when non-empty, ONLY these prefixes are readable

# Custom regex patterns treated like secret-scanner hits on tool results
deny_patterns:
  internal_host: "https://internal\\."

# Per-round volume caps (runaway-agent guard). Absent / ≤0 ⇒ that cap is not
# enforced — strictly opt-in, existing policies are unaffected.
limits:
  max_tool_calls_per_round: 50
  max_bash_calls_per_round: 10
  max_bytes_to_model_per_round: 2000000

# Per-tool routing. When present, REPLACES the built-in defaults entirely.
tools:
  Bash:
    action: PASS         # PASS (cloud) | LOCAL (run on your machine) | TRANSFORM (run + shape)
```

A missing `policy.yml` means the built-in defaults apply (see `DEFAULT_POLICY` in
`src/policy/loader.js`). Unknown keys are ignored; `occasio policy validate` flags
them.

## Commands

```bash
occasio policy init                 # write a starter policy.yml (--template dev-default|strict|finance)
occasio policy show [--diff]        # active policy (─diff = only overrides), incl. limits
occasio policy validate             # lint: errors (silently-dropped fields) + warnings (unknown keys)
occasio policy doctor               # cross-reference logs with policy; suggest tightening
```

## Approved policy: lock + diff

The audit chain's `policy_loaded` rows already prove *which policy was active
during a run*. A **lock** proves *which policy was approved*, and **diff**
detects drift from it — the CI pin.

```bash
occasio policy lock --sign --out policy.lock.json     # record the approved policy (hash + summary + optional Sigstore)
occasio policy diff --since policy.lock.json          # exit 1 if the active policy drifted from the lock
occasio policy lock --verify policy.lock.json --against policy.yml   # signature + payload + hash-drift check
```

- `policy.lock.json` carries the policy's SHA-256 (`policy_hash`, over the raw
  file bytes) plus a **machine-independent summary** built from the parsed file
  (raw `~` paths preserved — no absolute paths from the locking machine leak).
- `--sign` is **optional**: it adds a Sigstore (keyless) bundle sidecar with the
  dedicated payload type `application/vnd.occasio.policy-lock+json`. Unsigned
  locks still detect drift; the signature additionally proves *who* locked it.
- `policy diff` is **semantic** (ignores comment/whitespace churn) and also
  reports the byte-hash match/DRIFT. Exit code: `0` identical, `1` drifted —
  drop it into CI to fail when `policy.yml` moves away from the reviewed lock.

## Boundaries

- Enforcement covers the Occasio-controlled path only (proxy/interceptor) — not a
  kernel sandbox.
- Shell-mediated read enforcement resolves operands with `path.resolve` (no `~`
  expansion); `read_file` does expand `~`. Use absolute prefixes in `deny_paths`
  if you rely on shell-read blocking.
- The lock summary is derived from the current file; `policy diff`/`lock --verify`
  compare against the current `policy.yml`, not a historical run.

See also: [`docs/AUDIT.md`](AUDIT.md) (chain + `policy_loaded`), [`docs/SCAN.md`](SCAN.md),
[`docs/PREFLIGHT.md`](PREFLIGHT.md).
