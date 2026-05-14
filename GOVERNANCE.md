# Occasio — Governance One-Pager

**For:** Security, compliance, and procurement reviewers evaluating Occasio for a pilot.
**Plain answer:** Occasio sits at the AI tool-call boundary on the developer's own machine and controls, per call, what is allowed to re-enter the model's next request. The control surface is one human-readable [`policy.yml`](policy-templates/dev-default.yml); every governed call lands in a tamper-evident hash chain that an independent walker can verify without trusting Occasio's own code. The same policy governs Claude Code and MCP traffic identically — the [cross-protocol demo](docs/demos/mcp-block.md) shows the same rule producing the same `BLOCK` rows under both protocols.

---

## What Occasio controls

Occasio intercepts every action the AI agent takes (file reads, searches, file writes, shell commands, MCP calls) **before** that action is sent to the cloud model and **before** any of its output is sent back. At that boundary it enforces a single policy file:

- **Routing.** Which actions execute locally on the developer machine vs. are passed to the cloud. By default, file reads, file searches, and recognised read-only shell commands run locally; their content is never transmitted.
- **Path access.** `deny_paths` blocks reads under sensitive prefixes (e.g. `~/.ssh`, `~/.aws`, credential stores). `allow_paths`, when set, restricts the agent to a closed list of project directories.
- **Secret containment.** A built-in scanner detects API keys, JWTs, AWS credentials, database URLs, and similar patterns in any tool output and blocks the request before the secret reaches the cloud. `deny_patterns` extends the scanner with your own regexes (internal token formats, ticket IDs, locale-specific PII).
- **Spend.** A per-session `--budget` is enforced in-process; outbound requests over budget return an HTTP 402 without ever calling the model.

The entire policy lives in one human-readable YAML file at `~/.occasio/policy.yml`. `occasio policy validate` lints it; `occasio policy show` prints the active state with annotations. The published [JSON Schema](schemas/occasio-policy.schema.json) gives any IDE autocomplete and inline validation, and the package ships three starter templates ([`dev-default`](policy-templates/dev-default.yml), [`strict`](policy-templates/strict.yml), [`finance`](policy-templates/finance.yml)) so a deployment can begin from the posture closest to its compliance baseline.

## What the audit trail proves

Every tool call that runs through Occasio is appended to a tamper-evident log at `~/.occasio/pipeline-events.jsonl`. Each entry is hash-chained to the previous entry, starting from a fixed genesis sentinel, so any deletion, reordering, or post-hoc edit is detectable.

A real entry from this codebase, captured during a session today:

```json
{
  "ts": "2026-05-10T12:30:27.449Z",
  "event_id": "9e05ec86-3575-4b57-8a24-d470f7d0779b",
  "session_id": "live-doc-validation-1778416227442",
  "agent": "claude-code",
  "kind": "tool_call",
  "tool_name": "read_file",
  "tool_inputs": { "path": "C:\\Users\\you\\Desktop\\occasio\\README.md" },
  "action": "LOCAL",
  "reason": "ok",
  "policy_source": "default",
  "executor": "native",
  "exit_code": 0,
  "prev_hash": "aa4639917161a8ae85a70cef4f48de5d18d5ebb860107d526f08973fe2018912",
  "hash":      "3f93077efc2ad41f202c94d970072f875546a31f164ba806649a0b4e78d69bd4"
}
```

What `tool_inputs` records, and what it deliberately does not:

| Tool         | Logged                              | Not logged                              |
|--------------|-------------------------------------|-----------------------------------------|
| `read_file`  | resolved absolute `path`            | file contents                            |
| `find_files` | `pattern` (if a real glob), `path`  | content-search strings disguised as patterns |
| `grep`       | `path`, `glob` filter               | the search pattern itself (free-form)   |
| `todo_write` | item `count`                        | todo text                                |
| shell tools  | (intentionally absent)              | the shell command and its output         |

The omissions are deliberate: a free-form regex or a shell command line is itself a credential-shaped surface, so the audit logs *that* an action happened, not the searchable detail of it. The hash chain still covers every tool-call event by id, timestamp, decision, and reason.

`occasio audit` re-walks the chain and reports the first inconsistency it finds, or confirms integrity end-to-end. For independent verification — the case where the buyer would rather not trust Occasio's own verifier — the row format, hash algorithm, and a 30-line standalone Python walker are published at [`docs/AUDIT.md`](docs/AUDIT.md). Both verifiers are kept byte-for-byte parity-checked at each release.

## How deny policy works

A deny rule is consulted **before** any routing decision, so it cannot be bypassed by editing the routing block:

```yaml
deny_paths:
  - ~/.ssh
  - ~/.aws
  - /etc/shadow

allow_paths:
  - ~/projects/customer-x

deny_patterns:
  internal-jwt:    "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
  internal-ticket: "INC-[0-9]{6,}"
```

Path comparisons are performed on the symlink-resolved absolute path (case-insensitive on Windows). A symlink that points into a denied directory is still denied. A `deny_paths` entry with a typo is reported as a validation **error** by `occasio policy validate`, never silently dropped — a missing deny entry is treated as a security gap.

## Worked example — a denied path

Policy:
```yaml
deny_paths:
  - ~/.ssh
```

The agent attempts to read `~/.ssh/id_rsa`. The dispatcher short-circuits the call: the file is never opened, the agent receives a `(blocked by policy)` tool_result, and the following row — captured **verbatim** from `pipeline-events.jsonl` during a live run on this codebase — is appended to the audit log:

```json
{
  "ts": "2026-05-10T12:45:57.036Z",
  "event_id": "363997a2-6690-455e-9025-9c98f32820f1",
  "session_id": "slice-e-live-1778417157027",
  "agent": "claude-code",
  "kind": "tool_call",
  "tool_name": "read_file",
  "tool_inputs": { "path": "C:\\Users\\you\\.ssh\\id_rsa" },
  "action": "BLOCK",
  "reason": "path-denied",
  "policy_source": "default",
  "result_kind": "block",
  "prev_hash": "3f93077efc2ad41f202c94d970072f875546a31f164ba806649a0b4e78d69bd4",
  "hash":      "6d072317b5a6156e0bb9a366230851531495af44b95ea00346db6ded5fc5209a"
}
```

The same mechanism applies when the built-in or custom secret scanner finds a hit in tool output — the engine returns BLOCK with `reason: "secret in tool result: <label>"`, the agent receives the synthetic refusal, and the audit row is written with `result_kind: "block"`.

## What `occasio report` produces

A single command summarises the audit log over a chosen window. Real output from this codebase, today, with `occasio report --days 1` (the run that captured the denied access above):

```json
{
  "generated_at": "2026-05-10T12:46:27.452Z",
  "period_days":  1,
  "summary": {
    "sessions":          22,
    "requests":          155,
    "cost_usd":          2.48,
    "files_accessed":    5,
    "paths_blocked":     1,
    "secrets_detected":  0,
    "requests_blocked":  0
  },
  "audit_integrity": {
    "verified":     true,
    "chain_length": 31,
    "first_event_ts": "2026-05-09T14:36:04.352Z",
    "last_event_ts":  "2026-05-10T12:45:57.039Z"
  },
  "blocked_accesses": [
    {
      "ts":         "2026-05-10T12:45:57.036Z",
      "session_id": "slice-e-live-1778417157027",
      "tool":       "read_file",
      "path":       "C:\\Users\\you\\.ssh\\id_rsa",
      "action":     "BLOCK",
      "reason":     "path-denied"
    }
  ]
}
```

The `audit_integrity.verified` line is load-bearing: it is the result of re-walking the SHA-256 hash chain over the entire log. A buyer can ask for the raw `pipeline-events.jsonl`, run `occasio audit verify` (or any independent SHA-256 walker), and confirm the report is truthful row-for-row. The row referenced under `blocked_accesses[0]` is the same row shown in the worked example above; the chain through `prev_hash`/`hash` is what proves it has not been edited after the fact.

---

**Posture.** Occasio is a local boundary layer. It does not replace your cloud DLP, your endpoint controls, or your IAM. It closes the specific gap that exists today between an AI agent on a developer machine and the cloud model it talks to, and produces evidence — a hash-chained event log and a one-command summary — that closure happened.

The durable artefact a buyer leaves a pilot with is not the proxy software; it is the policy file. It is YAML, source-controllable, multi-stakeholder-reviewable, and pinned to a published [schema](schemas/occasio-policy.schema.json) that is stable across v0.6.x. A draft [SOC 2 control mapping](docs/compliance-mapping.md) for the `finance.yml` template is published alongside this document; it deliberately covers only stanzas where the link to a control is directly evidenced by an audit row, and is intended as a starting point for a pilot's compliance review, not a substitute for one.
