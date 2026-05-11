# LocalFirst — SOC 2 Control Mapping (DRAFT)

**Status.** Draft. Conservative scope. The mappings below are limited to stanzas where the link between the policy and the SOC 2 control is **direct and provable from the audit log** — i.e. every claimed control evidences itself as an actual row, not as a vendor assertion. Mappings that would require interpretive bridging are intentionally absent. Before relying on this document for an audit, have it reviewed by a compliance practitioner familiar with your environment; it is published as a starting point, not a substitute for that review.

**Scope.**
- Framework: SOC 2 Trust Services Criteria, 2017, Common Criteria series only.
- Template: `policy-templates/finance.yml`.
- Evidence: rows in `~/.localfirst/pipeline-events.jsonl`, verifiable by `localfirst audit verify` and the independent walker at [`audit_walker.py`](audit_walker.py).

What this document deliberately does not do:
- Map ISO 27001, HIPAA, PCI-DSS, FedRAMP, or NIST 800-53. (Single-framework discipline; per-framework mapping is a separate effort.)
- Claim coverage of any availability, processing integrity, confidentiality, or privacy criteria beyond what `finance.yml` directly produces evidence for.
- Imply that LocalFirst alone is sufficient for SOC 2 attestation — it is one signal in a control set that includes IAM, endpoint controls, network controls, and HR processes.

---

## CC6.1 — Logical and Physical Access Controls (Restrict)

> *"The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives."*

**Mapped stanza.** `deny_paths` in `finance.yml`.

```yaml
deny_paths:
  - ~/.ssh
  - ~/.aws
  - ~/.config/gcloud
  - ~/.gnupg
```

**Why this maps.** A `deny_paths` entry blocks any read of a path under the listed prefix by an AI agent's tool call, regardless of which agent is calling and regardless of the routing that would otherwise apply. The control point is enforced at the LocalFirst boundary; the agent receives a `(blocked by policy)` synthetic refusal and the underlying file is never opened.

**Evidence in the audit log.** Every blocked attempt produces a row of this exact shape:

```json
{
  "kind":         "tool_call",
  "tool_name":    "read_file",
  "tool_inputs":  { "path": "<resolved absolute path>" },
  "action":       "BLOCK",
  "reason":       "path-denied",
  "result_kind":  "block",
  "prev_hash":    "...",
  "hash":         "..."
}
```

A reviewer asks: *"show me every time the agent attempted to read protected credentials in the period."* The answer is `localfirst report --days N`'s `blocked_accesses[]` array filtered by `reason: "path-denied"`, with row-level evidence verifiable via the hash chain.

**Limitations.**
- Coverage is bounded by what is in the `deny_paths` list. A path not listed is not blocked.
- A developer with write access to `~/.localfirst/policy.yml` can edit the list; that edit produces a `policy_loaded` row in the audit log (under v0.6.6+) carrying the SHA-256 of the new file, so the change is detectable, but it is not prevented.
- Concurrent multi-process audit writes are an unmitigated risk in v0.6.5 and v0.6.6 — if two processes are appending to the same `pipeline-events.jsonl`, an interleaved write on Windows can corrupt the chain. Document the single-writer discipline alongside this control.

---

## CC7.2 — System Monitoring (Detection of Security Events)

> *"The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events."*

**Mapped stanza.** The audit log itself, as produced by the LocalFirst proxy and MCP server.

**Why this maps.** Every governed tool call produces an immutable audit row. The hash chain detects post-hoc edits, and the `policy_loaded` synthetic event (v0.6.6+) binds tool-call rows to the specific policy file under which they were decided. A `BLOCK` row with `reason: "secret in tool result: <label>"` or `reason: "path-denied"` is the security event a CC7.2 program would treat as anomalous.

**Evidence in the audit log.** The full `pipeline-events.jsonl` file, plus the integrity statement from `localfirst audit verify` (or the equivalent independent walker output). The `localfirst report` command summarises these into `summary.paths_blocked`, `summary.secrets_detected`, and the corresponding `blocked_accesses[]` and `secret_events[]` arrays.

**Limitations.**
- The audit log is local. CC7.2 typically expects centralised log aggregation; the log must be shipped to a SIEM or equivalent for organisation-wide monitoring. v0.6.6 does not ship a built-in shipper; this is a separate operational integration.
- The control covers detection, not response. Action on detected events (notification, ticketing, remediation) is out of scope for the policy file alone.
- Absence of rows is not a control signal in v0.6.6: gaps can occur if the proxy was not running. Pair with a supervisor template (see `bin/supervisor/`) and external uptime monitoring to close this gap.

---

## Mappings deliberately not included in this draft

The following criteria are sometimes claimed by AI-tooling vendors but are **not mapped here** because the link to a `finance.yml` stanza is not directly evidenced by an audit row:

- **CC6.6 — Encryption.** LocalFirst does not encrypt data at rest or in transit on its own; it relies on the underlying filesystem and HTTPS to Anthropic. No stanza in `finance.yml` produces evidence relevant to a CC6.6 review.
- **CC6.7 — Information classification.** `deny_patterns` partially address this for credential-shaped strings, but classification systems (DLP labels, sensitivity tags) are an organisational concern, not a regex-pattern concern. Mapping `deny_patterns` to CC6.7 would overstate what the audit log proves.
- **CC8.1 — Change management.** The `policy_loaded` row records *that* a policy changed and *what hash* it changed to, but not who changed it or whether the change was approved. Layering an MDM/dotfiles-with-PR-review process on top of `policy.yml` is what actually addresses CC8.1.
- **A series (Availability), PI (Processing Integrity), C (Confidentiality), P (Privacy).** Out of scope for a Common-Criteria-only mapping. Add per-framework mapping documents if a customer needs them.

---

## How to use this document

1. **Pre-pilot review.** Hand this document to the customer's compliance contact alongside `GOVERNANCE.md` and `docs/AUDIT.md`. Ask them to flag any mapping that is too aggressive (we'd rather narrow the document than overclaim) and any criterion they expected to see addressed (which becomes a roadmap input, not a v0.6.6 ship).
2. **At pilot end.** Run `localfirst report --days <pilot-length>` and walk through the output with the compliance contact, pointing at the rows that evidence each mapped control.
3. **Re-review.** This document is versioned with the policy schema. If `finance.yml` gains a new stanza, this mapping must be revisited at that point — a stanza without explicit mapping or explicit "not mapped" treatment is documentation drift.

---

*Last reviewed: pending. To request a review, see the issues link in `package.json`.*
