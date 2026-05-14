# Demo — Cross-protocol governance via MCP

**What this demo proves.** The same `policy.yml` that governs Claude Code's `Read` tool also governs an MCP client's `read_file` call, unmodified. A `deny_paths` rule produces a `BLOCK` decision on both protocols, both produce a synthetic refusal to the agent, and both land in the same hash-chained `pipeline-events.jsonl` audit log — distinguishable only by the `protocol` field.

**Status.** Captured against the Occasio v0.6.5 MCP server (`bin/occasio-mcp.js`), driven by a synthetic MCP client invocation. The same code path runs when a real MCP client (Claude Desktop, Cursor, Continue) connects via stdio to `occasio-mcp` configured in its `mcpServers` list.

---

## 1. Policy

`~/.occasio/policy.yml`:

```yaml
version: 1
deny_paths:
  - C:\Users\you\.ssh
```

This is the **same** policy file that produced the Slice E `BLOCK` row for the Claude Code adapter. No MCP-specific stanzas. No new primitives.

## 2. MCP traffic — drive the server with two tool calls

Two `tools/call` requests, one denied and one allowed, sent through the Occasio MCP server with `clientInfo.name: "claude-ai"`:

```
→ tools/call read_file { path: "C:\\Users\\you\\.ssh\\id_rsa"     }   # denied path
→ tools/call read_file { path: "C:\\Users\\you\\Desktop\\…\\README.md" }   # allowed path
```

The server's responses, captured from the JSON-RPC stdout stream:

```json
{ "id": 2, "result": {
    "content": [{ "type": "text", "text": "(blocked by policy)" }],
    "isError": true
}}

{ "id": 3, "result": {
    "content": [{ "type": "text", "text": "     1\t# Occasio\n     2\t…" }],
    "isError": false
}}
```

The denied call **never opened the file**. It was short-circuited at the policy boundary, the synthetic refusal flowed back to the MCP client, and an audit row was written before the response was sent.

## 3. Audit row — verbatim from `pipeline-events.jsonl`

```json
{
  "ts": "2026-05-10T14:28:16.133Z",
  "event_id": "1b20b7a1-0512-417f-a080-605ebecedb64",
  "agent": "claude-ai",
  "protocol": "mcp",
  "direction": "inbound",
  "kind": "tool_call",
  "tool_name": "read_file",
  "tool_inputs": { "path": "C:\\Users\\you\\.ssh\\id_rsa" },
  "action": "BLOCK",
  "reason": "path-denied",
  "policy_source": "default",
  "result_kind": "block",
  "prev_hash": "3a764943385af22ed364f6a56e0f2b53f06fd544c4fbd531a1633608ca1ada09",
  "hash":      "664a8b6076540185ca74255c5b4d25887cc09b7323f86dcee8fd562652be3650"
}
```

The `protocol: "mcp"` field is the proof that this is the same governance pipeline the Slice E row came from, just entered by a different front door. The `agent: "claude-ai"` field came from the MCP `initialize.clientInfo.name` and is what a real Claude Desktop client identifies itself as. The `prev_hash` value matches the `hash` of the previous Slice E LOCAL row — the chain is continuous across protocols.

## 4. Chain integrity — both verifiers agree

```
$ occasio audit verify
  Rows:  33 total  (33 chained, 0 legacy/unverified)
  ✓ Chain intact  (33 rows verified)

$ python docs/audit_walker.py ~/.occasio/pipeline-events.jsonl
  OK: 33 rows verified
```

Adding the MCP row to a chain that previously contained only Anthropic-protocol rows did not break either verifier. The independent walker treats `protocol: "mcp"` as just another field; the canonical-serialization rules in `docs/AUDIT.md` are protocol-agnostic.

## 5. `occasio report` surfaces the MCP block

```
$ occasio report --days 1
{
  "summary": {
    "paths_blocked": 2,
    …
  },
  "blocked_accesses": [
    { "ts": "2026-05-10T12:45:57.036Z", "session_id": "slice-e-live-…",
      "tool": "read_file", "path": "C:\\Users\\you\\.ssh\\id_rsa",
      "action": "BLOCK", "reason": "path-denied" },
    { "ts": "2026-05-10T14:28:16.133Z", "session_id": null,
      "tool": "read_file", "path": "C:\\Users\\you\\.ssh\\id_rsa",
      "action": "BLOCK", "reason": "path-denied" }
  ]
}
```

Both blocks appear under `blocked_accesses[]`. The first is the Slice E Claude-Code-protocol block; the second is this demo's MCP block. The report does not distinguish them by protocol because, from a governance-summary perspective, they are the same kind of event — and that is the point of the demo.

---

## What this demo deliberately does not show

- **No third-party MCP server is being forwarded to.** The Occasio MCP server (`lf`) implements `read_file` itself. A "transparent forwarder in front of `@modelcontextprotocol/server-filesystem`" is a deferred follow-up; the cross-protocol governance proof stands on its own without it.
- **No second MCP integration.** The same proof would extend to GitHub MCP, Slack MCP, etc.; v0.6.5 deliberately ships only the one path.
- **No new policy primitives, audit fields, or transforms.** Same policy schema, same audit row shape, same hash algorithm.
- **No README / GOVERNANCE positioning rewrite yet.** That work is sequenced after this proof exists, not before.

## Reproducing the demo

The demo is reproducible from a clean checkout in under a minute:

```sh
# 1. Set the policy
cat > ~/.occasio/policy.yml <<'EOF'
version: 1
deny_paths:
  - ~/.ssh
EOF

# 2. Drive the MCP server (synthetic; same code path as a real MCP client)
node -e "
  const mcp = require('./src/mcp-server');
  mcp.__setRespondHookForTests((f) => console.log(f));
  (async () => {
    await mcp.handleRequest({ jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { clientInfo: { name: 'claude-ai' } } });
    await mcp.handleRequest({ jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '$HOME/.ssh/id_rsa' } } });
  })();
"

# 3. Inspect the new BLOCK row
tail -1 ~/.occasio/pipeline-events.jsonl | python -m json.tool

# 4. Confirm both verifiers agree
occasio audit verify
python docs/audit_walker.py ~/.occasio/pipeline-events.jsonl

# 5. Confirm the report surfaces it
occasio report --days 1 | python -c "import json,sys; print(json.load(sys.stdin)['blocked_accesses'])"
```

For a real-MCP-client capture (Claude Desktop, Cursor, Continue), configure `occasio-mcp` as an MCP server in the client's config and prompt the agent to read a denied path. The audit row, the verifier output, and the report all behave identically — the only field that changes is `agent`, which carries the client's `clientInfo.name`.
