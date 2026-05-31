# Listing kit — awesome lists + MCP registries

Placement turns a launch spike into sustained, crawlable discovery. Do the four
MCP surfaces that matter and the one awesome list that fits the audience; skip
the long tail (it's noise).

---

## 1. awesome-claude-code (highest fit)
Repo: github.com/hesreallyhim/awesome-claude-code (~45k★, actively maintained).
Read its CONTRIBUTING before the PR — it has a submission format/script.

Suggested entry (tools/observability section):
> **[Occasio](https://github.com/occasiolabs/occasio)** — Local black-box
> recorder for AI coding agents. Records every file/command/MCP call Claude Code
> makes into a hash-chained, Sigstore-signed audit trail you can verify offline.
> Local-first, no telemetry. `npm install -g @occasiolabs/occasio`.

PR description: lead with the dev value ("know and prove what Claude Code did on
your machine"), link the demo video, mention local-first/no-telemetry. Do **not**
lead with compliance.

---

## 2. Official MCP Registry (the root everything ingests from)
Namespace `io.github.occasiolabs/occasio` is already reserved (see `server.json`,
currently at the bumped version). Publish/refresh the `server.json` entry so the
registry has the current version. Everything downstream (PulseMCP, mcp.so,
Glama) pulls from here, so this is the highest-leverage single action.

## 3. PulseMCP (highest-signal MCP channel)
pulsemcp.com — Steering-Committee-run, has a newsletter. Getting featured in the
newsletter is the best MCP-specific reach. Submit the server, then email/DM with
the demo video and the one-liner.

## 4. mcp.so + awesome-mcp-servers (SEO long-tail + backlink)
- mcp.so — submit for long-tail search discovery.
- github.com/punkpeye/awesome-mcp-servers — PR a one-line entry for the backlink.

---

## Skip (flagged as noise by research)
- llms.txt as an SEO/AI-search channel (crawlers barely touch it; we ship a
  minimal one anyway because IDE agents fetch it — already done).
- MCP registry/directory long tail beyond the four above.
- r/ClaudeAI as a primary channel — use r/LocalLLaMA + r/mcp instead.

## Sequencing
Do #2 (MCP Registry refresh) first — it's the root. Then #1 (awesome-claude-code)
for the dev audience. Then #3/#4. Pair every listing with the demo video and a
link to the `docs/launch/ci-snippet.md` so awareness can convert into a public
repo reference (the North Star).
