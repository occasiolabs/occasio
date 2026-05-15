// `occasio help` — top-level usage. Pure text; no side effects other
// than console.log. Each CLI command lives in its own file under
// src/cli/ as part of the index.js decomposition (see CHANGELOG).

'use strict';

const VERSION = (() => {
  try { return require('../../package.json').version; }
  catch { return '0.0.0-unknown'; }
})();

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function run() {
  console.log(`
${col.b(`⚡ Occasio v${VERSION}`)}

${col.b('Usage:')}
  occasio claude [args...]   Start Claude with local proxy (intercept + log)
  occasio demo               10-second proof: see Occasio block real secrets
  occasio demo attest        End-to-end attestation pipeline against a synthetic audit chain
  occasio demo anomalies     End-to-end EDR test: synthetic adversarial chain → all 4 detectors
  occasio dashboard          Open live dashboard for the running session
  occasio register           Register shell alias (type 'claude' directly)
  occasio status             Show session stats and savings breakdown
  occasio doctor             Check setup: Node, claude CLI, port, Python, profile
  occasio clear              Reset today's log and session data
  occasio clear --history    Wipe all historical logs
  occasio ledger             Inspect token ledger (--last N, --summary, --scope session|today)
  occasio replay             Replay run audit (--last N, --detail, --run <id>, --attribute)
  occasio distill            Inspect distilled outputs (--last N, --entry <N> for raw)
  occasio inspect            Cloud-boundary manifest (--last N, --entry N, --run <id>)
  occasio boundary           Per-request three-column view: produced / re-entered / prevented
  occasio baseline           Behavior baseline: [learn|show|compare|reset] (per project cwd)
  occasio harness            Run a real Claude Code session against scratch fixtures and verify governance claims (needs ANTHROPIC_API_KEY)
  occasio redteam            Autonomous adversarial test — tester LLM probes a subject Claude Code session under Occasio (needs ANTHROPIC_API_KEY + @anthropic-ai/sdk)
  occasio policy [show]      Show active policy: flags, tool routing, overrides
  occasio policy show --diff Only values that differ from defaults
  occasio policy validate    Validate policy.yml and report errors/warnings
  occasio policy init        Create a starter policy.yml (safe, non-destructive)
                                Use --template strict|finance for a non-default starter
  occasio policy doctor      Cross-reference session logs with policy; surface suggestions
  occasio audit [verify]     Verify tamper-evident hash chain in pipeline-events.jsonl
  occasio audit repair       Truncate a crash-partial trailing line (--file <path> [--dry-run])
  occasio report             Governance export: file access log, blocked paths, secret events
  occasio anomalies          Live anomaly detection over the audit chain (--window 15m, --json)
  occasio computer-use       Apply a Computer-Use policy to a JSONL of tool_use blocks (--dry-run --example)
  occasio attest --run-id <uuid>  AI-Agent Behavioral Attestation v1: hash-chain commitment + execution summary for one run
                              Add --sign in GitHub Actions (with permissions: id-token: write) for Sigstore keyless signing
  occasio attest verify <file>   Re-verify a signed attestation: Sigstore bundle + DSSE payload match + audit chain integrity
  occasio selftest           Run governance self-checks on a scratch chain (does not touch your audit log)
  occasio report --format csv  CSV export for auditors / SIEM import
  occasio mcp-experiment     MCP vs. built-in tool adoption stats (experiment)

${col.b('Presets:')}
  --preset balanced  (default)  Intercept safe reads locally, log all requests
  --preset strict               Block requests that contain detected secrets
  --preset off                  Log only — no interception, no blocking

${col.b('Flags:')}
  --budget <N>                  Block requests once session cost exceeds $N (e.g. --budget 1.00)
  --hardened                    Route Read/Glob/Grep through unified runtime (distill + secret scan)
  --block-secrets               Alias for --preset strict
  --log-only                    Alias for --preset off
  --dashboard                   Open live dashboard at http://localhost:3001
  --port <N>                    Proxy port (default: 8081)
  --verbose                     Print live per-request chatter (off by default — quiet for Claude Code's TUI)

${col.b('Multi-agent routing:')}
  Default               → Claude Code adapter
  Header x-occasio-agent: cline → Cline adapter (synthetic; live validation pending)

${col.b('Logs:')} ~/.occasio/logs/YYYY-MM-DD.jsonl
`);
}

module.exports = { run };
