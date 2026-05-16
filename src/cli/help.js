// `occasio help` — top-level usage. Pure text; no side effects other
// than console.log. Each CLI command lives in its own file under
// src/cli/ as part of the index.js decomposition (see CHANGELOG).
//
// Maturity tags follow the bewertung pillars:
//   (stable) — load-bearing, has test coverage and field validation
//   (beta)   — works end-to-end but missing breadth (one detector, one preset)
//   (alpha)  — scaffold; needs operator calibration before relying on it

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

${col.b('60-Second Start:')}
  ${col.c('occasio init')}        Create policy.yml from a template
  ${col.c('occasio register')}    Install shell alias so 'claude' uses the proxy
  ${col.c('claude --version')}    Confirm the wrapper resolves Claude Code

${col.b('Usage:')}  occasio <command> [args...]   (or  oc <command>)

${col.b('Setup')} ${col.d('— one-time, per project')}
  init                       ${col.d('(stable)')} Create starter policy.yml (--template strict|finance)
  register                   ${col.d('(stable)')} Register shell alias (type 'claude' directly)
  doctor                     ${col.d('(stable)')} Check setup: Node, claude CLI, port, Python, profile

${col.b('Run')} ${col.d('— start a session, observe live state')}
  claude [args...]           ${col.d('(stable)')} Start Claude with local proxy (intercept + log)
  status                     ${col.d('(stable)')} Session stats, savings breakdown, coverage
  clear                      ${col.d('(stable)')} Reset today's log and session data
  clear --history            ${col.d('(stable)')} Wipe all historical logs
  ledger                     ${col.d('(stable)')} Inspect token ledger (--last N, --summary, --scope)
  dashboard                  ${col.d('(beta)')}   Open live dashboard at http://localhost:3001

${col.b('Inspect')} ${col.d('— forensics over what the agent did')}
  replay                     ${col.d('(stable)')} Replay run audit (--last N, --detail, --run <id>)
  boundary                   ${col.d('(stable)')} Per-request: produced / re-entered / prevented
  inspect                    ${col.d('(stable)')} Cloud-boundary manifest (--last N, --entry N)
  distill                    ${col.d('(stable)')} Inspect distilled outputs (--last N, --entry <N>)
  report                     ${col.d('(stable)')} Governance export (--format csv for SIEM)
  preflight                  ${col.d('(beta)')}   Read-only miner over past logs
  baseline                   ${col.d('(beta)')}   Behavior baseline: [learn|show|compare|reset]

${col.b('Audit')} ${col.d('— tamper-evidence and attestation')}
  audit verify               ${col.d('(stable)')} Verify hash chain in pipeline-events.jsonl
  audit repair               ${col.d('(stable)')} Truncate crash-partial trailing line (--file --dry-run)
  attest --run-id <uuid>     ${col.d('(stable)')} Behavioral attestation: hash-chain + execution summary
                             ${col.d('Add --sign in GitHub Actions for Sigstore keyless signing')}
  attest verify <file>       ${col.d('(stable)')} Re-verify signed attestation (bundle + DSSE + chain)
  selftest                   ${col.d('(stable)')} Run governance self-checks on scratch chain

${col.b('Detect')} ${col.d('— anomalies, adversarial probes')}
  anomalies                  ${col.d('(beta)')}   Windowed EDR over the audit chain (--window 15m --json)
  harness                    ${col.d('(alpha)')}  Real Claude Code run vs. governance claims (API key required)
  redteam                    ${col.d('(alpha)')}  Autonomous adversarial probe (API key + SDK required)

${col.b('Policy & extras')}
  policy [show]              ${col.d('(stable)')} Show active policy: flags, routing, overrides
  policy show --diff         ${col.d('(stable)')} Only values that differ from defaults
  policy validate            ${col.d('(stable)')} Validate policy.yml and report errors/warnings
  policy doctor              ${col.d('(beta)')}   Cross-reference logs with policy; suggest tightening
  computer-use               ${col.d('(alpha)')}  Apply policy to a JSONL of tool_use blocks (--dry-run --example)
  mcp-experiment             ${col.d('(beta)')}   MCP vs. built-in tool adoption stats
  demo                       ${col.d('(stable)')} 10-second proof: see Occasio block real secrets
  demo attest                ${col.d('(stable)')} End-to-end attestation pipeline against a synthetic chain
  demo anomalies             ${col.d('(stable)')} End-to-end EDR test: synthetic adversarial chain

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
  --port <N>                    Proxy port (default: auto-assigned by OS)
  --verbose                     Print live per-request chatter (off by default)

${col.b('Multi-agent routing:')}
  Default               → Claude Code adapter
  Header x-occasio-agent: cline → Cline adapter (synthetic; live validation pending)

${col.b('Logs:')} ~/.occasio/logs/YYYY-MM-DD.jsonl
`);
}

module.exports = { run };
