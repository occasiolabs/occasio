#!/usr/bin/env node
const { spawn } = require('child_process');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
// Phase E: the proxy calls the adapter's runToolLoop directly. The
// interceptToolUse shim is gone — this is the canonical entry point for an
// Anthropic conversation that contains tool_use turns.
//
// Stage 3: multi-agent routing. The proxy supports multiple AI agents via
// per-request adapter selection. Detection signal: the
// `x-occasio-agent` header. Default (header absent or unrecognized)
// preserves Claude Code behavior exactly. Every adapter is loaded at startup
// so its tool-name registration runs before any traffic arrives.
const claudeCodeAdapter = require('./adapters/claude-code');
const clineAdapter      = require('./adapters/cline');
const toolNamesRegistry = require('./core/tool-names');
const { selectAdapter: routeAgent, HEADER_NAME: AGENT_HEADER } = require('./proxy/agent-router');

const AGENT_ADAPTERS = Object.freeze({
  'claude-code': claudeCodeAdapter,
  'cline':       clineAdapter,
});
const DEFAULT_AGENT = 'claude-code';

/**
 * Per-request adapter selection. Two signals, in order:
 *   1. `x-occasio-agent` HTTP header (explicit)
 *   2. content fingerprint of the SSE response (implicit fallback)
 * Fingerprint is critical because some agents (notably Cline in some
 * release versions) don't expose a custom-headers UI, so the explicit
 * header isn't always reliable.
 */
function selectAdapter(headers, sseBody) {
  return routeAgent(headers, AGENT_ADAPTERS, DEFAULT_AGENT, {
    sseBody,
    registry: toolNamesRegistry,
  });
}
const { parseFileTokens, scanSecrets } = require('./analyzer');
const { optimizeContext } = require('./lao');
const { randomUUID }      = require('crypto');
const { runLedgerCli }    = require('./ledger');
const { runReplayCli }    = require('./replay');
const { runInspectCli }   = require('./inspect');
const { runAuditCli }     = require('./audit/verifier');
const { budgetStatus, fmtBudget, BUDGET_EXCEEDED_EVENT } = require('./budget');

// Source of truth: package.json. Read at startup so `occasio --version`
// can't drift from what npm reports — the previous hardcoded constant
// caused 0.8.1's CLI to mis-report itself as 0.8.0.
const VERSION = (() => {
  try { return require('../package.json').version; }
  catch { return '0.0.0-unknown'; }
})();
const LOG_SCHEMA_VERSION = 2;
// Port: defaults to 0 (auto-assigned by the OS) so multiple `occasio claude`
// sessions can run in parallel. Explicit overrides via OCCASIO_PORT env or
// --port flag still pin a fixed port (and surface EADDRINUSE if taken).
let PORT = parseInt(process.env.OCCASIO_PORT, 10) || 0;
let PORT_EXPLICIT = PORT !== 0;
const ANTHROPIC_REAL = 'api.anthropic.com';
const LOG_DIR      = path.join(os.homedir(), '.occasio');
const SESSION_FILE = path.join(LOG_DIR, 'session.json');
// Captured once at process start; stable for the entire session.
// Used by the preflight miner to group sessions by project root.
const SESSION_CWD  = process.cwd();

function todayStr() { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; }
function getLogFile()     { return path.join(LOG_DIR, 'logs',    `${todayStr()}.jsonl`); }
function getBlockedFile() { return path.join(LOG_DIR, 'blocked', `${todayStr()}-secrets.log`); }

// Pricing extracted to its own module — see src/cost/prices.js for the
// MODEL_PRICES table + cost-arithmetic helpers. Re-exported here so the
// rest of index.js keeps its existing call sites unchanged.
const {
  calcCost,
  calcCacheSavings,
  calcCompoundingSavings,
} = require('./cost/prices');

// ── Persistence ────────────────────────────────────────────────────────────────

function ensureDirs() {
  for (const sub of ['', 'logs', 'reports', 'blocked', 'distilled']) {
    const d = path.join(LOG_DIR, sub);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }
}
function getDistilledFile() { return path.join(LOG_DIR, 'distilled', `${todayStr()}.jsonl`); }
function writeLog(e)        { ensureDirs(); fs.appendFileSync(getLogFile(),       JSON.stringify(e) + '\n'); }
function writeBlocked(e)    { ensureDirs(); fs.appendFileSync(getBlockedFile(),   JSON.stringify(e) + '\n'); }
function writeDistilledRaw(e) { ensureDirs(); fs.appendFileSync(getDistilledFile(), JSON.stringify(e) + '\n'); }
function updateSession(e) {
  ensureDirs();
  let s = {
    requests:0, input_tokens:0, output_tokens:0, cost:0, blocked:0, intercepted_count:0,
    cache_read_tokens:0, cache_write_tokens:0, cache_savings:0,
    lao_tokens_saved:0, lao_cost_saved:0, tools_local_count:0, tools_mcp_count:0,
    tools_attempted:0,
  };
  try { s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch { /* ignore */ }
  s.requests++;
  s.input_tokens       += e.input_tokens       || 0;
  s.output_tokens      += e.output_tokens      || 0;
  s.cost               += e.cost               || 0;
  s.cache_read_tokens  += e.cache_read_tokens  || 0;
  s.cache_write_tokens += e.cache_write_tokens || 0;
  s.cache_savings      += e.cache_savings      || 0;
  s.lao_tokens_saved      += e.lao_tokens_saved      || 0;
  s.lao_cost_saved        += e.lao_cost_saved        || 0;
  s.tools_local_count     += e.tools_local_count     || 0;
  s.tools_mcp_count       += e.tools_mcp_count       || 0;
  s.distill_tokens_saved  += e.distill_tokens_saved  || 0;
  s.distill_cost_saved    += e.distill_cost_saved    || 0;
  s.tools_attempted       += e.tools_attempted       || 0;
  s.secrets_redacted      += e.secrets_redacted      || 0;
  s.tools_transformed     += e.tools_transformed     || 0;
  if (e.model && !s.model) s.model = e.model;
  if (e.intercepted)                               s.intercepted_count++;
  if (e.event_type === 'blocked' || e.blocked?.length) s.blocked++;
  fs.writeFileSync(SESSION_FILE, JSON.stringify(s));
}

// ── Terminal colors ────────────────────────────────────────────────────────────

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

// Print a compact recap banner just before claude starts — gives the user
// (and the agent, via on-screen context) a memory anchor for the previous
// session in this cwd. Silent if no prior data exists.
function printSessionRecapBanner() {
  let conv = null;
  try { conv = require('./cli/conversation').readLastConversation(process.cwd()); }
  catch { /* module load issue → skip */ }

  // Last run summary from the audit chain.
  let runLine = null;
  try {
    const chainFile = path.join(LOG_DIR, 'pipeline-events.jsonl');
    if (fs.existsSync(chainFile)) {
      const text = fs.readFileSync(chainFile, 'utf8');
      const rows = [];
      for (const line of text.split('\n')) {
        if (!line) continue;
        try { rows.push(JSON.parse(line)); } catch { /* skip */ }
      }
      const byRun = new Map();
      for (const r of rows) {
        const id = r.run_id || 'legacy';
        if (!byRun.has(id)) byRun.set(id, []);
        byRun.get(id).push(r);
      }
      const newest = [...byRun.entries()].map(([id, rs]) => ({
        id, rs, end: rs[rs.length - 1]?.ts || '',
      })).sort((a, b) => a.end < b.end ? 1 : -1)[0];
      if (newest) {
        const tc = newest.rs.filter(r => r.kind === 'tool_call').length;
        const blocked = newest.rs.filter(r => r.action === 'BLOCK').length;
        const date = newest.end ? new Date(newest.end).toISOString().slice(0, 16).replace('T', ' ') : 'unknown';
        runLine = `${tc} tool calls, ${blocked} blocked  ·  ${date}`;
      }
    }
  } catch { /* skip */ }

  if (!conv && !runLine) return;

  const oneLine = (s, max = 160) => {
    const flat = String(s).replace(/\s+/g, ' ').trim();
    return flat.length > max ? flat.slice(0, max - 1) + '…' : flat;
  };
  process.stderr.write('\n' + col.b('── previous session in this directory ──') + '\n');
  if (runLine) process.stderr.write('  ' + col.d(runLine) + '\n');
  if (conv && conv.lastUser) {
    process.stderr.write('  ' + col.y('You: ') + oneLine(conv.lastUser) + '\n');
  }
  if (conv && conv.lastAssistant) {
    process.stderr.write('  ' + col.g('Agent: ') + oneLine(conv.lastAssistant) + '\n');
  }
  process.stderr.write(col.d('  (enabled via --recap; suppress next time by omitting it)') + '\n\n');
}

// ── Pre-send manifest ─────────────────────────────────────────────────────────

function fmtTok(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}kt` : `${n}t`;
}

/**
 * Rough token estimate from a parsed request body.
 * Walks system prompt + all message content blocks and sums character counts / 4.
 * Deliberately conservative: does not include JSON framing overhead so the
 * estimate stays close to actual model-token counts (4 chars ≈ 1 token).
 */
function roughTokensFromBody(body) {
  if (!body) return 0;
  let chars = 0;
  if (body.system) {
    const s = typeof body.system === 'string' ? body.system
      : Array.isArray(body.system) ? body.system.map(b => b.text || '').join('') : '';
    chars += s.length;
  }
  for (const msg of body.messages || []) {
    const c = msg.content;
    if (typeof c === 'string') {
      chars += c.length;
    } else if (Array.isArray(c)) {
      for (const b of c) {
        if (typeof b === 'string')             chars += b.length;
        else if (typeof b.text === 'string')   chars += b.text.length;
        else if (typeof b.content === 'string') chars += b.content.length;
        else if (Array.isArray(b.content)) {
          for (const cb of b.content) chars += (typeof cb === 'string' ? cb : cb.text || '').length;
        }
      }
    }
  }
  return Math.ceil(chars / 4);
}

/**
 * Print a compact pre-send manifest to stderr just before the request leaves
 * the machine.  Called once per outbound /v1/messages call from the proxy.
 *
 * Format (all dim, ▶ in cyan — one line):
 *   HH:MM:SS  ▶  ~Xkt  ·  N msgs  ·  dir/file ~Yt  ·  dir/file ~Zt  +W more
 *
 * totalEst:     rough payload size in tokens (marked ~, derived from content chars / 4)
 * Token counts for files are estimates (marked ~).  Message count is exact.
 */
function printPreSendManifest(fileTokens, outboundMsgCount, totalEst) {
  if (!LIVE_VERBOSE) return;  // quiet by default: avoid corrupting Claude Code's TUI
  const ts   = new Date().toTimeString().slice(0, 8);
  const top  = fileTokens.slice(0, 3);
  const more = fileTokens.length > 3 ? col.d(` +${fileTokens.length - 3} more`) : '';

  const fileStr = top.map(f => {
    const segs = f.name.replace(/\\/g, '/').split('/');
    const name = segs.length > 2 ? segs.slice(-2).join('/') : f.name;
    return col.d(`${name} ~${fmtTok(f.tokens)}`);
  }).join(col.d('  '));

  const totalPart = totalEst > 0 ? col.d(`~${fmtTok(totalEst)}`) : '';
  const msgPart   = outboundMsgCount > 0 ? col.d(`${outboundMsgCount} msgs`) : '';
  const filePart  = fileStr + more;

  const parts = [totalPart, msgPart, filePart].filter(Boolean);
  const body  = parts.join(col.d('  ·  ')) || col.d('(no context)');

  process.stderr.write(`${col.d(ts)}  ${col.c('▶')}  ${body}\n`);
}

// ── Distill CLI ────────────────────────────────────────────────────────────────

function runDistillCli(cliArgs) {
  const file = getDistilledFile();
  if (!fs.existsSync(file)) {
    console.log('No distilled output today.');
    return;
  }
  const entries = fs.readFileSync(file, 'utf8').trim().split('\n')
    .filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  if (entries.length === 0) {
    console.log('No distilled output today.');
    return;
  }

  const lastFlagIdx = cliArgs.indexOf('--last');
  const lastN       = lastFlagIdx !== -1 ? (parseInt(cliArgs[lastFlagIdx + 1]) || 10) : 10;
  const entryFlagIdx = cliArgs.indexOf('--entry');
  const entryIdx    = entryFlagIdx !== -1 ? parseInt(cliArgs[entryFlagIdx + 1]) : null;

  // Show single entry's raw content
  if (entryIdx != null) {
    const e = entries[entryIdx];
    if (!e) { console.log(`No entry at index ${entryIdx} (${entries.length} total today).`); return; }
    console.log(`\n${col.b(`Entry [${entryIdx}]`)}  ${col.d(e.cmd || '?')}  ${col.d(`${(e.rawBytes || 0).toLocaleString()} bytes`)}\n`);
    console.log(e.rawContent || '(no raw content saved)');
    return;
  }

  // List view
  const recent = entries.slice(-lastN);
  const offset = entries.length - recent.length;
  console.log(`\n${col.b('Distilled outputs')}  ${col.d(`last ${recent.length} of ${entries.length} today`)}\n`);
  recent.forEach((e, i) => {
    const idx = offset + i;
    const cmd_ = (e.cmd || '?').slice(0, 48).padEnd(48);
    const kb   = ((e.rawBytes || 0) / 1024).toFixed(1).padStart(6);
    console.log(`  [${String(idx).padStart(2)}] ${cmd_}  ${col.d(`${kb} KB`)}  ${col.d(e.label || '')}`);
  });
  console.log(`\n${col.d('  occasio distill --entry <N>   show raw output for entry N')}`);
  console.log(`${col.d('  occasio distill --last <N>    show last N entries')}\n`);
}

// ── CLI commands ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const cmd = args[0];

if (cmd === '--version' || cmd === '-v') { console.log(`occasio v${VERSION}`); process.exit(0); }

if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
  require('./cli/help').run();
  process.exit(0);
}

if (cmd === 'register') {
  require('./cli/register').run();
  process.exit(0);
}

if (cmd === 'status' || cmd === 'stats') {
  require('./cli/status').run();
  process.exit(0);
}

if (cmd === 'clear') {
  require('./cli/clear').run(args.slice(1));
  process.exit(0);
}

if (cmd === 'ledger') {
  runLedgerCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'replay') {
  runReplayCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'recap') {
  process.exit(require('./cli/recap').run(args.slice(1)));
}

if (cmd === 'distill') {
  runDistillCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'boundary') {
  const { runBoundaryCli } = require('./boundary');
  const result = runBoundaryCli(args.slice(1));
  process.exit(result.ok ? 0 : 1);
}

if (cmd === 'baseline') {
  const { runBaselineCli } = require('./baseline');
  const result = runBaselineCli(args.slice(1));
  process.exit(result.ok ? 0 : 1);
}

if (cmd === 'harness') {
  const { runHarnessCli } = require('./harness');
  runHarnessCli(args.slice(1)).then(r => process.exit(r.ok ? 0 : 1));
  return;
}

if (cmd === 'redteam') {
  const { runRedteamCli } = require('./redteam');
  runRedteamCli(args.slice(1)).then(r => process.exit(r.ok ? 0 : 1));
  return;
}

if (cmd === 'inspect') {
  runInspectCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'audit') {
  runAuditCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'selftest') {
  const { runSelfTestCli } = require('./selftest');
  runSelfTestCli();   // async, calls process.exit itself
  return;
}

if (cmd === 'policy') {
  const sub = args[1];
  if (!sub || sub === 'show') {
    const { runPolicyCli } = require('./policy/show');
    runPolicyCli(args.slice(sub ? 2 : 1));
    process.exit(0);
  }
  if (sub === 'validate') {
    const { runValidateCli } = require('./policy/validate');
    const result = runValidateCli(args.slice(2));
    process.exit(result.ok ? 0 : 1);
  }
  if (sub === 'init') {
    const { runInitCli } = require('./policy/init');
    const result = runInitCli(args.slice(2));
    process.exit(result.ok ? 0 : 1);
  }
  if (sub === 'doctor') {
    const { runDoctorCli } = require('./policy/doctor');
    runDoctorCli(args.slice(2));
    process.exit(0);
  }
  console.error(col.r(`Unknown policy subcommand: ${sub}`));
  console.error(col.d('  Usage: occasio policy [show] [--diff]'));
  console.error(col.d('         occasio policy validate [--file path]'));
  console.error(col.d('         occasio policy init [--template dev-default|strict|finance] [--force] [--file path]'));
  console.error(col.d('         occasio policy doctor [--days N]'));
  process.exit(1);
}

if (cmd === 'report') {
  const { runReportCli } = require('./report/index');
  runReportCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'anomalies' || cmd === 'anomaly') {
  const { runAnomaliesCli } = require('./anomaly/cli');
  process.exit(runAnomaliesCli(args.slice(1)));
}

if (cmd === 'computer-use') {
  const { runComputerUseCli } = require('./adapters/computer-use-cli');
  process.exit(runComputerUseCli(args.slice(1)));
}

if (cmd === 'attest') {
  const { runAttestCli } = require('./attest');
  const r = runAttestCli(args.slice(1));
  if (r && typeof r.then === 'function') {
    r.then(() => process.exit(0)).catch(() => process.exit(1));
  } else {
    process.exit(0);
  }
  return;
}

if (cmd === 'preflight') {
  const { runPreflightCli } = require('./preflight/cli');
  runPreflightCli(args.slice(1));
  process.exit(0);
}

if (cmd === 'demo' && args[1] === 'attest') {
  const { runAttestDemoCli } = require('./demo/attest-demo');
  runAttestDemoCli(args.slice(2)).then(code => process.exit(code))
    .catch(e => { process.stderr.write(`[demo attest] ${e.message}\n`); process.exit(1); });
  return;
}

if (cmd === 'demo' && (args[1] === 'anomalies' || args[1] === 'anomaly')) {
  const { runAnomaliesDemoCli } = require('./demo/anomalies-demo');
  process.exit(runAnomaliesDemoCli(args.slice(2)));
}

if (cmd === 'demo' && (args[1] === 'audit' || args[1] === 'auditor')) {
  const { runAuditDemoCli } = require('./demo/audit-demo');
  runAuditDemoCli(args.slice(2)).then(code => process.exit(code))
    .catch(e => { process.stderr.write(`[demo audit] ${e.message}\n`); process.exit(1); });
  return;
}

if (cmd === 'demo') {
  const { scanSecrets } = require('../src/analyzer');
  // Realistic-looking but synthetic credentials. Each hits exactly one pattern.
  // No real keys are used; the AWS string is the actual public AWS docs example.
  const FIXTURES = [
    {
      name: '.env',
      content: [
        '# Production environment',
        'NODE_ENV=production',
        'ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_EXAMPLE',
        'PORT=3000',
      ].join('\n'),
    },
    {
      name: 'config.yml',
      content: [
        'app:',
        '  name: occasio-demo',
        '  database:',
        '    url: postgres://admin:hunter2hunter2@db.internal:5432/prod',
        '  port: 5432',
      ].join('\n'),
    },
    {
      name: 'deploy.sh',
      content: [
        '#!/bin/bash',
        'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        'aws s3 sync ./build s3://my-bucket/',
      ].join('\n'),
    },
    {
      name: 'secrets.json',
      content: [
        '{',
        '  "github_token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",',
        '  "service": "ci"',
        '}',
      ].join('\n'),
    },
    {
      name: 'setup.py',
      content: [
        'import os',
        '',
        'def configure():',
        '    # TODO: load from env in production',
        '    api_key = "1234567890abcdef1234567890abcdef"',
        '    return api_key',
      ].join('\n'),
    },
  ];

  console.log(col.b('\n⚡ Occasio — secret-block demo\n'));
  console.log(col.d(`  Simulating a Claude Code session that reads ${FIXTURES.length} files.`));
  console.log(col.d(`  Running the real scanner — same code path that fires on every tool result.\n`));

  let totalHits = 0;
  for (const f of FIXTURES) {
    const hits = scanSecrets(f.content);
    console.log(`  ${col.b('📄 ' + f.name)}`);
    if (hits.length === 0) {
      console.log(`    ${col.g('✓ clean')}\n`);
      continue;
    }
    for (const h of hits) {
      const tag = col.r('✗ BLOCKED');
      const lbl = col.y(h.label.padEnd(15));
      console.log(`    ${tag}  ${lbl}  line ${h.line}`);
      console.log(`       ${col.d(h.snippet)}`);
      totalHits++;
    }
    console.log('');
  }

  console.log(col.d('  ' + '─'.repeat(64)));
  console.log(`  ${col.r(totalHits + ' secrets')} that would have been sent to Anthropic — ${col.g('blocked locally')}.`);
  console.log(col.d(`  Each value masked before logging; the raw secret never leaves your machine.\n`));
  process.exit(0);
}

if (cmd === 'mcp-experiment' || cmd === 'mcp-stats') {
  require('./mcp-experiment');
  process.exit(0);
}

if (cmd === 'dashboard') {
  require('./dashboard');
  const url = 'http://localhost:3001';
  process.stderr.write(col.b('\n⚡ Occasio Dashboard\n\n'));
  process.stderr.write(`  ${col.c(url)}\n`);
  process.stderr.write(col.d('  Reads from the running session in ~/.occasio/session.json\n\n'));
  require('child_process').exec(
    process.platform === 'win32' ? `start ${url}` :
    process.platform === 'darwin' ? `open ${url}` : `xdg-open ${url}`,
    { shell: true }
  );
  return;
}

if (cmd === 'doctor' || cmd === 'check') {
  (async () => {
    const { execSync } = require('child_process');
    const net = require('net');
    let allOk = true;
    const ok  = (label, detail) => process.stderr.write(col.g(`  ✓ ${label}`) + (detail ? col.d(` — ${detail}`) : '') + '\n');
    const bad = (label, hint)   => { process.stderr.write(col.r(`  ✗ ${label}`) + (hint ? col.d(` — ${hint}`) : '') + '\n'); allOk = false; };

    process.stderr.write(col.b('\n⚡ Occasio doctor\n\n'));

    // 1. Node.js version
    const [nodeMajor] = process.versions.node.split('.').map(Number);
    if (nodeMajor >= 18) ok('Node.js', `v${process.versions.node}`);
    else bad('Node.js', `v${process.versions.node} — requires ≥ 18`);

    // 2. claude CLI
    try {
      const out = execSync('claude --version', {
        shell: process.platform === 'win32', timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).toString().trim();
      ok('claude CLI', out.split('\n')[0]);
    } catch { bad('claude CLI', 'not found — npm install -g @anthropic-ai/claude-code'); }

    // 3. Log dir writable
    try {
      ensureDirs();
      const probe = path.join(LOG_DIR, '.doctor');
      fs.writeFileSync(probe, ''); fs.unlinkSync(probe);
      ok('log dir', LOG_DIR);
    } catch (e) { bad('log dir', e.message); }

    // 4. Port availability (async) — only probe when an explicit port is pinned.
    // With auto-assignment (default), the OS picks a free port at listen-time
    // so there's nothing meaningful to probe in advance.
    if (PORT_EXPLICIT) {
      await new Promise(resolve => {
        const srv = net.createServer();
        srv.once('error', () => {
          bad(`port ${PORT}`, `already in use — kill it: netstat -ano | findstr :${PORT}`);
          resolve();
        });
        srv.once('listening', () => { srv.close(); ok(`port ${PORT}`, 'available'); resolve(); });
        srv.listen(PORT, '127.0.0.1');
      });
    } else {
      ok('port', 'auto-assigned at runtime');
    }

    // 5. Python + LAO scorer script
    const laoPyPath = path.join(__dirname, 'lao_prep.py');
    const laoPyExists = fs.existsSync(laoPyPath);
    let pyFound = false;
    for (const pyCmd of ['python', 'python3']) {
      if (pyFound) break;
      try {
        const out = execSync(`${pyCmd} --version`, {
          shell: process.platform === 'win32', timeout: 5000,
          stdio: ['pipe', 'pipe', 'pipe'],
        }).toString().trim();
        ok('Python (LAO)', out); pyFound = true;
      } catch { /* ignore */ }
    }
    if (!pyFound) bad('Python (LAO)', 'not found — context trimming disabled');
    if (laoPyExists) ok('LAO scorer', laoPyPath);
    else bad('LAO scorer', 'lao_prep.py missing — context trimming disabled even if Python is installed');

    // 6. PowerShell profile + execution policy (Windows only)
    if (process.platform === 'win32') {
      const pFile = path.join(os.homedir(), 'Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1');
      try {
        const src = fs.existsSync(pFile) ? fs.readFileSync(pFile, 'utf8') : '';
        if (src.includes('occasio claude @args')) ok('PowerShell profile', 'registered');
        else bad('PowerShell profile', 'not registered — run: occasio register');
      } catch { bad('PowerShell profile', 'cannot read profile'); }

      // Check execution policy — Restricted prevents profile scripts from running.
      try {
        const policy = execSync(
          'powershell -NoProfile -Command "Get-ExecutionPolicy -Scope CurrentUser"',
          { shell: false, timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
        ).toString().trim();
        if (policy === 'Restricted' || policy === 'Undefined') {
          bad('ExecutionPolicy', `${policy} — profile scripts blocked. Fix: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`);
          allOk = false;
        } else {
          ok('ExecutionPolicy', policy);
        }
      } catch { /* powershell not on PATH or timed out — skip silently */ }
    }

    // Session summary
    try {
      const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
      const localSavD = (s.lao_cost_saved || 0) + (s.distill_cost_saved || 0);
      const savingStr = localSavD > 0 ? ` · saved $${localSavD.toFixed(4)}` : '';
      process.stderr.write(col.d(`\n  Last session: ${s.requests} requests · $${(s.cost || 0).toFixed(4)}${savingStr}\n`));
    } catch { process.stderr.write(col.d('\n  No session data yet.\n')); }

    process.stderr.write('\n');
    if (!allOk) {
      process.stderr.write(col.r('  Some checks failed.\n\n'));
      process.exit(1);
    }
    process.stderr.write(col.g('  All checks passed.\n\n'));
    process.exit(0);
  })();
  return;
}

const claudeArgs = cmd === 'claude' ? args.slice(1) : args;
let mode = 'intercept';
const mi = claudeArgs.indexOf('--mode');
if (mi >= 0) { mode = claudeArgs[mi+1]||'intercept'; claudeArgs.splice(mi, 2); }
const ii = claudeArgs.indexOf('--intercept');
if (ii >= 0) { mode = 'intercept'; claudeArgs.splice(ii, 1); }
const li = claudeArgs.indexOf('--log-only');
if (li >= 0) { mode = 'log'; claudeArgs.splice(li, 1); }
const bi = claudeArgs.indexOf('--block-secrets');
if (bi >= 0) { mode = 'block_secrets'; claudeArgs.splice(bi, 1); }
const mpi = claudeArgs.indexOf('--hardened');
if (mpi >= 0) { mode = 'hardened'; claudeArgs.splice(mpi, 1); }
const prIdx = claudeArgs.indexOf('--preset');
if (prIdx >= 0) {
  const preset = claudeArgs[prIdx + 1] || '';
  claudeArgs.splice(prIdx, 2);
  if      (preset === 'strict')   mode = 'block_secrets';
  else if (preset === 'off')      mode = 'log';
  // 'balanced' or unrecognised → keep current mode (intercept default)
}
const di = claudeArgs.indexOf('--dashboard');
const useDashboard = di >= 0;
if (di >= 0) claudeArgs.splice(di, 1);
const recapIdx = claudeArgs.indexOf('--recap');
const showRecap = recapIdx >= 0;
if (recapIdx >= 0) claudeArgs.splice(recapIdx, 1);
const pi = claudeArgs.indexOf('--port');
if (pi >= 0) {
  const parsed = parseInt(claudeArgs[pi+1], 10);
  if (parsed > 0) { PORT = parsed; PORT_EXPLICIT = true; }
  claudeArgs.splice(pi, 2);
}

// Budget flag: --budget <N> sets a session dollar limit.
const bgtIdx = claudeArgs.indexOf('--budget');
let budget = null;
if (bgtIdx >= 0) {
  const bv = parseFloat(claudeArgs[bgtIdx + 1]);
  if (!isNaN(bv) && bv > 0) budget = bv;
  else process.stderr.write(col.y(`  ⚠  --budget requires a positive number (e.g. --budget 1.00)\n`));
  claudeArgs.splice(bgtIdx, 2);
}

// Verbose flag: --verbose enables live per-request chatter on stderr.
// Default is quiet — Claude Code's TUI redraws the same lines we'd write to,
// and any concurrent stderr writes corrupt the rendering. The exit summary
// (Saved banner) and critical events (BLOCKED, BUDGET EXCEEDED, errors)
// always print; only the per-tool / per-request live ribbon is gated.
const vIdx = claudeArgs.indexOf('--verbose');
const LIVE_VERBOSE = vIdx >= 0;
if (vIdx >= 0) claudeArgs.splice(vIdx, 1);
let sessionCost       = 0;      // running in-memory total for budget enforcement
let budgetWarnFired   = false;   // fires warning at most once per session

const currentRunId = randomUUID();
const sessionTodoStore       = [];          // session-scoped todo list, shared across all runToolLoop calls
const pendingToolInjections  = new Map();   // tool_use_id → distilled content (partial-batch pre-runs)

// Stage 1 architecture: production tool dispatch runs through the canonical
// pipeline. Each Read/Glob/Grep/TodoWrite/TodoRead tool call records one
// audit row to ~/.occasio/pipeline-events.jsonl. The legacy daily ledger
// remains the source of truth for cost/usage; this file complements it with
// per-event tracing and is the foundation for Stage 2's tamper-evident log.
const { createAuditor: _createAuditor } = require('./audit/jsonl-auditor');
// Audit-file override via env var. Used by `occasio harness` to run
// against a scratch chain so the user's real ~/.occasio/pipeline-events
// .jsonl is never touched. When unset, the auditor uses its default location.
const sessionAuditor = _createAuditor(process.env.OCCASIO_AUDIT_FILE || undefined);

// v0.6.6: register a policy-change listener that emits a `policy_loaded`
// audit row whenever the active policy hash transitions to a new value
// (cold start, hot reload, or file-now-absent). The proxy is the only
// long-running process inside this Node instance, so registering once at
// startup is sufficient. The listener honours the v0.6.4 fail-fatal
// contract: an audit-write failure aborts the proxy.
{
  const policyLoader = require('./policy/loader');
  policyLoader.onPolicyChange((change) => {
    const status = sessionAuditor.recordPolicyLoaded(change);
    if (status && status.ok === false) {
      const dropped = status.droppedRow ? JSON.stringify(status.droppedRow) : '(no row attached)';
      process.stderr.write(`\n${col.r('[occasio][audit-fatal]')} policy_loaded write failed: ${status.error?.message}\n`);
      process.stderr.write(`${col.r('[occasio][audit-fatal] dropped row:')} ${dropped}\n`);
      process.stderr.write(`${col.r('[occasio][audit-fatal] proxy aborting; supervisor will restart.')}\n`);
      try { server && server.close && server.close(); } catch { /* ignore */ }
      setTimeout(() => process.exit(1), 250);
    }
  });
  // Trigger first load so the cold-start policy_loaded row lands BEFORE
  // any tool call audit row. load() is idempotent — the proxy and
  // pipeline call it again per request without duplicating the event.
  policyLoader.load();
}

ensureDirs();
fs.writeFileSync(SESSION_FILE, JSON.stringify({
  run_id: currentRunId,
  log_file: getLogFile(),
  budget: budget,
  requests:0, input_tokens:0, output_tokens:0, cost:0,
  blocked:0, intercepted_count:0,
  budget_exceeded_count: 0,
  cache_read_tokens:0, cache_write_tokens:0, cache_savings:0,
  lao_tokens_saved:0, lao_cost_saved:0, tools_local_count:0, tools_mcp_count:0,
  distill_tokens_saved:0, distill_cost_saved:0, secrets_redacted:0, tools_transformed:0,
  mode, start: new Date().toISOString(),
}));

process.stderr.write(col.b(`\n⚡ Occasio v${VERSION}\n`));
const modeLabel = mode === 'block_secrets' ? col.r('block-secrets')
                : mode === 'hardened'      ? col.c('hardened')
                : col.d(mode);
const modeHint  = mode === 'intercept' ? col.d('  (--preset strict to block secrets)')
                : mode === 'hardened'  ? col.d('  (Read/Glob/Grep → unified runtime, distill + secret scan)')
                : '';
process.stderr.write(`  ${col.d('mode:')} ${modeLabel}${modeHint}  ${col.d('log:')} ${col.d(getLogFile())}\n`);
if (budget !== null) {
  process.stderr.write(`  ${col.d('budget:')} ${col.y(`$${budget.toFixed(4)}`)}  ${col.d('(session limit — requests blocked when exceeded)')}\n`);
}
{
  const { execSync: _ex } = require('child_process');
  let _pyOk = false;
  for (const _cmd of ['python', 'python3']) {
    try { _ex(`${_cmd} --version`, { shell: process.platform === 'win32', timeout: 3000, stdio: 'pipe' }); _pyOk = true; break; } catch { /* ignore */ }
  }
  if (!_pyOk) process.stderr.write(col.y(`  ⚠ LAO disabled — Python not found (context trimming inactive)\n`));
}
const isFirstRun = !fs.existsSync(path.join(LOG_DIR, '.registered'));
if (isFirstRun) {
  process.stderr.write(col.g(`\n  Your traffic is now routing through Occasio.\n`));
  process.stderr.write(col.d(`  Run ${col.b('occasio register')} to alias 'claude' directly (one-time).\n`));
  process.stderr.write(col.d(`  Run ${col.b('occasio doctor')} to verify your setup.\n`));
  fs.mkdirSync(LOG_DIR, { recursive: true });
  fs.writeFileSync(path.join(LOG_DIR, '.registered'), '');
}
if (!LIVE_VERBOSE) {
  process.stderr.write(col.d(`  Quiet mode — session summary at exit. Pass ${col.b('--verbose')} for live per-request chatter.\n`));
}
process.stderr.write('\n');

if (useDashboard) require('./dashboard');

// ── Proxy server ───────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  if (req.url === '/api/session' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try { res.end(fs.readFileSync(SESSION_FILE, 'utf8')); } catch { res.end('{}'); }
    return;
  }

  const chunks = []; req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const body   = Buffer.concat(chunks);
    const isMsg  = req.url?.includes('/v1/messages');
    let model = '', fileTokens = [], files = [], secrets = [], blocked = [], reqBody = null;

    if (isMsg && body.length) {
      try {
        const d = JSON.parse(body.toString());
        reqBody    = d;
        model      = d.model || '';
        fileTokens = parseFileTokens(d.messages);          // Level 1
        files      = fileTokens.map(f => f.name);
        secrets    = scanSecrets(body.toString());          // Level 2

        const rp = path.join(process.cwd(), '.occasio', 'rules.json');
        if (fs.existsSync(rp)) {
          try {
            const rules = JSON.parse(fs.readFileSync(rp, 'utf8'));
            blocked = files.filter(f => (rules.block || []).some(p => f.includes(p.replace(/\*\*/g, '').replace(/\*/g, ''))));
          } catch { /* ignore */ }
        }

        const shouldBlock = (mode === 'block_secrets' && secrets.length) || (mode === 'block_rules' && blocked.length);
        if (shouldBlock) {
          const blockedNow = new Date();
          const ts  = blockedNow.toTimeString().slice(0, 8);
          const iso = blockedNow.toISOString();
          process.stderr.write(`\n${col.d(ts)} ${col.r('🛑 BLOCKED')} ${col.d('— nothing sent to Anthropic')}\n`);
          for (const sec of secrets) {
            process.stderr.write(`  ${col.r(`⚠  ${sec.label}`)} ${col.d(`line ${sec.line}`)}\n`);
          }
          if (blocked.length) {
            process.stderr.write(`  ${col.r('📄 rule-blocked:')} ${col.d(blocked.join(', '))}\n`);
          }
          writeBlocked({ ts, model, secrets, blocked, files });
          const blockedEntry = {
            v: LOG_SCHEMA_VERSION, iso, ts, run_id: currentRunId,
            event_type: 'blocked',
            model, input_tokens: 0, output_tokens: 0,
            cache_write_tokens: 0, cache_read_tokens: 0,
            cache_savings: 0, lao_tokens_saved: 0, lao_cost_saved: 0,
            distill_tokens_saved: 0, distill_cost_saved: 0,
            tools_local_count: 0, tools_attempted: 0, cost: 0,
            files, file_tokens: fileTokens, secrets, blocked,
            intercepted: false, tools: [],
          };
          writeLog(blockedEntry);
          updateSession(blockedEntry);
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { type: 'blocked', reason: secrets.length ? secrets[0].label : 'rule', by: 'Occasio' } }));
          return;
        }
      } catch { /* ignore */ }
    }

    // ── Budget enforcement (Stage 2: policy-driven BLOCK) ─────────────────────
    // The decision-to-block is produced by policy.evaluateRequest, which
    // reads ~/.occasio/policy.yml's `block_requests_over_budget` rule.
    // Side effects (verbose print, JSONL log, session counter) stay here as
    // observability/state concerns, separate from the policy decision.
    if (isMsg && budget !== null) {
      const policyEngine = require('./policy/engine');
      const decision = policyEngine.evaluateRequest({ sessionCost, budget });
      if (decision.action === 'BLOCK') {
        const ts  = new Date().toTimeString().slice(0, 8);
        const iso = new Date().toISOString();
        process.stderr.write(`\n${col.d(ts)} ${col.r('🚫 BUDGET EXCEEDED')} — $${sessionCost.toFixed(4)} of $${budget.toFixed(4)} spent this session\n`);
        process.stderr.write(col.d(`  Reset: occasio clear  |  Increase: restart with --budget ${(budget * 2).toFixed(4)}\n`));
        const bEntry = {
          v: LOG_SCHEMA_VERSION, iso, ts, run_id: currentRunId,
          event_type: BUDGET_EXCEEDED_EVENT,
          budget_limit: parseFloat(budget.toFixed(6)),
          budget_spent: parseFloat(sessionCost.toFixed(6)),
          model, input_tokens: 0, output_tokens: 0,
          cache_write_tokens: 0, cache_read_tokens: 0, cache_savings: 0,
          lao_tokens_saved: 0, lao_cost_saved: 0,
          distill_tokens_saved: 0, distill_cost_saved: 0,
          tools_local_count: 0, tools_attempted: 0, cost: 0,
          files, file_tokens: fileTokens, secrets: [], blocked: [],
          intercepted: false, tools: [],
        };
        writeLog(bEntry);
        try {
          const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
          s.budget_exceeded_count = (s.budget_exceeded_count || 0) + 1;
          fs.writeFileSync(SESSION_FILE, JSON.stringify(s));
        } catch { /* ignore */ }
        const synth = decision.syntheticResponse;
        res.writeHead(synth.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(synth.body));
        return;
      }
    }
    // ──────────────────────────────────────────────────────────────────────────

    // ── Partial-batch injection: replace pre-run tool result content ─────────
    // When the previous response was a mixed batch (e.g. [Grep, Bash]),
    // the interceptor pre-ran the interceptable tools and stored distilled results
    // in pendingToolInjections keyed by tool_use_id.  Replace the raw results that
    // Claude Code collected before forwarding this tool_results request to Anthropic.
    if (isMsg && reqBody && pendingToolInjections.size > 0) {
      try {
        const msgs = reqBody.messages;
        if (msgs?.length > 0) {
          const lastMsg = msgs[msgs.length - 1];
          if (lastMsg.role === 'user' && Array.isArray(lastMsg.content)) {
            for (const item of lastMsg.content) {
              if (item.type === 'tool_result' && pendingToolInjections.has(item.tool_use_id)) {
                item.content = pendingToolInjections.get(item.tool_use_id);
                pendingToolInjections.delete(item.tool_use_id);
              }
            }
          }
        }
      } catch { /* ignore */ }
    }
    // ──────────────────────────────────────────────────────────────────────────

    // ── Cache injection + LAO context optimization ────────────────────────────
    let forwardBody = body;
    let laoSaved = 0, laoDropped = [];
    let outboundMessageCount = reqBody?.messages?.length || 0;
    if (isMsg && reqBody) {
      try {
        const b = JSON.parse(JSON.stringify(reqBody));
        // Inject cache_control on system prompt
        if (b.system) {
          if (typeof b.system === 'string') {
            b.system = [{ type: 'text', text: b.system, cache_control: { type: 'ephemeral' } }];
          } else if (Array.isArray(b.system) && b.system.length > 0) {
            const last = b.system[b.system.length - 1];
            if (!last.cache_control) last.cache_control = { type: 'ephemeral' };
          }
        }
        // Inject cache_control on last large user message (tool results / long context)
        if (Array.isArray(b.messages) && b.messages.length >= 2) {
          const lastUser = [...b.messages].reverse().find(m => m.role === 'user');
          if (lastUser && !lastUser.cache_control) {
            if (typeof lastUser.content === 'string' && lastUser.content.length > 1024) {
              lastUser.content = [{ type: 'text', text: lastUser.content, cache_control: { type: 'ephemeral' } }];
            } else if (Array.isArray(lastUser.content) && lastUser.content.length > 0) {
              const lc = lastUser.content[lastUser.content.length - 1];
              if (!lc.cache_control) lc.cache_control = { type: 'ephemeral' };
            }
          }
        }
        // ── Path-2 defense: enforce deny_paths against pre-baked auto-context
        // The tool-call gate in src/policy/engine.js catches deny_paths
        // violations in `tool_use` blocks the cloud model EMITS. But
        // Claude Code (and similar agent runtimes) inject synthetic
        // `tool_use Read` + `tool_result <file content>` pairs into the
        // OUTBOUND body as agentic context before the model has had a
        // chance to call any tool. Those reach the model unless we strip
        // them here. STRIP semantics (not request-BLOCK): mirror the
        // existing redact-secrets TRANSFORM convention so the agent sees
        // structural continuity but the bytes never reach the model.
        const { enforceOutboundDenyPaths, enforceOutboundSecretRedaction, enforceOutboundShaping } = require('./outbound-policy');
        const policyForOutbound = require('./policy/loader').load();
        const outboundResult = enforceOutboundDenyPaths(b, policyForOutbound);
        if (outboundResult.strips.length > 0) {
          b.messages = outboundResult.messages;
          // Emit one BLOCK audit row per stripped tool_result, mirroring the
          // tool-call-time gate's shape so `occasio report` aggregates
          // both paths uniformly under blocked_accesses[].
          const { makeBoundaryEvent } = require('./core/boundary-event');
          for (const strip of outboundResult.strips) {
            const evt = makeBoundaryEvent({
              direction: 'outbound', kind: 'tool_call',
              agent: 'claude-code', protocol: 'anthropic-http',
              sessionId: undefined, runId: currentRunId,
              toolName: /^(Read|read_file)$/i.test(strip.toolName) ? 'read_file'
                      : /^(Glob|find_files)$/i.test(strip.toolName) ? 'find_files'
                      : /^(Grep|grep)$/i.test(strip.toolName)       ? 'grep'
                      : /^(Bash|shell_bash)$/i.test(strip.toolName)  ? 'shell_bash'
                      : /^(PowerShell|shell_powershell)$/i.test(strip.toolName) ? 'shell_powershell'
                      : strip.toolName,
              toolInput: { file_path: strip.path, path: strip.path },
            });
            const status = sessionAuditor.record(
              evt,
              { action: 'BLOCK', reason: 'outbound-context-' + strip.reason,
                policySource: policyForOutbound.deny_paths?.length ? 'user' : 'default' },
              { blocked: true },
            );
            if (status && status.ok === false) {
              const { AuditWriteError } = require('./audit/errors');
              throw new AuditWriteError(status.error, status.droppedRow);
            }
          }
          if (LIVE_VERBOSE) {
            const tsOut = new Date().toTimeString().slice(0, 8);
            const head  = outboundResult.strips.slice(0, 2).map(s => path.basename(s.path)).join(', ');
            const more  = outboundResult.strips.length > 2 ? ` +${outboundResult.strips.length - 2} more` : '';
            process.stderr.write(`${col.d(tsOut)} ${col.r('🛑 outbound-deny')} ${col.d(`stripped: ${head}${more}`)}\n`);
          }
        }
        // ──────────────────────────────────────────────────────────────────────

        // ── Path-2 defense: outbound secret redaction (symmetric with the
        // path-1 TRANSFORM redact-secrets). Fires when
        // redact_secrets_in_tool_results OR block_secrets_in_tool_results is
        // true. Always redacts (never request-blocks) — see outbound-policy.js
        // for the design rationale. One TRANSFORM audit row per redacted
        // tool_result, attributed to the source tool_use when paired.
        const secretResult = enforceOutboundSecretRedaction(b, policyForOutbound);
        if (secretResult.redactions.length > 0) {
          b.messages = secretResult.messages;
          const { makeBoundaryEvent: mkBE } = require('./core/boundary-event');
          for (const r of secretResult.redactions) {
            const canonicalName =
              /^(Read|read_file)$/i.test(r.toolName || '')          ? 'read_file' :
              /^(Glob|find_files)$/i.test(r.toolName || '')         ? 'find_files' :
              /^(Grep|grep)$/i.test(r.toolName || '')               ? 'grep' :
              /^(Bash|shell_bash)$/i.test(r.toolName || '')          ? 'shell_bash' :
              /^(PowerShell|shell_powershell)$/i.test(r.toolName || '') ? 'shell_powershell' :
              (r.toolName || 'tool_result');
            const evt = mkBE({
              direction: 'outbound', kind: 'tool_call',
              agent: 'claude-code', protocol: 'anthropic-http',
              sessionId: undefined, runId: currentRunId,
              toolName: canonicalName,
              toolInput: r.path ? { file_path: r.path, path: r.path } : undefined,
            });
            const status = sessionAuditor.record(
              evt,
              { action: 'TRANSFORM',
                reason: r.reason,
                transform: 'redact-secrets',
                policySource: policyForOutbound.deny_patterns?.length ? 'user' : 'default' },
              { transformed: true, secretsRedacted: new Array(r.secretsRedacted) },
            );
            if (status && status.ok === false) {
              const { AuditWriteError } = require('./audit/errors');
              throw new AuditWriteError(status.error, status.droppedRow);
            }
          }
          if (LIVE_VERBOSE) {
            const tsOut = new Date().toTimeString().slice(0, 8);
            const total = secretResult.redactions.reduce((s, r) => s + r.secretsRedacted, 0);
            process.stderr.write(`${col.d(tsOut)} ${col.r('🛑 outbound-secrets')} ${col.d(`${total} secret(s) redacted in ${secretResult.redactions.length} tool_result(s)`)}\n`);
          }
        }
        // ──────────────────────────────────────────────────────────────────────

        // ── Path-2 defense: outbound output shaping (distill-output +
        // max_output_tokens). Completes the path-1 ↔ path-2 symmetry trio
        // (deny_paths ✓ secrets ✓ shaping ✓). One TRANSFORM audit row per
        // shaped tool_result with the steps that ran in `transform` and
        // saved-tokens recorded.
        const shapingResult = enforceOutboundShaping(b, policyForOutbound);
        if (shapingResult.shapings.length > 0) {
          b.messages = shapingResult.messages;
          const { makeBoundaryEvent: mkBE2 } = require('./core/boundary-event');
          for (const sh of shapingResult.shapings) {
            const canonicalName =
              /^(Read|read_file)$/i.test(sh.toolName || '')          ? 'read_file' :
              /^(Glob|find_files)$/i.test(sh.toolName || '')         ? 'find_files' :
              /^(Grep|grep)$/i.test(sh.toolName || '')               ? 'grep' :
              /^(Bash|shell_bash)$/i.test(sh.toolName || '')          ? 'shell_bash' :
              /^(PowerShell|shell_powershell)$/i.test(sh.toolName || '') ? 'shell_powershell' :
              (sh.toolName || 'tool_result');
            const transformName = sh.reasons.length > 1
              ? sh.reasons.join('+')
              : sh.reasons[0] || 'distill-output';
            const evt = mkBE2({
              direction: 'outbound', kind: 'tool_call',
              agent: 'claude-code', protocol: 'anthropic-http',
              sessionId: undefined, runId: currentRunId,
              toolName: canonicalName,
              toolInput: sh.path ? { file_path: sh.path, path: sh.path } : undefined,
            });
            const status = sessionAuditor.record(
              evt,
              { action: 'TRANSFORM',
                reason: 'outbound-shaping-' + sh.reasons.join('+'),
                transform: transformName,
                policySource: 'user' },
              { transformed: true, savedTokens: sh.savedTokens, label: sh.label },
            );
            if (status && status.ok === false) {
              const { AuditWriteError } = require('./audit/errors');
              throw new AuditWriteError(status.error, status.droppedRow);
            }
          }
          if (LIVE_VERBOSE) {
            const tsOut = new Date().toTimeString().slice(0, 8);
            const total = shapingResult.shapings.reduce((s, r) => s + r.savedTokens, 0);
            process.stderr.write(`${col.d(tsOut)} ${col.r('🛑 outbound-shaping')} ${col.d(`${shapingResult.shapings.length} tool_result(s) shaped, ~${total}t saved`)}\n`);
          }
        }
        // ──────────────────────────────────────────────────────────────────────

        // LAO: trim low-relevance file tool_results when context is large (>20k tokens)
        const lao = await optimizeContext(b, process.cwd());
        if (lao.tokensSaved > 0) {
          b.messages = lao.messages;
          laoSaved   = lao.tokensSaved;
          laoDropped = lao.filesDropped;
        }
        forwardBody = Buffer.from(JSON.stringify(b));
        outboundMessageCount = b.messages?.length ?? outboundMessageCount;
      } catch { /* ignore */ }
    }
    if (laoDropped.length > 0) {
      const ts0  = new Date().toTimeString().slice(0, 8);
      const drop = laoDropped.slice(0, 3).join(', ') + (laoDropped.length > 3 ? ` +${laoDropped.length - 3} more` : '');
      const tStr = laoSaved >= 1000 ? `${(laoSaved / 1000).toFixed(1)}k` : String(laoSaved);
      if (LIVE_VERBOSE) process.stderr.write(`${col.d(ts0)} ${col.c('🔬 LAO')} ${col.d(`trimmed: ${drop} (${tStr} tokens saved)`)}\n`);
    }
    // ──────────────────────────────────────────────────────────────────────────

    // ── Pre-send manifest — show what is about to leave the machine ──────────
    if (isMsg) {
      let outboundTokensEst = 0;
      try {
        // Parse the post-LAO body to get a content-based token estimate.
        // Falls back to body-length / 5 (accounts for JSON framing overhead) if parsing fails.
        outboundTokensEst = roughTokensFromBody(JSON.parse(forwardBody.toString('utf8')));
      } catch { outboundTokensEst = Math.ceil(forwardBody.length / 5); }
      printPreSendManifest(fileTokens, outboundMessageCount, outboundTokensEst);
    }
    // ──────────────────────────────────────────────────────────────────────────

    const hdrs = { ...req.headers, host: ANTHROPIC_REAL, 'content-length': forwardBody.length };
    delete hdrs['accept-encoding'];
    // Strip Occasio-internal routing header so it never leaves the machine.
    delete hdrs[AGENT_HEADER];
    const pr = https.request({ hostname: ANTHROPIC_REAL, port: 443, path: req.url, method: req.method, headers: hdrs }, pres => {
      const rc = []; pres.on('data', c => rc.push(c));
      pres.on('end', async () => {
        let rb = Buffer.concat(rc);
        let intercepted = false;
        let interceptResult = null;
        let toolsAttempted  = 0;
        let fallbackReasons = [];

        // ── Interceptor: short-circuit local-safe tool_use ─────────────────────
        if (isMsg && reqBody && (mode === 'intercept' || mode === 'hardened')) {
          try {
            const { adapter: selectedAdapter, agentId: selectedAgent, source: selectedSource } =
              selectAdapter(req.headers, rb);
            if (LIVE_VERBOSE && selectedAgent !== 'claude-code') {
              process.stderr.write(`  [proxy] routed to ${selectedAgent} adapter (${selectedSource})\n`);
            }
            const result = await selectedAdapter.runToolLoop({
              initialSse: rb,
              reqBody,
              reqHeaders: req.headers,
              verbose:    LIVE_VERBOSE,
              mode,
              todoStore:  sessionTodoStore,
              // Every intercepted tool call produces one audit row.
              auditor:    sessionAuditor,
              sessionId:  currentRunId,
              runId:      currentRunId,
            });
            toolsAttempted  = result.toolsAttempted  || 0;
            fallbackReasons = result.fallbackReasons || [];
            if (result.intercepted) {
              intercepted     = true;
              interceptResult = result;
              rb = Buffer.from(JSON.stringify(result.response), 'utf8');
              if (LIVE_VERBOSE) {
                const ts = new Date().toTimeString().slice(0, 8);
                process.stderr.write('\n');
                for (const t of result.toolsRun) {
                  const label = t.cmd.length > 52 ? t.cmd.slice(0, 52) + '…' : t.cmd;
                  const tok   = t.outputTokens ?? Math.ceil(t.bytes / 4);
                  const tStr  = tok >= 1000 ? `(${(tok / 1000).toFixed(1)}k tokens local)` : '';
                  const dStr  = t.distilled ? col.y(` ✂ ${t.distillLabel}`) : '';
                  process.stderr.write(`${col.d(ts)} ${col.g('⚡')} ${col.b(label)} ${col.d(tStr)}${dStr}\n`);
                }
              }
            } else if (result.partialIntercept) {
              // Mixed batch: pre-ran the interceptable subset, storing results for injection.
              // The original SSE response passes through to Claude Code unchanged.
              for (const pr of result.partialResults) {
                pendingToolInjections.set(pr.tool_use_id, pr.content);
              }
              if (LIVE_VERBOSE) {
                const ts = new Date().toTimeString().slice(0, 8);
                process.stderr.write('\n');
                for (const t of result.toolsRun) {
                  const label = t.cmd.length > 52 ? t.cmd.slice(0, 52) + '…' : t.cmd;
                  const tok   = t.outputTokens ?? Math.ceil(t.bytes / 4);
                  const tStr  = tok >= 1000 ? `(${(tok / 1000).toFixed(1)}k tokens local)` : '';
                  const dStr  = t.distilled ? col.y(` ✂ ${t.distillLabel}`) : '';
                  process.stderr.write(`${col.d(ts)} ${col.c('⚡~')} ${col.b(label)} ${col.d(tStr)}${dStr}\n`);
                }
              }
              toolsAttempted  = result.toolsAttempted  || 0;
              fallbackReasons = result.fallbackReasons || [];
              interceptResult = result;  // carry toolsRun for distill accounting in entry below
            } else if (result.fallbackReason) {
              const ts = new Date().toTimeString().slice(0, 8);
              let hint = '';
              if (result.fallbackReason === 'max rounds exceeded')
                hint = ' (interceptor limit reached — Claude Code will handle it)';
              else if (result.fallbackReason.startsWith('tool not handled:'))
                hint = ' (Claude Code will handle it)';
              else if (result.fallbackReason.startsWith('mid-loop tool not handled:'))
                hint = ' (Claude Code will handle remaining rounds)';
              else if (result.fallbackReason.startsWith('Anthropic '))
                hint = ' (will retry via Claude)';
              else if (result.fallbackReason.startsWith('secret in tool result'))
                hint = ' (proxy scanner will handle it)';
              if (LIVE_VERBOSE) process.stderr.write(`${col.d(ts)} ${col.y('↩ fallback:')} ${col.d(result.fallbackReason + hint)}\n`);
              // Counter-bug fix: if the fallback carries toolsRun (mid-loop
              // hit after some tools already ran successfully), preserve them
              // for the per-request log so the count isn't silently discarded.
              if (Array.isArray(result.toolsRun) && result.toolsRun.length) {
                interceptResult = result;
              }
            }
          } catch (e) {
            // v0.6.4: an audit-write failure is session-fatal. The dropped row
            // is logged to stderr (so a supervisor can recover it forensically),
            // the listening socket is closed so no further requests arrive, and
            // the process exits non-zero. The supervisor templates under
            // bin/supervisor/ restart us. This trades a graceful degradation
            // for the stronger guarantee that no successful tool call ever
            // exists without a matching audit row.
            if (e && e.name === 'AuditWriteError') {
              const dropped = e.droppedRow ? JSON.stringify(e.droppedRow) : '(no row attached)';
              process.stderr.write(`\n${col.r('[occasio][audit-fatal]')} ${e.message}\n`);
              process.stderr.write(`${col.r('[occasio][audit-fatal] dropped row:')} ${dropped}\n`);
              process.stderr.write(`${col.r('[occasio][audit-fatal] proxy aborting; supervisor will restart.')}\n`);
              try { server && server.close && server.close(); } catch { /* ignore */ }
              setTimeout(() => process.exit(1), 250);
              return;
            }
            process.stderr.write(`  ${col.r('[interceptor error]')} ${e.message}\n`);
          }
        }

        if (isMsg) {
          let inp = 0, out = 0, cacheWrite = 0, cacheRead = 0;
          try {
            const rbStr = rb.toString();
            try {
              const rd = JSON.parse(rbStr);
              inp        = rd.usage?.input_tokens                  || 0;
              out        = rd.usage?.output_tokens                 || 0;
              cacheWrite = rd.usage?.cache_creation_input_tokens   || 0;
              cacheRead  = rd.usage?.cache_read_input_tokens       || 0;
            } catch {
              for (const m of rbStr.matchAll(/data:\s*({[^\n]+})/g)) {
                try {
                  const d = JSON.parse(m[1]);
                  if (d.usage) {
                    inp        = d.usage.input_tokens                || inp;
                    out        = d.usage.output_tokens               || out;
                    cacheWrite = d.usage.cache_creation_input_tokens || cacheWrite;
                    cacheRead  = d.usage.cache_read_input_tokens     || cacheRead;
                  }
                  if (d.type === 'message_delta' && d.usage) out = d.usage.output_tokens || out;
                } catch { /* ignore */ }
              }
            }
          } catch { /* ignore */ }

          // When the interceptor ran, Anthropic was billed for N calls:
          //   call #1  → initial tool_use round  (toolCallUsage)
          //   calls #2…N-1 → middle rounds if tool chain > 2 deep (middleRoundsUsage)
          //   call #N  → final response            (inp/out from rb)
          // Sum all non-final rounds so the reported cost is accurate for any chain length.
          const toolCallUsage    = intercepted ? (interceptResult?.toolCallUsage    || { input_tokens: 0, output_tokens: 0 }) : null;
          const middleRoundsUsage = intercepted ? (interceptResult?.middleRoundsUsage || { input_tokens: 0, output_tokens: 0 }) : null;
          const allPriorTokensIn  = (toolCallUsage?.input_tokens  || 0) + (middleRoundsUsage?.input_tokens  || 0);
          const allPriorTokensOut = (toolCallUsage?.output_tokens || 0) + (middleRoundsUsage?.output_tokens || 0);
          const toolCallCost      = toolCallUsage ? calcCost(model, allPriorTokensIn, allPriorTokensOut) : 0;
          const cost          = calcCost(model, inp, out, cacheWrite, cacheRead) + toolCallCost;
          const cacheSavings  = calcCacheSavings(model, cacheRead);
          const allToolsRun       = interceptResult?.toolsRun || [];
          const toolsMcpPrimary   = allToolsRun.filter(t => t.mcpPath).length;
          const toolsLocalCount   = allToolsRun.length - toolsMcpPrimary;
          const laoTokensSaved  = laoSaved;
          const laoSavings      = laoTokensSaved > 0 ? calcCost(model, laoTokensSaved, 0) : 0;

          const entryTime = new Date();
          const ts  = entryTime.toTimeString().slice(0, 8);
          const iso = entryTime.toISOString();
          const ms  = model.replace('claude-', '').replace(/-\d{8}$/, '');
          const icon = intercepted ? col.g('📦') : (secrets.length || blocked.length) ? col.r('📤') : col.c('📤');
          const cacheStr = cacheRead > 0
            ? col.d(` · cache ${(cacheRead / 1000).toFixed(1)}k (-$${cacheSavings.toFixed(4)})`)
            : '';

          if (LIVE_VERBOSE) process.stderr.write(`\n${col.d(ts)} ${icon} ${col.y(`${inp.toLocaleString()} in / ${out.toLocaleString()} out`)} ${col.d(`$${cost.toFixed(4)} · ${ms}`)}${cacheStr}\n`);

          // Level 2: secret with line number in terminal
          for (const sec of secrets) {
            process.stderr.write(`  ${col.r(`⚠️  ${sec.label} (line ${sec.line})`)}\n`);
          }

          // Level 2b: secrets found in interceptor tool results (file reads / cmd output).
          // These never pass through the proxy-level scanner, so we scan them here.
          // In intercept mode they are forwarded — this warning and log entry make it visible.
          // In block_secrets mode the interceptor already aborted before reaching here.
          const toolResultSecrets = intercepted ? (interceptResult?.secretsInResults || []) : [];
          for (const sec of toolResultSecrets) {
            process.stderr.write(`  ${col.r(`⚠️  ${sec.label} in tool result (line ${sec.line})`)}\n`);
          }

          // Level 3: tool runs from interceptor
          const tools = interceptResult?.toolsRun || [];

          const distillTokensSaved = tools.reduce((s, t) => s + (t.distillSaved || 0), 0);
          const distillSavings     = distillTokensSaved > 0 ? calcCost(model, distillTokensSaved, 0) : 0;
          const secretsRedacted    = tools.reduce((s, t) => s + (t.secretsRedacted || 0), 0);
          const toolsTransformed   = tools.filter(t => t.transformed).length;

          // Same-call payload counterfactual: what this request would have cost without
          // distillation and LAO trimming (same-call effect only, not cross-request compounding).
          // Prompt cache savings are NOT included — shown separately as exact.
          const payloadCfCost = parseFloat((cost + distillSavings + laoSavings).toFixed(6));

          const eventType = intercepted                        ? 'local_only'
                          : interceptResult?.partialIntercept  ? 'partial_intercept'
                          : laoTokensSaved > 0                 ? 'trimmed'
                          :                                      'cloud_sent';
          const entry = {
            v:                   LOG_SCHEMA_VERSION,
            iso, ts, run_id: currentRunId,
            cwd:                 SESSION_CWD,
            event_type:          eventType,
            model,
            input_tokens:        inp,
            output_tokens:       out,
            cache_write_tokens:  cacheWrite,
            cache_read_tokens:   cacheRead,
            cache_savings:       parseFloat(cacheSavings.toFixed(6)),
            lao_tokens_saved:      laoTokensSaved,
            lao_cost_saved:        parseFloat(laoSavings.toFixed(6)),
            distill_tokens_saved:  distillTokensSaved,
            distill_cost_saved:    parseFloat(distillSavings.toFixed(6)),
            payload_counterfactual_cost: payloadCfCost,
            tools_local_count:     toolsLocalCount,
            tools_mcp_count:       toolsMcpPrimary,
            tools_attempted:       toolsAttempted,
            fallback_reasons:      fallbackReasons.length ? fallbackReasons : undefined,
            cost:                  parseFloat(cost.toFixed(6)),
            files,
            file_tokens:         fileTokens,
            lao_dropped:         laoDropped,
            outbound_message_count: outboundMessageCount || undefined,
            secrets:             [...secrets, ...toolResultSecrets],
            secrets_redacted:    secretsRedacted  || undefined,
            tools_transformed:   toolsTransformed || undefined,
            blocked,
            intercepted,
            tools,
          };
          writeLog(entry); updateSession(entry);
          sessionCost += cost;

          // Budget warning: fires once when spend crosses 80 % of budget
          if (budget !== null && !budgetWarnFired) {
            const { warnNow, exceeded: nowExceeded, pct } = budgetStatus(sessionCost, budget);
            if (warnNow) {
              budgetWarnFired = true;
              const pctStr = Math.round(pct * 100);
              if (nowExceeded) {
                process.stderr.write(col.r(`\n  🚫 Budget limit reached: $${sessionCost.toFixed(4)} of $${budget.toFixed(4)} — next request will be blocked.\n`));
              } else {
                process.stderr.write(col.y(`\n  ⚠  Budget at ${pctStr}%: $${sessionCost.toFixed(4)} of $${budget.toFixed(4)}\n`));
                process.stderr.write(col.d(`     Next request will be blocked at $${budget.toFixed(4)}. Reset: occasio clear\n`));
              }
            }
          }

          // Persist raw distilled output so it can be inspected later
          const distilledTools = tools.filter(t => t.distilled && t.rawContent);
          for (const t of distilledTools) {
            writeDistilledRaw({
              iso, run_id: currentRunId,
              cmd: t.cmd, rawBytes: t.bytes,
              label: t.distillLabel,
              rawContent: t.rawContent,
            });
          }
        }

        const rh = intercepted
          ? { 'content-type': 'application/json' }
          : { ...pres.headers };
        if (!intercepted) { delete rh['content-encoding']; delete rh['transfer-encoding']; }
        rh['content-length'] = rb.length.toString();
        res.writeHead(intercepted ? 200 : pres.statusCode, rh);
        res.end(rb);
      });
    });
    pr.on('error', e => { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
    pr.end(forwardBody);
  });
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') {
    process.stderr.write(col.r(`\n❌ Port ${PORT} already in use. Kill the old process first or omit --port / OCCASIO_PORT to let the OS auto-assign:\n`));
    process.stderr.write(col.d(`   netstat -ano | findstr :${PORT}  → then: taskkill /PID <pid> /F\n\n`));
  } else {
    process.stderr.write(col.r(`\n❌ ${e.message}\n`));
  }
  process.exit(1);
});

server.listen(PORT, '127.0.0.1', () => {
  PORT = server.address().port;
  process.stderr.write(col.d(`occasio proxy listening on 127.0.0.1:${PORT}\n`));

  // Best-effort: print a 3-line recap of the previous session so the user
  // (and via screen-context, the agent itself) has a memory anchor before
  // typing the next prompt. Silent if no prior session in this cwd.
  // Disable with --no-recap.
  if (showRecap) {
    try { printSessionRecapBanner(); } catch { /* never block startup */ }
  }

  const env = { ...process.env, ANTHROPIC_BASE_URL: `http://localhost:${PORT}` };
  // On Windows, npm installs binaries as .cmd wrappers (claude.cmd).
  // spawn() without shell:true calls CreateProcess directly, which won't
  // execute .cmd files — claude would silently fail to start.
  //
  // shell:true on Windows joins the args array with spaces and runs the
  // result through `cmd.exe /d /s /c "<line>"`. Node's auto-quoting is
  // unreliable for args containing spaces (the prompt passed via --print
  // gets truncated at the first space). Build the command line ourselves
  // with explicit quoting and pass a single pre-quoted string when
  // shell:true is in play.
  let cmdLine, spawnArgs;
  if (process.platform === 'win32') {
    const quote = (a) => /[\s"^&|<>]/.test(a)
      ? `"${String(a).replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`
      : String(a);
    cmdLine   = ['claude', ...claudeArgs.map(quote)].join(' ');
    spawnArgs = [];
  } else {
    cmdLine   = 'claude';
    spawnArgs = claudeArgs;
  }
  const claude = spawn(cmdLine, spawnArgs, {
    env,
    stdio: ['inherit', 'inherit', 'inherit'],
    shell: process.platform === 'win32',
  });

  claude.on('exit', code => {
    server.close();
    try {
      const s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
      const cacheSavX = s.cache_savings      || 0;
      const laoSavX   = s.lao_cost_saved     || 0;
      const distSavX  = s.distill_cost_saved || 0;
      const payloadX  = laoSavX + distSavX;
      const { savings: contextX } =
        calcCompoundingSavings(s.run_id, s.log_file || getLogFile(), s.model || '');
      const totalSavX  = payloadX + contextX + cacheSavX;
      const broaderCfX = (s.cost || 0) + totalSavX;
      const savedPctX  = broaderCfX > 0.00001 ? Math.round(totalSavX / broaderCfX * 100) : 0;

      process.stderr.write(col.b('\n─── Session ────────────────────────────\n'));

      // Headline
      if (totalSavX > 0.00001) {
        process.stderr.write(col.g(`  Saved:       $${totalSavX.toFixed(4)}`) +
          col.d(`  (${savedPctX}% off — would have cost $${broaderCfX.toFixed(4)})\n`));
      } else {
        process.stderr.write(col.d(`  Saved:       $0.0000  (no interceptable tool calls in this session yet)\n`));
      }
      process.stderr.write(col.y(`  Cost:        $${s.cost.toFixed(4)}\n`));

      // Plain-English coverage. See status command for clamping rationale.
      const localCnt   = s.tools_local_count || 0;
      const mcpCnt     = s.tools_mcp_count   || 0;
      const attempted  = s.tools_attempted   || 0;
      const totalLocal = localCnt + mcpCnt;
      const denom      = Math.max(attempted, totalLocal);
      if (denom > 0) {
        const cpct = Math.round(totalLocal / denom * 100);
        const cColor = cpct >= 80 ? col.g : cpct >= 50 ? col.y : col.r;
        process.stderr.write(cColor(`  Ran locally: ${totalLocal} of ${denom} tool calls (${cpct}%)\n`));
      }
      if (s.blocked) process.stderr.write(col.r(`  Blocked:     ${s.blocked} secrets\n`));
      if (s.secrets_redacted) process.stderr.write(col.c(`  Redacted:    ${s.secrets_redacted} secret${s.secrets_redacted !== 1 ? 's' : ''} in tool results\n`));
      if (s.tools_transformed) process.stderr.write(col.c(`  Transforms:  ${s.tools_transformed} tool result${s.tools_transformed !== 1 ? 's' : ''} shaped\n`));
      if (s.budget != null) {
        const pct = Math.min(999, Math.round((s.cost || 0) / s.budget * 100));
        const budgetStr = fmtBudget(s.cost || 0, s.budget);
        const budgetColor = pct >= 100 ? col.r : pct >= 80 ? col.y : col.g;
        process.stderr.write(budgetColor(`  Budget:      ${budgetStr}\n`));
        if (s.budget_exceeded_count) process.stderr.write(col.r(`  BudgetBlk:   ${s.budget_exceeded_count} request(s) blocked\n`));
      }

      // Detail
      process.stderr.write(col.d(`  ────\n`));
      process.stderr.write(col.d(`  Requests:    ${s.requests} · ${(s.input_tokens/1000).toFixed(1)}k tokens in · ${(s.output_tokens/1000).toFixed(1)}k out\n`));
      if (totalSavX > 0.00001) {
        const parts = [];
        if (payloadX  > 0.00001) parts.push(`$${payloadX.toFixed(4)} payload`);
        if (contextX  > 0.00001) parts.push(`$${contextX.toFixed(4)} context`);
        if (cacheSavX > 0.00001) parts.push(`$${cacheSavX.toFixed(4)} cache`);
        if (parts.length) process.stderr.write(col.d(`  Breakdown:   ${parts.join(' + ')}\n`));
      }
      process.stderr.write('────────────────────────────────────────\n\n');
    } catch { /* ignore */ }
    process.exit(code || 0);
  });

  claude.on('error', () => {
    process.stderr.write(col.r('\n❌ claude not found — is Claude Code installed?\n'));
    process.stderr.write(col.d('   Install: https://claude.ai/download  or  npm install -g @anthropic-ai/claude-code\n'));
    server.close(); process.exit(1);
  });
});
