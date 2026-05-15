'use strict';

/**
 * mcp-experiment.js — Reads both log streams and reports MCP vs. built-in adoption.
 *
 * Usage:
 *   node src/mcp-experiment.js              — stats for today's session
 *   node src/mcp-experiment.js --clear      — wipe mcp-experiment.jsonl and restart count
 *   node src/mcp-experiment.js --raw        — dump raw MCP log entries
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

const LOG_DIR     = path.join(os.homedir(), '.occasio');
const MCP_LOG     = path.join(LOG_DIR, 'mcp-experiment.jsonl');
const TODAY       = new Date().toISOString().slice(0, 10);
const SESSION_LOG = path.join(LOG_DIR, 'logs', `${TODAY}.jsonl`);

function runStats() {
  // ── MCP path: read mcp-experiment.jsonl ──────────────────────────────────────
  let mcpEntries = [];
  try {
    mcpEntries = fs.readFileSync(MCP_LOG, 'utf8').trim().split('\n')
      .filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { /* ignore */ }

  // ── Built-in path: read today's session log, count intercepted Read/Glob/Grep ─
  let builtinTools = [];
  try {
    const lines = fs.readFileSync(SESSION_LOG, 'utf8').trim().split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        const tools = (entry.tools || []).filter(t => ['Read', 'Glob', 'Grep'].includes(t.tool));
        builtinTools.push(...tools);
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }

  const mcpTotal     = mcpEntries.length;
  const builtinTotal = builtinTools.length;
  const total        = mcpTotal + builtinTotal;
  const mcpPct       = total > 0 ? (mcpTotal / total * 100).toFixed(1) : '—';

  // Aggregate hardening metrics (added in Slice 2)
  const mcpDistilled   = mcpEntries.filter(e => e.distillSaved > 0).length;
  const mcpDistillSaved = mcpEntries.reduce((s, e) => s + (e.distillSaved || 0), 0);
  const mcpSecretsFound = mcpEntries.reduce((s, e) => s + (e.secretsFound || 0), 0);

  console.log(col.b('\n⚡ Occasio MCP Experiment\n'));

  if (total === 0) {
    console.log(col.d('  No tool calls recorded yet. Run a Claude session first.\n'));
    console.log(col.d('  Tip: ask Claude to read a file, search code, or list files.\n'));
    return;
  }

  console.log(`  MCP path    (mcp__lf__*)          ${col.g(String(mcpTotal).padStart(4))} calls`);
  console.log(`  Built-in    (Read / Glob / Grep)   ${col.c(String(builtinTotal).padStart(4))} calls`);
  console.log(`  Total                              ${String(total).padStart(4)} calls`);
  console.log('');
  console.log(`  MCP adoption rate: ${col.b(mcpPct + '%')}`);

  // MCP hardening metrics (distillation + secret scanning)
  if (mcpTotal > 0) {
    if (mcpDistilled > 0) {
      console.log(col.d(`  MCP distilled: ${mcpDistilled} calls, ${mcpDistillSaved} tokens saved`));
    }
    if (mcpSecretsFound > 0) {
      console.log(col.r(`  MCP secrets:   ${mcpSecretsFound} credential pattern(s) detected`));
    }
  }

  // Breakdown by tool
  if (mcpTotal > 0) {
    console.log(col.d('\n  MCP breakdown:'));
    const byTool = {};
    for (const e of mcpEntries) byTool[e.tool] = (byTool[e.tool] || 0) + 1;
    for (const [t, n] of Object.entries(byTool)) {
      console.log(col.d(`    ${t.padEnd(14)} ${n}`));
    }
  }
  if (builtinTotal > 0) {
    console.log(col.d('\n  Built-in breakdown:'));
    const byTool = {};
    for (const e of builtinTools) byTool[e.tool] = (byTool[e.tool] || 0) + 1;
    for (const [t, n] of Object.entries(byTool)) {
      console.log(col.d(`    ${t.padEnd(14)} ${n}`));
    }
  }

  // Verdict
  console.log('');
  const pct = parseFloat(mcpPct);
  if (isNaN(pct)) {
    console.log(col.d('  Not enough data.'));
  } else if (pct >= 70) {
    console.log(col.g('  ✓ MCP adoption is strong — MCP-primary architecture is viable.'));
  } else if (pct >= 30) {
    console.log(col.y('  ~ Mixed adoption — MCP usable as supplement, interceptor still needed.'));
  } else {
    console.log(col.r('  ✗ MCP adoption too low — interceptor must remain primary path.'));
  }
  console.log('');
}

function runClear() {
  try { fs.unlinkSync(MCP_LOG); console.log(col.g('✓ mcp-experiment.jsonl cleared')); } catch { /* ignore */ }
}

function runRaw() {
  try {
    const entries = fs.readFileSync(MCP_LOG, 'utf8').trim().split('\n').filter(Boolean);
    if (entries.length === 0) { console.log('No MCP calls recorded.'); return; }
    console.log(col.b(`\n${entries.length} MCP calls:\n`));
    entries.forEach((l, i) => {
      try {
        const e = JSON.parse(l);
        console.log(`  [${i}] ${e.ts}  ${col.c(e.tool)}  ${col.d(JSON.stringify(e).slice(0, 120))}`);
      } catch { console.log(`  [${i}] ${l.slice(0, 120)}`); }
    });
    console.log('');
  } catch { console.log('No MCP log found.'); }
}

const args = process.argv.slice(2);
if (args.includes('--clear')) runClear();
else if (args.includes('--raw')) runRaw();
else runStats();
