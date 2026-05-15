#!/usr/bin/env node
'use strict';

/**
 * edr-synthetic.js — generate a synthetic pipeline-events.jsonl for EDR
 * calibration and false-positive testing.
 *
 * Unlike calibrate-anomaly-detectors.js (which slides a window over a real
 * chain), this script *fabricates* a chain matching one of four profiles
 * and emits the result to stdout or a file. Pair with `occasio anomalies
 * --chain <file>` to see what each detector does on each profile.
 *
 * Profiles
 *   low-activity   ~1 tool-call / 5 min over the window, no redactions, no
 *                  BLOCKs. Represents an idle coding session. None of the
 *                  four built-in detectors should fire HIGH on this.
 *   bursty         60 distinct file reads inside a 5-minute sub-window
 *                  during an otherwise quiet day. file-read-volume should
 *                  flag this; the others should stay quiet.
 *   secret-heavy   Periodic stretches of redactions (8-15 per window),
 *                  mixed in with normal reads. secret-redact-rate should
 *                  fire MEDIUM/HIGH on the spike windows.
 *   denied-heavy   12 BLOCK rows clustered in the last 15 minutes.
 *                  deny-rate should fire HIGH; others quiet.
 *
 * Usage
 *   node scripts/edr-synthetic.js --profile bursty --rows 1500 --out /tmp/c.jsonl
 *   node scripts/edr-synthetic.js --profile low-activity --out -    # stdout
 *
 * The generated chain is hash-chained (prev_hash + hash on every row) so
 * `occasio audit verify --file <path>` returns clean.
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const GENESIS = '0'.repeat(64);

function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function flag(args, name, def) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
}

function rand(seedRef) {
  // Cheap LCG so runs are reproducible given a seed.
  seedRef.s = (seedRef.s * 1664525 + 1013904223) >>> 0;
  return seedRef.s / 0x100000000;
}

function pick(seedRef, arr) {
  return arr[Math.floor(rand(seedRef) * arr.length)];
}

// Build a single audit row in the same field order as
// src/audit/jsonl-auditor.js#recordInner, so the chain is verifier-clean.
function makeRow({ ts, sessionId, runId, toolName, toolInput, action, reason, secretsRedacted, prevHash }) {
  const row = {
    audit_schema: 1,
    ts,
    event_id:      crypto.randomUUID(),
    session_id:    sessionId,
    run_id:        runId,
    agent:         'claude-code',
    protocol:      'anthropic',
    direction:     'request',
    kind:          'tool_call',
    tool_name:     toolName,
    tool_inputs:   toolInput,
    action,
    reason:        reason || (action === 'BLOCK' ? 'policy_block' : 'pass'),
    policy_source: 'synthetic',
    executor:      action === 'BLOCK' ? undefined : 'local',
    transform:     secretsRedacted ? 'redact-secrets' : undefined,
    result_kind:   action === 'BLOCK' ? 'block' : (secretsRedacted ? 'transform' : 'local'),
    exit_code:     action === 'BLOCK' ? undefined : 0,
    secrets_redacted: secretsRedacted || undefined,
    distilled:     undefined,
    tokens_saved:  undefined,
    prev_hash:     prevHash,
  };
  row.hash = sha256hex(JSON.stringify(row));
  return row;
}

// ── profiles ────────────────────────────────────────────────────────────────

function genLowActivity({ rows, endMs, seedRef }) {
  // 1 tool-call every ~5 min. Reads, occasional grep. No BLOCKs, no redactions.
  const events = [];
  const stepMs = 5 * 60 * 1000;
  for (let i = 0; i < rows; i++) {
    const ts = new Date(endMs - (rows - i) * stepMs).toISOString();
    const tool = pick(seedRef, ['Read', 'Glob', 'Grep']);
    events.push({
      ts,
      toolName: tool,
      toolInput: tool === 'Read' ? { file_path: `/repo/src/file-${i % 5}.js` }
        : tool === 'Glob' ? { pattern: '**/*.js' }
        : { pattern: 'TODO', path: '/repo/src' },
      action: 'LOCAL',
    });
  }
  return events;
}

function genBursty({ rows, endMs, seedRef }) {
  // Quiet day, then a 5-minute spike of distinct reads near the end.
  const events = [];
  const stepMs = 10 * 60 * 1000;
  for (let i = 0; i < rows - 60; i++) {
    const ts = new Date(endMs - (rows - i) * stepMs).toISOString();
    events.push({
      ts,
      toolName: 'Read',
      toolInput: { file_path: `/repo/src/old-${i % 8}.js` },
      action: 'LOCAL',
    });
  }
  const burstStart = endMs - 5 * 60 * 1000;
  for (let i = 0; i < 60; i++) {
    const ts = new Date(burstStart + i * 4000).toISOString();
    events.push({
      ts,
      toolName: 'Read',
      toolInput: { file_path: `/repo/secrets/recon-${i}.js` },
      action: 'LOCAL',
    });
  }
  events.sort((a, b) => a.ts.localeCompare(b.ts));
  return events;
}

function genSecretHeavy({ rows, endMs, seedRef }) {
  // Periodic redaction stretches. Every ~50 rows, 10 in a row are redacted.
  const events = [];
  const stepMs = 60 * 1000;
  for (let i = 0; i < rows; i++) {
    const ts = new Date(endMs - (rows - i) * stepMs).toISOString();
    const inRedactBurst = Math.floor(i / 50) % 5 === 4 && (i % 50) < 12;
    events.push({
      ts,
      toolName: 'Read',
      toolInput: { file_path: `/repo/src/file-${i % 7}.js` },
      action: 'TRANSFORM',
      secretsRedacted: inRedactBurst ? 1 + Math.floor(rand(seedRef) * 3) : 0,
    });
  }
  return events;
}

function genDeniedHeavy({ rows, endMs, seedRef }) {
  // Clean history, then 12 BLOCKs clustered in the final 15 minutes.
  const events = [];
  const stepMs = 5 * 60 * 1000;
  for (let i = 0; i < rows - 12; i++) {
    const ts = new Date(endMs - (rows - i) * stepMs).toISOString();
    events.push({
      ts,
      toolName: 'Read',
      toolInput: { file_path: `/repo/src/file-${i % 4}.js` },
      action: 'LOCAL',
    });
  }
  const blockStart = endMs - 14 * 60 * 1000;
  for (let i = 0; i < 12; i++) {
    const ts = new Date(blockStart + i * 30 * 1000).toISOString();
    events.push({
      ts,
      toolName: 'Bash',
      toolInput: { command: `cat /etc/shadow # try-${i}` },
      action: 'BLOCK',
      reason: 'policy:deny_paths',
    });
  }
  events.sort((a, b) => a.ts.localeCompare(b.ts));
  return events;
}

const PROFILES = {
  'low-activity':  genLowActivity,
  'bursty':        genBursty,
  'secret-heavy':  genSecretHeavy,
  'denied-heavy':  genDeniedHeavy,
};

function generate({ profile, rows, endMs, seed }) {
  const gen = PROFILES[profile];
  if (!gen) throw new Error(`unknown profile: ${profile} (try: ${Object.keys(PROFILES).join('|')})`);
  const seedRef = { s: seed >>> 0 };
  const events = gen({ rows, endMs, seedRef });
  const sessionId = crypto.randomUUID();
  const runId     = crypto.randomUUID();
  let prevHash = GENESIS;
  const out = [];
  for (const e of events) {
    const row = makeRow({ ...e, sessionId, runId, prevHash });
    prevHash = row.hash;
    out.push(JSON.stringify(row));
  }
  return out.join('\n') + '\n';
}

function main(argv) {
  const args = argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      'Usage: edr-synthetic.js --profile <name> [--rows N] [--out PATH|-] [--seed N] [--end ISO]\n' +
      `Profiles: ${Object.keys(PROFILES).join(', ')}\n`);
    return 0;
  }
  const profile = flag(args, '--profile', 'low-activity');
  const rows    = parseInt(flag(args, '--rows', '500'), 10);
  const seed    = parseInt(flag(args, '--seed', '1'), 10);
  const endIso  = flag(args, '--end', null);
  const endMs   = endIso ? Date.parse(endIso) : Date.now();
  const outArg  = flag(args, '--out', '-');

  const content = generate({ profile, rows, endMs, seed });
  if (outArg === '-' || !outArg) {
    process.stdout.write(content);
  } else {
    fs.mkdirSync(path.dirname(path.resolve(outArg)), { recursive: true });
    fs.writeFileSync(outArg, content);
    process.stderr.write(`wrote ${rows} rows to ${outArg} (profile=${profile})\n`);
  }
  return 0;
}

if (require.main === module) {
  process.exit(main(process.argv));
}

module.exports = { generate, PROFILES };
