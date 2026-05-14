'use strict';

/**
 * demo/anomalies-demo.js — `occasio demo anomalies`
 *
 * Production CLI command, first-class user-facing feature. See
 * src/demo/README.md for the folder convention. Builds a synthetic
 * adversarial audit chain in a temp dir and runs all four anomaly
 * detectors against it. Each detector is designed to fire on exactly
 * one of the four written patterns:
 *
 *   deny-rate           pattern: 12 BLOCK rows in the recent window
 *                                (vs. a quiet historical baseline)
 *   file-read-volume    pattern: 60 distinct file paths read in window
 *                                (vs. historical p95 ≈ 5)
 *   unknown-tool-input  pattern: Bash invoked with novel `env` key
 *                                (after 60 historical "Bash {command, cwd}" rows)
 *   secret-redact-rate  pattern: 3 redacted-secret rows in window
 *                                (vs. zero in 250 historical rows)
 *
 * Never touches ~/.occasio — uses os.tmpdir() throughout.
 *
 * Used by:
 *   - Smoke-testing the EDR layer end-to-end
 *   - First-time demo / "show me what would have fired in our last shift"
 *   - Reference for what a real adversarial-activity chain shape looks like
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const { runDetectors, DEFAULT_WINDOW_MS } = require('../anomaly');

const C = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

const SEV_COLOR = { high: C.r, medium: C.y, low: C.c };

const GENESIS  = '0'.repeat(64);
const RUN_ID   = '12345678-1234-1234-1234-123456789abc';

function appendRow(file, prevHash, row) {
  const withPrev = { ...row, prev_hash: prevHash };
  const hash = crypto.createHash('sha256').update(JSON.stringify(withPrev), 'utf8').digest('hex');
  const full = { ...withPrev, hash };
  fs.appendFileSync(file, JSON.stringify(full) + '\n');
  return hash;
}

/**
 * Build the adversarial chain. Returns the file path + the "now" anchor we
 * should evaluate against (cleaner than relying on wall clock).
 *
 * Timeline:
 *   t = NOW - 3h ...... NOW - 20m  → historical baseline (quiet)
 *   t = NOW - 10m ..... NOW         → window (the anomalies live here)
 */
function buildAdversarialChain(chainFile) {
  fs.writeFileSync(chainFile, '');
  const NOW = Date.parse('2026-05-14T16:00:00.000Z');
  const tIso = (msAgo) => new Date(NOW - msAgo).toISOString();
  let prev = GENESIS;

  // ── Historical baseline ────────────────────────────────────────────────
  // 300 quiet rows over 3h: tool reads against a small file pool, no BLOCKs,
  // no redactions, all Bash calls use only { command, cwd } keys.
  const baselinePaths = ['a.js', 'b.js', 'c.js', 'd.js', 'e.js'];
  for (let i = 0; i < 300; i++) {
    const msAgo = 3 * 60 * 60 * 1000 - i * Math.floor((3 * 60 * 60 * 1000 - 20 * 60 * 1000) / 300);
    if (i % 3 === 0) {
      prev = appendRow(chainFile, prev, {
        ts: tIso(msAgo),
        kind: 'tool_call', tool_name: 'Read', action: 'PASS',
        tool_inputs: { path: 'src/' + baselinePaths[i % baselinePaths.length] },
        run_id: RUN_ID,
      });
    } else if (i % 3 === 1) {
      prev = appendRow(chainFile, prev, {
        ts: tIso(msAgo),
        kind: 'tool_call', tool_name: 'Grep', action: 'PASS',
        tool_inputs: { pattern: 'TODO', path: 'src/' },
        run_id: RUN_ID,
      });
    } else {
      prev = appendRow(chainFile, prev, {
        ts: tIso(msAgo),
        kind: 'tool_call', tool_name: 'Bash', action: 'PASS',
        tool_inputs: { command: 'ls', cwd: '/workspace' },
        run_id: RUN_ID,
      });
    }
  }

  // ── Window: adversarial activity (last ~10 minutes) ────────────────────
  // Each block below intentionally triggers one of the four detectors.

  // (1) Deny-rate spike — 12 rapid BLOCKs on sensitive paths
  for (let i = 0; i < 12; i++) {
    prev = appendRow(chainFile, prev, {
      ts: tIso(10 * 60_000 - i * 30_000),
      kind: 'tool_call', tool_name: 'Read', action: 'BLOCK',
      tool_inputs: { path: '/home/user/.ssh/id_rsa' },
      reason: 'path-denied',
      run_id: RUN_ID,
    });
  }

  // (2) File-read-volume burst — 60 distinct paths, all new
  for (let i = 0; i < 60; i++) {
    prev = appendRow(chainFile, prev, {
      ts: tIso(8 * 60_000 - i * 5_000),
      kind: 'tool_call', tool_name: 'Read', action: 'PASS',
      tool_inputs: { path: `recon/discovered-${i}.cfg` },
      run_id: RUN_ID,
    });
  }

  // (3) Unknown-tool-input — Bash invoked with previously-unseen `env` key
  prev = appendRow(chainFile, prev, {
    ts: tIso(5 * 60_000),
    kind: 'tool_call', tool_name: 'Bash', action: 'PASS',
    tool_inputs: { command: 'curl https://example.com', cwd: '/workspace',
                   env: { LD_PRELOAD: '/tmp/x.so' } },
    run_id: RUN_ID,
  });

  // (4) Secret-redact-rate — 3 redaction events
  for (let i = 0; i < 3; i++) {
    prev = appendRow(chainFile, prev, {
      ts: tIso(3 * 60_000 - i * 30_000),
      kind: 'tool_call', tool_name: 'Grep', action: 'TRANSFORM',
      tool_inputs: { pattern: 'sk-ant-', path: 'src/' },
      secrets_redacted: 1,
      run_id: RUN_ID,
    });
  }

  return { chainFile, nowMs: NOW };
}

function runAnomaliesDemoCli(_args = []) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-demo-anomalies-'));
  const chainFile = path.join(tmpDir, 'pipeline-events.jsonl');

  process.stdout.write(`${C.b('occasio demo anomalies')}\n`);
  process.stdout.write(`${C.d('  scratch dir: ' + tmpDir)}\n\n`);

  // ── Step 1 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('1.')} Building synthetic adversarial chain  ${C.d('(300 quiet baseline rows + 4 distinct anomaly patterns in last 10 min)')}\n`);
  const { nowMs } = buildAdversarialChain(chainFile);
  const stat = fs.statSync(chainFile);
  process.stdout.write(`   ${C.g('✓')} ${C.d(chainFile + ' (' + stat.size + ' bytes)')}\n\n`);

  // ── Step 2 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('2.')} Running detectors over the last ${C.c('15 minutes')}  ${C.d('(window vs. historical baseline)')}\n\n`);
  const result = runDetectors({
    chainFile,
    windowMs: DEFAULT_WINDOW_MS,
    now: nowMs,
  });

  process.stdout.write(`   ${C.d('window: ' + result.window_start + ' → ' + result.window_end)}\n`);
  process.stdout.write(`   ${C.d(result.window_rows + ' rows in window, ' + result.history_rows + ' historical)')}\n\n`);

  if (result.alerts.length === 0) {
    process.stderr.write(`   ${C.r('✗ no alerts fired — detectors are silent on activity that should trigger them')}\n`);
    return 1;
  }

  for (const a of result.alerts) {
    const color = SEV_COLOR[a.severity] || C.d;
    process.stdout.write(`   ${color('[' + a.severity.toUpperCase() + ']')} ${C.b(a.detector_id)}\n`);
    process.stdout.write(`       ${a.message}\n`);
    if (a.rows_implicated && a.rows_implicated.length) {
      process.stdout.write(`       ${C.d('implicated: ' + a.rows_implicated[0].slice(0, 16) +
        '…  (+' + (a.rows_implicated.length - 1) + ' more)')}\n`);
    }
    process.stdout.write('\n');
  }

  // ── Step 3 ─────────────────────────────────────────────────────────────
  process.stdout.write(`${C.b('3.')} Verifying all four built-in detectors fired\n`);
  const fired = new Set(result.alerts.map(a => a.detector_id));
  const expected = ['deny-rate', 'file-read-volume', 'unknown-tool-input', 'secret-redact-rate'];
  let allFired = true;
  for (const id of expected) {
    if (fired.has(id)) {
      process.stdout.write(`   ${C.g('✓')} ${id}\n`);
    } else {
      process.stdout.write(`   ${C.r('✗')} ${id} ${C.d('— did NOT fire on its trigger pattern (regression!)')}\n`);
      allFired = false;
    }
  }
  process.stdout.write('\n');

  if (!allFired) return 1;
  process.stdout.write(`${C.g('✓')} EDR layer end-to-end OK  ${C.d('(scratch chain preserved at ' + tmpDir + ')')}\n`);
  process.stdout.write(`\n${C.d('Re-run against the same chain interactively:')}\n`);
  process.stdout.write(`   ${C.c('occasio anomalies --chain ' + chainFile + ' --since "' + new Date(nowMs).toISOString() + '"')}\n\n`);
  return 0;
}

module.exports = { runAnomaliesDemoCli, buildAdversarialChain };
