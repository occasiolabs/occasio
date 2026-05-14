#!/usr/bin/env node
'use strict';

/**
 * scripts/calibrate-anomaly-detectors.js
 *
 * Slide the 15-minute anomaly window across an audit chain and count how
 * often each detector fires. Use against your real
 * ~/.localfirst/pipeline-events.jsonl to find the false-positive rate of
 * the current default thresholds on normal usage.
 *
 * The thresholds in src/anomaly/detectors/* started as best guesses. This
 * script gives them an empirical basis: if the deny-rate detector fires
 * five times per hour on your normal coding day, the threshold is wrong.
 *
 * Usage:
 *   node scripts/calibrate-anomaly-detectors.js
 *   node scripts/calibrate-anomaly-detectors.js --chain <path>
 *   node scripts/calibrate-anomaly-detectors.js --step 5m --window 15m
 *   node scripts/calibrate-anomaly-detectors.js --json > report.json
 *
 * Output:
 *   For each detector: total alerts, alerts-per-hour-of-activity, severity
 *   breakdown, an example alert message, and the windows that produced
 *   each severity level so you can spot-check whether they were "real"
 *   anomalies or normal-but-bursty activity.
 *
 * NOT a replacement for adversarial testing. Calibration tells us whether
 * the threshold is too tight for normal use; it does not tell us whether
 * the threshold is loose enough to catch genuine attacks (the
 * `demo anomalies` smoke test and the EDR-demo walkthrough address that).
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const {
  loadChainRows, splitByWindow, runDetectors, DEFAULT_WINDOW_MS, DEFAULT_CHAIN,
} = require('../src/anomaly');

function flag(args, name)  { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function bool(args, name)  { return args.indexOf(name) >= 0; }

function parseDuration(s, fallback) {
  if (!s) return fallback;
  const m = String(s).trim().match(/^(\d+)\s*([smh]?)$/i);
  if (!m) return fallback;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || 'm').toLowerCase();
  return n * (unit === 's' ? 1000 : unit === 'h' ? 3600_000 : 60_000);
}

function fmtDuration(ms) {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)}h`;
  return `${(ms / 86_400_000).toFixed(1)}d`;
}

const args     = process.argv.slice(2);
const chain    = flag(args, '--chain') || DEFAULT_CHAIN;
const windowMs = parseDuration(flag(args, '--window'), DEFAULT_WINDOW_MS);
const stepMs   = parseDuration(flag(args, '--step'),   5 * 60 * 1000);
const asJson   = bool(args, '--json');

if (!fs.existsSync(chain)) {
  process.stderr.write(`[calibrate] chain file not found: ${chain}\n`);
  process.exit(2);
}

const rows = loadChainRows(chain);
if (rows.length === 0) {
  process.stderr.write(`[calibrate] chain has no parseable rows\n`);
  process.exit(2);
}

const first = Date.parse(rows[0].ts);
const last  = Date.parse(rows[rows.length - 1].ts);
if (!Number.isFinite(first) || !Number.isFinite(last) || last <= first) {
  process.stderr.write(`[calibrate] chain ts range invalid\n`);
  process.exit(2);
}

const spanMs = last - first;

// Per-detector tally. severity → {count, examples}.
const tally = {
  'deny-rate':           { high: 0, medium: 0, low: 0, examples: { high: null, medium: null, low: null } },
  'file-read-volume':    { high: 0, medium: 0, low: 0, examples: { high: null, medium: null, low: null } },
  'unknown-tool-input':  { high: 0, medium: 0, low: 0, examples: { high: null, medium: null, low: null } },
  'secret-redact-rate':  { high: 0, medium: 0, low: 0, examples: { high: null, medium: null, low: null } },
};

let windowsEvaluated = 0;
for (let t = first + windowMs; t <= last; t += stepMs) {
  const result = runDetectors({ rows, windowMs, now: t });
  windowsEvaluated++;
  for (const a of result.alerts) {
    const slot = tally[a.detector_id];
    if (!slot) continue;
    if (slot[a.severity] === undefined) continue;
    slot[a.severity] += 1;
    if (!slot.examples[a.severity]) {
      slot.examples[a.severity] = {
        at: new Date(t).toISOString(),
        message: a.message,
      };
    }
  }
}

// Activity hours = wall-clock span. Real "session hours" would be smaller
// (gaps between coding days don't count), but for a first calibration the
// alerts-per-window metric is the more useful denominator anyway.
const activityHours = spanMs / 3_600_000;
const windowsPerHour = (3_600_000 / stepMs);

const report = {
  chain,
  rows: rows.length,
  span: { from: new Date(first).toISOString(), to: new Date(last).toISOString(), duration: fmtDuration(spanMs) },
  window_ms: windowMs,
  step_ms:   stepMs,
  windows_evaluated: windowsEvaluated,
  detectors: {},
};

for (const id of Object.keys(tally)) {
  const t = tally[id];
  const total = t.high + t.medium + t.low;
  report.detectors[id] = {
    total_alerts: total,
    high: t.high,
    medium: t.medium,
    low: t.low,
    alerts_per_window:   total / Math.max(windowsEvaluated, 1),
    alerts_per_hour:     total / Math.max(activityHours, 0.01),
    example_high:        t.examples.high,
    example_medium:      t.examples.medium,
    example_low:         t.examples.low,
  };
}

if (asJson) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(0);
}

// Human render
const C = {
  b: (s) => `\x1b[1m${s}\x1b[0m`,
  d: (s) => `\x1b[2m${s}\x1b[0m`,
  g: (s) => `\x1b[32m${s}\x1b[0m`,
  y: (s) => `\x1b[33m${s}\x1b[0m`,
  r: (s) => `\x1b[31m${s}\x1b[0m`,
};

process.stdout.write(`${C.b('Anomaly-detector calibration')}\n`);
process.stdout.write(`  Chain:    ${chain}\n`);
process.stdout.write(`  Span:     ${fmtDuration(spanMs)}  (${report.span.from} → ${report.span.to})\n`);
process.stdout.write(`  Rows:     ${rows.length}\n`);
process.stdout.write(`  Window:   ${fmtDuration(windowMs)}  · Step: ${fmtDuration(stepMs)}\n`);
process.stdout.write(`  Windows:  ${windowsEvaluated} evaluated  (≈ ${windowsPerHour.toFixed(1)}/hour)\n\n`);

for (const id of Object.keys(report.detectors)) {
  const d = report.detectors[id];
  const head = `${C.b(id.padEnd(22))} ${d.total_alerts.toString().padStart(4)} alerts  ` +
               `(${d.high} high · ${d.medium} medium · ${d.low} low)  ` +
               `${C.d(d.alerts_per_window.toFixed(3) + '/window · ' +
                  d.alerts_per_hour.toFixed(2) + '/hour')}`;
  process.stdout.write(head + '\n');
  for (const sev of ['high', 'medium', 'low']) {
    const ex = d['example_' + sev];
    if (!ex) continue;
    const color = sev === 'high' ? C.r : sev === 'medium' ? C.y : C.g;
    process.stdout.write(`  ${color('[' + sev + ']')} ${C.d(ex.at)}\n`);
    process.stdout.write(`         ${ex.message.slice(0, 120)}\n`);
  }
  process.stdout.write('\n');
}

// Suggest action based on what we saw
process.stdout.write(`${C.b('Suggested interpretation')}\n`);
let anySpike = false;
for (const id of Object.keys(report.detectors)) {
  const d = report.detectors[id];
  if (d.alerts_per_hour > 1) {
    process.stdout.write(`  ${C.y('⚠')}  ${id}: >1 alert/hour on normal usage — threshold likely too tight\n`);
    anySpike = true;
  }
  if (d.high > Math.max(activityHours / 24, 1)) {
    process.stdout.write(`  ${C.r('⚠')}  ${id}: >1 HIGH/day on normal usage — investigate or raise threshold\n`);
    anySpike = true;
  }
}
if (!anySpike) {
  process.stdout.write(`  ${C.g('✓')}  All detectors fire at < 1 alert/hour and < 1 HIGH/day on this chain. Defaults are reasonable for this user.\n`);
}
process.stdout.write('\n');
