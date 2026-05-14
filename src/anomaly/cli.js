'use strict';

/**
 * anomaly/cli.js — `localfirst anomalies`
 *
 * Usage:
 *   localfirst anomalies                       Run all detectors over the last 15 min
 *   localfirst anomalies --window 5m           Override window size (s/m/h suffixes)
 *   localfirst anomalies --json                Machine-readable output
 *   localfirst anomalies --since <ISO>         Pin the "now" anchor (testing)
 *   localfirst anomalies --chain <path>        Override chain file
 *
 * Exit codes:
 *   0  no alerts
 *   1  alerts present (low only)
 *   2  alerts present including medium/high
 */

const { runDetectors, DEFAULT_CHAIN, DEFAULT_WINDOW_MS } = require('./index');

const C = {
  r:  s => `\x1b[31m${s}\x1b[0m`,
  y:  s => `\x1b[33m${s}\x1b[0m`,
  g:  s => `\x1b[32m${s}\x1b[0m`,
  c:  s => `\x1b[36m${s}\x1b[0m`,
  d:  s => `\x1b[2m${s}\x1b[0m`,
  b:  s => `\x1b[1m${s}\x1b[0m`,
};

const SEV_COLOR = { high: C.r, medium: C.y, low: C.c };
const SEV_RANK  = { high: 3, medium: 2, low: 1 };

function parseWindow(spec) {
  if (!spec) return DEFAULT_WINDOW_MS;
  const m = String(spec).trim().match(/^(\d+)\s*([smh]?)$/i);
  if (!m) return DEFAULT_WINDOW_MS;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || 'm').toLowerCase();
  const mult = unit === 's' ? 1000 : unit === 'h' ? 3600_000 : 60_000;
  return n * mult;
}

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
function bool(args, name) { return args.indexOf(name) >= 0; }

function runAnomaliesCli(args = []) {
  if (bool(args, '--help') || bool(args, '-h')) {
    process.stdout.write(
      'Usage:\n' +
      '  localfirst anomalies [--window 15m] [--since <ISO>] [--chain <path>] [--json]\n' +
      '\n' +
      'Detectors:\n' +
      '  deny-rate           BLOCK rate spike vs historical baseline\n' +
      '  file-read-volume    Distinct files-read burst (recon pattern)\n' +
      '  unknown-tool-input  Previously-unseen tool_inputs shape\n' +
      '  secret-redact-rate  Secret-redaction count vs historical baseline\n'
    );
    return 0;
  }

  const windowMs = parseWindow(flag(args, '--window'));
  const since    = flag(args, '--since');
  const chain    = flag(args, '--chain') || DEFAULT_CHAIN;
  const asJson   = bool(args, '--json');

  const result = runDetectors({ chainFile: chain, windowMs, now: since });

  if (asJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    renderHuman(result, windowMs);
  }

  // Exit code reflects worst severity in alerts.
  if (result.alerts.length === 0) return 0;
  const worst = result.alerts.reduce(
    (m, a) => Math.max(m, SEV_RANK[a.severity] || 0), 0);
  return worst >= 2 ? 2 : 1;
}

function renderHuman(result, windowMs) {
  const winLabel = humanDuration(windowMs);
  process.stdout.write(
    `${C.b('localfirst anomalies')}  ${C.d('window=' + winLabel + ', ' +
       result.window_rows + ' rows in window, ' +
       result.history_rows + ' historical)')}\n\n`);

  if (result.alerts.length === 0) {
    process.stdout.write(`  ${C.g('✓')} no anomalies in the current window\n\n`);
    return;
  }

  // Sort high→low so worst is visible first.
  const sorted = [...result.alerts].sort(
    (a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
  for (const a of sorted) {
    const color = SEV_COLOR[a.severity] || C.d;
    const sev   = color(`[${a.severity.toUpperCase()}]`);
    process.stdout.write(`  ${sev} ${C.b(a.detector_id)} — ${a.message}\n`);
    if (a.rows_implicated.length) {
      const sample = a.rows_implicated[0];
      process.stdout.write(`         ${C.d('implicated rows: ' + sample.slice(0,12) +
        '…  (+' + (a.rows_implicated.length - 1) + ' more)')}\n`);
    }
  }
  process.stdout.write('\n');
  process.stdout.write(
    `  ${C.d('Tip: `localfirst replay --run <id>` to see the run that produced an implicated row.')}\n\n`);
}

function humanDuration(ms) {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3600_000).toFixed(1)}h`;
}

module.exports = { runAnomaliesCli, parseWindow, humanDuration };
