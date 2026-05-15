'use strict';

/**
 * anomaly/index.js — runtime anomaly detection over the tamper-evident audit
 * chain (`~/.occasio/pipeline-events.jsonl`).
 *
 * Complements src/baseline.js (which does per-project, novelty-based detection
 * over the session log) with **time-windowed rate detectors over the chain**.
 * Where baseline.js answers "did this session do something it never did",
 * this module answers "did the last 15 minutes look anomalous compared to the
 * preceding history".
 *
 * Architecture
 *   loadChainRows(file)               read + parse rows once
 *   splitByWindow(rows, ms, now)      split into windowRows vs historical
 *   runDetectors(...)                 invoke every detector, collect alerts
 *
 * Each detector is a small module exporting:
 *   {
 *     id:            'deny-rate' | ...,
 *     label:         'Human-readable name',
 *     evaluate(windowRows, historicalRows, opts) → Alert[]
 *   }
 *
 * Alert shape (stable contract for CLI + chain-persist + tests)
 *   {
 *     detector_id, severity: 'low'|'medium'|'high',
 *     observed, baseline, message,
 *     rows_implicated: string[]  // first ≤5 row hashes that triggered
 *   }
 *
 * Runner result shape:
 *   {
 *     alerts:  Alert[]   anomalies the detectors observed in the window
 *     errors:  Error[]   detectors that threw — bug reports, NOT anomalies
 *     window_start, window_end, window_rows, history_rows
 *   }
 *
 * Why alerts and errors are separate:
 *   A crashed detector is a *bug in the detector*, not an *anomaly in the
 *   chain*. Surfacing detector crashes as low-severity alerts trains
 *   compliance reviewers to dismiss real anomalies. Separate channels:
 *   alerts get human attention; errors go to the operator log and CI.
 *
 * Read-only by default. Persistence (writing alerts back into the chain as
 * `kind:"anomaly_alert"` rows) is opt-in via the CLI's --persist flag and
 * piggybacks the existing JsonlAuditor so alerts inherit the chain's
 * tamper-evident property.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const DEFAULT_CHAIN = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;   // 15 minutes

// ── Built-in detectors ──────────────────────────────────────────────────────
// Order is the order alerts appear in CLI output. Keep deterministic.
function builtinDetectors() {
  return [
    require('./detectors/deny-rate'),
    require('./detectors/file-read-volume'),
    require('./detectors/unknown-tool-input'),
    require('./detectors/secret-redact-rate'),
  ];
}

// ── Chain row loader ─────────────────────────────────────────────────────────

function loadChainRows(filePath) {
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch { return []; }
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try {
      const row = JSON.parse(line);
      if (row && row.ts) out.push(row);
    } catch { /* skip malformed */ }
  }
  return out;
}

// ── Window split ─────────────────────────────────────────────────────────────
// Split rows into { window, historical }: window contains rows whose ts is
// within [now - windowMs, now]; historical contains everything strictly
// before that. We use rows[i].ts (ISO 8601) — parse failures fall through to
// historical (treat as old).
function splitByWindow(rows, windowMs, now) {
  const nowMs   = typeof now === 'number' ? now : (now ? new Date(now).getTime() : Date.now());
  const cutoff  = nowMs - windowMs;
  const window     = [];
  const historical = [];
  for (const r of rows) {
    const t = Date.parse(r.ts);
    if (!Number.isFinite(t)) { historical.push(r); continue; }
    if (t >= cutoff && t <= nowMs) window.push(r);
    else if (t < cutoff)            historical.push(r);
    // rows in the future (t > nowMs) are skipped — they're either clock skew
    // or rows we shouldn't be evaluating yet
  }
  return { window, historical, windowStartMs: cutoff, windowEndMs: nowMs };
}

// ── Runner ───────────────────────────────────────────────────────────────────
function runDetectors({
  chainFile = DEFAULT_CHAIN,
  windowMs  = DEFAULT_WINDOW_MS,
  now       = null,
  detectors = null,
  // Multiplier applied to detector internal thresholds. >1 = more permissive
  // (fewer alerts), <1 = more sensitive. Detectors choose how to apply this;
  // categorical detectors may ignore it.
  thresholdMultiplier = 1,
  // For tests: pass rows directly instead of reading from disk.
  rows      = null,
} = {}) {
  const allRows = rows || loadChainRows(chainFile);
  const split   = splitByWindow(allRows, windowMs, now);
  const list    = detectors || builtinDetectors();

  const alerts = [];
  const errors = [];
  for (const d of list) {
    try {
      const out = d.evaluate(split.window, split.historical, {
        windowMs, windowStartMs: split.windowStartMs, windowEndMs: split.windowEndMs,
        thresholdMultiplier,
      });
      if (!Array.isArray(out)) continue;
      for (const a of out) {
        if (!a) continue;
        alerts.push({
          detector_id:   d.id,
          severity:      a.severity || 'medium',
          observed:      a.observed,
          baseline:      a.baseline,
          message:       a.message || `${d.label}: anomaly detected`,
          rows_implicated: (a.rows_implicated || []).slice(0, 5),
        });
      }
    } catch (e) {
      // A crashed detector is a bug, not an anomaly. Surface it on the
      // errors channel so operators / CI see it without contaminating
      // the alerts stream that compliance reviews.
      errors.push({
        detector_id: d.id,
        label:       d.label,
        error:       e.message || String(e),
        stack:       e.stack || null,
      });
    }
  }

  return {
    alerts,
    errors,
    window_start: new Date(split.windowStartMs).toISOString(),
    window_end:   new Date(split.windowEndMs).toISOString(),
    window_rows:  split.window.length,
    history_rows: split.historical.length,
  };
}

module.exports = {
  runDetectors,
  loadChainRows,
  splitByWindow,
  builtinDetectors,
  DEFAULT_CHAIN,
  DEFAULT_WINDOW_MS,
};
