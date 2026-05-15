'use strict';

/**
 * deny-rate — alert when the BLOCK rate in the window is materially higher
 * than the historical BLOCK rate.
 *
 * Window count vs. historical rate-per-equivalent-window. Cold start: if
 * historical has < 100 rows, only fire when window has ≥ MIN_ABSOLUTE blocks,
 * to avoid spurious alerts on a fresh chain.
 */

const ID    = 'deny-rate';
const LABEL = 'Deny rate spike';

const MIN_ABSOLUTE          = 5;    // window must contain at least this many BLOCKs
const MULTIPLIER_THRESHOLD  = 3.0;  // window rate >= baseline_rate × this
const COLD_START_MIN_HISTORY = 100;

function countBlocks(rows) {
  let n = 0;
  for (const r of rows) if (r.action === 'BLOCK') n++;
  return n;
}

function evaluate(windowRows, historicalRows, opts) {
  const winBlocks = countBlocks(windowRows);
  if (winBlocks < MIN_ABSOLUTE) return [];

  const winMs = opts.windowMs || 0;
  if (winMs <= 0) return [];

  // Historical rate: BLOCKs / (history span in ms) × winMs
  if (historicalRows.length < COLD_START_MIN_HISTORY) {
    // Cold start: only fire when window has a lot of blocks AND the
    // overall window proportion is anomalously high. Avoids spurious
    // alerts on a brand-new install.
    const winRate = windowRows.length ? winBlocks / windowRows.length : 0;
    if (winRate < 0.5) return [];
    return [{
      severity: 'medium',
      observed: winBlocks,
      baseline: 0,
      message: `BLOCK count ${winBlocks} in current window (cold-start: no historical baseline yet, but ${(winRate * 100).toFixed(0)}% of window rows are blocked)`,
      rows_implicated: implicatedHashes(windowRows),
    }];
  }

  const histBlocks = countBlocks(historicalRows);
  const firstTs = Date.parse(historicalRows[0]?.ts);
  const lastTs  = Date.parse(historicalRows[historicalRows.length - 1]?.ts);
  if (!Number.isFinite(firstTs) || !Number.isFinite(lastTs) || lastTs <= firstTs) return [];

  const histSpanMs = lastTs - firstTs;
  const histRatePerWindow = (histBlocks / histSpanMs) * winMs;
  if (histRatePerWindow <= 0) {
    return [{
      severity: 'high',
      observed: winBlocks,
      baseline: 0,
      message: `${winBlocks} BLOCKs in current window; historical baseline shows none — possible new attack pattern or policy change`,
      rows_implicated: implicatedHashes(windowRows),
    }];
  }

  const ratio = winBlocks / histRatePerWindow;
  const effectiveThreshold = MULTIPLIER_THRESHOLD * (opts.thresholdMultiplier || 1);
  if (ratio < effectiveThreshold) return [];

  const severity = ratio > 10 ? 'high' : 'medium';
  return [{
    severity,
    observed: winBlocks,
    baseline: Number(histRatePerWindow.toFixed(2)),
    message: `BLOCK rate ${winBlocks} in current window vs. historical ${histRatePerWindow.toFixed(2)}/window (×${ratio.toFixed(1)})`,
    rows_implicated: implicatedHashes(windowRows),
  }];
}

function implicatedHashes(rows) {
  return rows.filter(r => r.action === 'BLOCK' && typeof r.hash === 'string')
             .slice(0, 5)
             .map(r => r.hash);
}

module.exports = { id: ID, label: LABEL, evaluate };
