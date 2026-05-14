'use strict';

/**
 * secret-redact-rate — alert when the rate of secret-redaction events in the
 * window is materially higher than baseline. Single redactions get a low-
 * severity alert; spikes get medium/high. A non-zero window count when
 * history is zero gets high severity (first-time-leak signal).
 *
 * `secrets_redacted` is an integer count on tool-call rows when the result
 * carried redacted secrets. Any row with `secrets_redacted >= 1` counts.
 */

const ID    = 'secret-redact-rate';
const LABEL = 'Secret-redaction rate';

const MIN_HISTORY_FOR_RATE = 200;
const MULTIPLIER_THRESHOLD = 5.0;

function sumRedactions(rows) {
  let n = 0;
  for (const r of rows) {
    const v = r.secrets_redacted;
    if (typeof v === 'number' && v > 0) n += v;
  }
  return n;
}

function rowsWithRedactions(rows) {
  const out = [];
  for (const r of rows) {
    if (typeof r.secrets_redacted === 'number' && r.secrets_redacted > 0) out.push(r);
  }
  return out;
}

function evaluate(windowRows, historicalRows, opts) {
  const winRows = rowsWithRedactions(windowRows);
  const winCount = sumRedactions(winRows);
  if (winCount === 0) return [];

  const winMs = opts.windowMs || 0;
  if (winMs <= 0) return [];

  // First-leak signal: there's redaction in the window, none in history.
  if (historicalRows.length >= MIN_HISTORY_FOR_RATE) {
    const histCount = sumRedactions(historicalRows);
    if (histCount === 0) {
      return [{
        severity: 'high',
        observed: winCount,
        baseline: 0,
        message: `${winCount} secret-redaction event(s) in current window; no historical baseline of redactions — first time we are blocking leaks from this agent/policy combination`,
        rows_implicated: firstHashes(winRows),
      }];
    }

    const firstTs = Date.parse(historicalRows[0].ts);
    const lastTs  = Date.parse(historicalRows[historicalRows.length - 1].ts);
    if (Number.isFinite(firstTs) && Number.isFinite(lastTs) && lastTs > firstTs) {
      const histSpanMs    = lastTs - firstTs;
      const histPerWindow = (histCount / histSpanMs) * winMs;
      const ratio = winCount / Math.max(histPerWindow, 0.01);

      if (ratio < MULTIPLIER_THRESHOLD) {
        // Still surface non-spike redactions as low severity so reviewers
        // see them. Compliance teams want to know about every leak attempt.
        return [{
          severity: 'low',
          observed: winCount,
          baseline: Number(histPerWindow.toFixed(2)),
          message: `${winCount} secret-redaction event(s) in current window (baseline ${histPerWindow.toFixed(2)}/window, within normal range)`,
          rows_implicated: firstHashes(winRows),
        }];
      }

      const severity = ratio > 20 ? 'high' : 'medium';
      return [{
        severity,
        observed: winCount,
        baseline: Number(histPerWindow.toFixed(2)),
        message: `${winCount} secret-redaction event(s) in current window vs. baseline ${histPerWindow.toFixed(2)}/window (×${ratio.toFixed(1)})`,
        rows_implicated: firstHashes(winRows),
      }];
    }
  }

  // Cold-start: a single redaction is LOW (visible in JSON/SIEM, not loud
  // for human review); a burst (≥ COLD_START_BURST) is MEDIUM. Calibration
  // showed that emitting MEDIUM on every cold-start redaction produces a
  // false-positive every coding session that touches files matching the
  // built-in secret patterns (e.g. test fixtures, example configs). The
  // burst threshold ensures real spikes still surface during warm-up.
  const COLD_START_BURST = 5;
  return [{
    severity: winCount >= COLD_START_BURST ? 'medium' : 'low',
    observed: winCount,
    baseline: null,
    message: `${winCount} secret-redaction event(s) in current window (cold-start: not enough history yet to compute baseline)`,
    rows_implicated: firstHashes(winRows),
  }];
}

function firstHashes(rows) {
  return rows.filter(r => typeof r.hash === 'string').slice(0, 5).map(r => r.hash);
}

module.exports = { id: ID, label: LABEL, evaluate };
