'use strict';

/**
 * file-read-volume — alert when the count of distinct files read in the
 * window exceeds the per-window historical p95 by a configurable multiplier.
 *
 * Catches recon-style bursts where an agent suddenly reads dozens of files
 * it has never touched. Uses **distinct** paths (not total reads) to avoid
 * false positives from a single re-read loop.
 */

const ID    = 'file-read-volume';
const LABEL = 'File-read volume spike';

const MIN_ABSOLUTE        = 20;   // window must read at least this many distinct paths
const P95_MULTIPLIER      = 1.5;  // window > p95 × this
const COLD_START_MIN_RUNS = 5;    // need ≥ this many historical windows to compute p95

function readTool(row) {
  const t = String(row.tool_name || '').toLowerCase();
  return t === 'read' || t === 'read_file';
}

function pathOf(row) {
  return row.tool_inputs && (row.tool_inputs.path || row.tool_inputs.file_path) || null;
}

function distinctReadPaths(rows) {
  const s = new Set();
  for (const r of rows) {
    if (!readTool(r)) continue;
    const p = pathOf(r);
    if (p) s.add(p);
  }
  return s;
}

// Build a p95 of "distinct read-paths per equivalent window" from history,
// by splitting historical rows into N consecutive windows of size windowMs.
function historicalDistinctP95(historicalRows, windowMs) {
  if (!historicalRows.length) return { p95: 0, samples: 0 };
  const first = Date.parse(historicalRows[0].ts);
  const last  = Date.parse(historicalRows[historicalRows.length - 1].ts);
  if (!Number.isFinite(first) || !Number.isFinite(last) || last <= first) {
    return { p95: 0, samples: 0 };
  }

  const buckets = new Map();   // bucketIdx → Set<path>
  for (const r of historicalRows) {
    if (!readTool(r)) continue;
    const p = pathOf(r);
    if (!p) continue;
    const t = Date.parse(r.ts);
    if (!Number.isFinite(t)) continue;
    const idx = Math.floor((t - first) / windowMs);
    if (!buckets.has(idx)) buckets.set(idx, new Set());
    buckets.get(idx).add(p);
  }

  const counts = Array.from(buckets.values()).map(s => s.size);
  if (counts.length < COLD_START_MIN_RUNS) return { p95: 0, samples: counts.length };

  counts.sort((a, b) => a - b);
  const i95 = Math.min(counts.length - 1, Math.floor(counts.length * 0.95));
  return { p95: counts[i95], samples: counts.length };
}

function evaluate(windowRows, historicalRows, opts) {
  const winSet = distinctReadPaths(windowRows);
  if (winSet.size < MIN_ABSOLUTE) return [];

  const winMs = opts.windowMs || 0;
  if (winMs <= 0) return [];

  const { p95, samples } = historicalDistinctP95(historicalRows, winMs);
  if (samples < COLD_START_MIN_RUNS) {
    // Cold start fallback: fire only on very large bursts so we never
    // alarm on a normal first session.
    if (winSet.size < MIN_ABSOLUTE * 3) return [];
    return [{
      severity: 'medium',
      observed: winSet.size,
      baseline: null,
      message: `${winSet.size} distinct files read in current window (cold-start: not enough historical windows yet to compute p95)`,
      rows_implicated: firstReadHashes(windowRows),
    }];
  }

  if (p95 === 0) return [];
  const effectiveMult = P95_MULTIPLIER * (opts.thresholdMultiplier || 1);
  if (winSet.size < p95 * effectiveMult) return [];

  const ratio = winSet.size / Math.max(p95, 1);
  const severity = ratio > 4 ? 'high' : 'medium';
  return [{
    severity,
    observed: winSet.size,
    baseline: p95,
    message: `${winSet.size} distinct files read in current window vs. p95 ${p95} (×${ratio.toFixed(1)})`,
    rows_implicated: firstReadHashes(windowRows),
  }];
}

function firstReadHashes(rows) {
  return rows.filter(r => readTool(r) && typeof r.hash === 'string')
             .slice(0, 5)
             .map(r => r.hash);
}

module.exports = { id: ID, label: LABEL, evaluate };
