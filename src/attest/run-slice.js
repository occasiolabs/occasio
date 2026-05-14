'use strict';

/**
 * run-slice.js — load a tamper-evident audit chain and return the slice of rows
 * belonging to a single run_id, preserving the original on-disk order.
 *
 * Returns:
 *   {
 *     events:       [row, …]   // sorted by file order (which is chain order)
 *     event_count:  integer    // events.length
 *     first_hash:   string|null  // hash field of the first row in the slice
 *     last_hash:    string|null  // hash field of the last row in the slice
 *   }
 *
 * Why we don't sort by ISO timestamp here (unlike replay.groupByRun): the
 * chain's hash linkage is the canonical order. If two rows share an iso
 * second, the on-disk order is the only correct sequence — any other sort
 * would produce a `first_hash`/`last_hash` pair that does not correspond
 * to a contiguous block of `prev_hash → hash` links.
 *
 * Legacy rows (no `hash` field — pre-hash-chain) are included if their
 * `run_id` matches, but their `hash` will be undefined, so `first_hash`/
 * `last_hash` may be null. Callers that need cryptographic commitments
 * should check `first_hash !== null` and gate accordingly.
 */

const fs = require('fs');

function readJsonlFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function loadRunSlice(logFile, runId) {
  if (!runId || typeof runId !== 'string') {
    return { events: [], event_count: 0, first_hash: null, last_hash: null };
  }
  const all = readJsonlFile(logFile);
  const events = all.filter(e => e && e.run_id === runId);
  const first = events[0];
  const last  = events[events.length - 1];
  return {
    events,
    event_count: events.length,
    first_hash:  (first && typeof first.hash === 'string') ? first.hash : null,
    last_hash:   (last  && typeof last.hash  === 'string') ? last.hash  : null,
  };
}

module.exports = { loadRunSlice, readJsonlFile };
