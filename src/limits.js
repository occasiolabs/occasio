'use strict';

/**
 * limits.js — pure per-round volume limits. No I/O, no dependencies.
 * Mirrors budget.js: imported by the round loop (adapters/claude-code.js) and
 * by tests.
 *
 * A `limits:` block in policy.yml caps how much a single agent roundtrip may
 * do, as a runaway-agent guard. Each key is a positive integer; absent or ≤0
 * means that limit is NOT enforced (opt-in / default-off — existing users with
 * no `limits:` block are unaffected).
 *
 *   limits:
 *     max_tool_calls_per_round:     50     # tool_use blocks in one assistant turn
 *     max_bash_calls_per_round:     10     # of those, shell calls
 *     max_bytes_to_model_per_round: 2000000  # bytes of tool output re-entering the model
 */

const LIMIT_KEYS = Object.freeze([
  'max_tool_calls_per_round',
  'max_bash_calls_per_round',
  'max_bytes_to_model_per_round',
]);

// Maps an observed count field → its limit key. Checked in this fixed order;
// the first violation wins (deterministic for tests + audit).
const COUNT_TO_LIMIT = Object.freeze([
  ['toolCalls',    'max_tool_calls_per_round'],
  ['bashCalls',    'max_bash_calls_per_round'],
  ['bytesToModel', 'max_bytes_to_model_per_round'],
]);

/**
 * Keep only the known limit keys, coerced to positive integers. Anything
 * absent, non-integer, or ≤0 is dropped (⇒ unenforced).
 */
function normalizeLimits(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const k of LIMIT_KEYS) {
    const n = Number(raw[k]);
    if (Number.isFinite(n) && Number.isInteger(n) && n > 0) out[k] = n;
  }
  return out;
}

/**
 * @param {object} limits  normalized limits ({} = nothing enforced)
 * @param {{toolCalls?:number, bashCalls?:number, bytesToModel?:number}} counts
 * @returns {{exceeded:boolean, kind?:string, max?:number, actual?:number}}
 *   The first violated limit (actual > max), or { exceeded:false }.
 */
function checkRoundLimits(limits, counts) {
  const lim = limits || {};
  const c   = counts || {};
  for (const [countKey, limitKey] of COUNT_TO_LIMIT) {
    const max = lim[limitKey];
    if (typeof max !== 'number' || max <= 0) continue;   // unenforced
    const actual = Number(c[countKey]) || 0;
    if (actual > max) return { exceeded: true, kind: limitKey, max, actual };
  }
  return { exceeded: false };
}

module.exports = { checkRoundLimits, normalizeLimits, LIMIT_KEYS };
