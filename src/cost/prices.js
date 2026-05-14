// Token-cost arithmetic for Anthropic-priced models. Extracted from
// src/index.js so the proxy hot-path doesn't carry pricing data, and so
// MODEL_PRICES updates land in a file small enough to review at a glance.
//
// Prices are USD per 1M tokens. Cache-write is the one-time cost to
// populate a cache breakpoint; cache-read is the cheap subsequent hit.
//
// Substring matching is intentional — Anthropic's model_id strings often
// carry a dated suffix (claude-haiku-4-5-20251001) we want to absorb
// without a table update. The trade-off: a truly unknown model silently
// falls back to `default`. We warn once per unknown model so the failure
// is loud the first time and quiet thereafter.

'use strict';

const fs = require('fs');

const MODEL_PRICES = {
  'claude-opus-4-6':   { in: 15.00, out: 75.00, cache_write:  18.75, cache_read:  1.50 },
  'claude-opus-4':     { in: 15.00, out: 75.00, cache_write:  18.75, cache_read:  1.50 },
  'claude-sonnet-4-6': { in:  3.00, out: 15.00, cache_write:   3.75, cache_read:  0.30 },
  'claude-sonnet-4':   { in:  3.00, out: 15.00, cache_write:   3.75, cache_read:  0.30 },
  'claude-haiku-4-5':  { in:  0.25, out:  1.25, cache_write:   0.30, cache_read:  0.03 },
  'claude-haiku-4':    { in:  0.25, out:  1.25, cache_write:   0.30, cache_read:  0.03 },
  'default':           { in:  3.00, out: 15.00, cache_write:   3.75, cache_read:  0.30 },
};

// Track which unknown model names we've already complained about, so a
// long session with a new model surfaces the warning exactly once instead
// of on every request.
const _warnedUnknown = new Set();

function getPrice(model) {
  if (!model) return MODEL_PRICES.default;
  for (const [k, v] of Object.entries(MODEL_PRICES)) {
    if (k !== 'default' && model.includes(k)) return v;
  }
  if (!_warnedUnknown.has(model)) {
    _warnedUnknown.add(model);
    // stderr so it doesn't pollute proxy stdout. Silenceable via env for
    // CI runs that legitimately want to price unknown models as default.
    if (!process.env.OCCASIO_QUIET_PRICING) {
      process.stderr.write(
        `[occasio] warning: unknown model "${model}" — falling back to default pricing ` +
        `(in:$${MODEL_PRICES.default.in}/M, out:$${MODEL_PRICES.default.out}/M). ` +
        `Add it to src/cost/prices.js to silence this.\n`
      );
    }
  }
  return MODEL_PRICES.default;
}

function calcCost(model, inp, out, cacheWrite = 0, cacheRead = 0) {
  const p = getPrice(model);
  return (inp / 1e6 * p.in) + (out / 1e6 * p.out)
       + (cacheWrite / 1e6 * p.cache_write) + (cacheRead / 1e6 * p.cache_read);
}

// Savings from Anthropic prompt caching: cache reads are 10× cheaper than fresh input.
function calcCacheSavings(model, cacheReadTokens) {
  if (!cacheReadTokens) return 0;
  const p = getPrice(model);
  return (cacheReadTokens / 1e6) * (p.in - p.cache_read);
}

// Cross-request compounding savings: reads the run's JSONL entries in sequence order
// and weights each distilled batch by the exact number of subsequent API calls that
// carry the smaller result in their conversation history.
// Formula: Σ (distill_tokens_saved[i] / 1M × price_in × (N - i - 1))
// Returns { savings: float, carryInstances: int }
// carryInstances = total sum of subsequent-call counts across all distilled batches
// — the actual multiplier used — so the display is self-explanatory.
// Assumption: tool results accumulate in Claude Code's message history for all
// subsequent requests in the session (true for normal sessions; may not hold if
// Claude Code resets context mid-session).
function calcCompoundingSavings(runId, logFile, model) {
  if (!runId) return { savings: 0, carryInstances: 0 };
  let entries;
  try {
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean);
    entries = lines
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(e => e && e.run_id === runId);
  } catch { return { savings: 0, carryInstances: 0 }; }
  const N = entries.length;
  if (N < 2) return { savings: 0, carryInstances: 0 };
  const p = getPrice(model);
  let savings = 0, carryInstances = 0;
  for (let i = 0; i < N; i++) {
    const dt = entries[i].distill_tokens_saved || 0;
    if (dt > 0) {
      const subsequent = N - i - 1;
      savings += (dt / 1e6) * p.in * subsequent;
      carryInstances += subsequent;
    }
  }
  return { savings, carryInstances };
}

module.exports = {
  MODEL_PRICES,
  getPrice,
  calcCost,
  calcCacheSavings,
  calcCompoundingSavings,
};
