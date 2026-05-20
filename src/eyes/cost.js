'use strict';

/**
 * eyes/cost.js — session-cost aggregation across captured exchanges.
 *
 * Answers: "what is Anthropic's own system prompt costing me per session?"
 *
 * For each exchange we have:
 *   - system.bytes               — actual size of the system prompt sent
 *   - byteCount.after            — total bytes sent
 *   - response.usage             — Anthropic-reported token usage
 *
 * Cost attribution: we apportion the paid input tokens to the system prompt
 * by the bytes-ratio (system.bytes / outbound.bytes). This is an approximation
 * but defensible — bytes track tokens closely for English/code text, and the
 * apportionment is monotone in system size which is what the story needs.
 *
 * Pure: takes an array of payloads, returns a JSON-serializable summary.
 * No I/O, no fs reads — testable.
 */

const { getPrice } = require('../cost/prices');

function aggregate(payloads) {
  const out = {
    exchanges:           0,
    exchanges_with_usage: 0,
    models:              {},   // model → count
    bytes: {
      system_shipped:    0,    // sum of system.bytes across all exchanges
      total_outbound:    0,    // sum of byteCount.after
      total_inbound:     0,    // sum of responseMeta.bytes
    },
    tokens: {
      input_fresh:       0,    // billed at price.in
      input_cached:      0,    // billed at price.cache_read (cache_read_input_tokens)
      input_cache_write: 0,    // billed at price.cache_write (cache_creation_input_tokens)
      output:            0,
    },
    cost: {
      actual_usd:        0,    // what you actually pay
      uncached_usd:      0,    // hypothetical: if every cached token were billed fresh
      cache_savings_usd: 0,    // uncached - actual (always ≥ 0)
    },
    attribution: {
      system_prompt: { share_pct: 0, actual_usd: 0, uncached_usd: 0 },
      your_content:  { share_pct: 0, actual_usd: 0, uncached_usd: 0 },
    },
  };

  if (!Array.isArray(payloads) || !payloads.length) return out;

  // Sum exchange-level numbers and per-exchange apportion.
  let attribSystemActual = 0, attribSystemUncached = 0;
  let attribUserActual   = 0, attribUserUncached   = 0;

  for (const p of payloads) {
    out.exchanges += 1;
    const model = p.model || p.response?.model || 'default';
    out.models[model] = (out.models[model] || 0) + 1;

    const sysBytes  = p.system?.bytes || 0;
    const sentBytes = p.byteCount?.after || 0;
    const inBytes   = p.responseMeta?.bytes || 0;
    out.bytes.system_shipped += sysBytes;
    out.bytes.total_outbound += sentBytes;
    out.bytes.total_inbound  += inBytes;

    const usage = p.response?.usage;
    if (!usage) continue;
    out.exchanges_with_usage += 1;

    const fresh       = usage.input_tokens || 0;
    const cacheRead   = usage.cache_read_input_tokens || 0;
    const cacheWrite  = usage.cache_creation_input_tokens || 0;
    const outputT     = usage.output_tokens || 0;

    out.tokens.input_fresh       += fresh;
    out.tokens.input_cached      += cacheRead;
    out.tokens.input_cache_write += cacheWrite;
    out.tokens.output            += outputT;

    const price = getPrice(model);
    const actual = (fresh / 1e6) * price.in
                 + (cacheRead / 1e6) * price.cache_read
                 + (cacheWrite / 1e6) * price.cache_write
                 + (outputT / 1e6) * price.out;
    const uncached = ((fresh + cacheRead + cacheWrite) / 1e6) * price.in
                   + (outputT / 1e6) * price.out;
    out.cost.actual_usd   += actual;
    out.cost.uncached_usd += uncached;

    // Apportion this exchange's input cost between system-prompt and "your content"
    // by the bytes-ratio. Output tokens are NOT system-attributed (model writes them).
    const inputActual   = actual - (outputT / 1e6) * price.out;
    const inputUncached = uncached - (outputT / 1e6) * price.out;
    const ratio = sentBytes > 0 ? Math.max(0, Math.min(1, sysBytes / sentBytes)) : 0;
    attribSystemActual   += inputActual   * ratio;
    attribSystemUncached += inputUncached * ratio;
    attribUserActual     += inputActual   * (1 - ratio);
    attribUserUncached   += inputUncached * (1 - ratio);
  }

  out.cost.cache_savings_usd = Math.max(0, out.cost.uncached_usd - out.cost.actual_usd);

  // The split below is INPUT-only because that's where the system prompt
  // contributes; output tokens belong to "your content" in the model's reply.
  out.attribution.system_prompt.actual_usd   = attribSystemActual;
  out.attribution.system_prompt.uncached_usd = attribSystemUncached;
  out.attribution.your_content.actual_usd    = attribUserActual + (out.cost.actual_usd - attribSystemActual - attribUserActual);
  out.attribution.your_content.uncached_usd  = attribUserUncached + (out.cost.uncached_usd - attribSystemUncached - attribUserUncached);

  const totalInputActual = attribSystemActual + attribUserActual;
  out.attribution.system_prompt.share_pct =
    totalInputActual > 0 ? (attribSystemActual / totalInputActual) * 100 : 0;
  out.attribution.your_content.share_pct =
    totalInputActual > 0 ? 100 - out.attribution.system_prompt.share_pct : 0;

  return out;
}

module.exports = { aggregate };
