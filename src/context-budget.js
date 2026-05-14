'use strict';

/**
 * context-budget.js — per-tool context budget enforcement.
 *
 * Pure function. Given a string output and a token cap (positive integer),
 * returns either the input untouched or a clipped version with a one-line
 * marker that mirrors distill()'s convention. Token estimate is the same
 * char/4 rule used throughout the project (see boundary.js, analyzer.js).
 *
 * Returns:
 *   { content: string, clipped: boolean,
 *     raw_tokens: number, kept_tokens: number, prevented_tokens: number }
 *
 * The caller (interceptor.runOneRound) applies this AFTER any existing
 * transform/distill so context-budget is the final clip before the tool
 * result re-enters the model's next request.
 */

const CHARS_PER_TOKEN = 4;

function estTokens(s) {
  if (typeof s !== 'string' || !s) return 0;
  return Math.ceil(Buffer.byteLength(s, 'utf8') / CHARS_PER_TOKEN);
}

function enforceContextBudget(output, maxTokens) {
  if (typeof output !== 'string' || !output) {
    return {
      content: output || '',
      clipped: false,
      raw_tokens: 0,
      kept_tokens: 0,
      prevented_tokens: 0,
    };
  }
  // No cap or invalid cap → pass through. Caller is responsible for validating
  // the policy value, but be defensive: never fall closed on a bad config.
  if (typeof maxTokens !== 'number' || !Number.isFinite(maxTokens) || maxTokens <= 0) {
    const tok = estTokens(output);
    return {
      content: output, clipped: false,
      raw_tokens: tok, kept_tokens: tok, prevented_tokens: 0,
    };
  }
  const rawTokens = estTokens(output);
  if (rawTokens <= maxTokens) {
    return {
      content: output, clipped: false,
      raw_tokens: rawTokens, kept_tokens: rawTokens, prevented_tokens: 0,
    };
  }
  // Cut by chars (≈ tokens × 4), preserving valid UTF-8 by using slice on the
  // string (JS strings are UTF-16, but the char/4 estimate is an estimate —
  // we don't claim exactness, only approximation marked with '~').
  const charBudget = maxTokens * CHARS_PER_TOKEN;
  const cut = output.slice(0, charBudget);
  const cutTokens = estTokens(cut);
  // "Prevented" is the count of ORIGINAL tool-output tokens that did not
  // make it into the model's next request. The informational marker added
  // below counts toward kept_tokens (it is in the prompt) but must not
  // shrink prevented_tokens — the bytes that came from the tool itself are
  // gone whether the marker is appended or not.
  const preventedTokens = Math.max(0, rawTokens - cutTokens);
  const clipped = cut +
    `\n\n[Occasio: ~${preventedTokens}t cut by context_budget (max ${maxTokens}t). Full output not re-sent to model.]`;
  const keptTokens = estTokens(clipped);
  return {
    content: clipped,
    clipped: true,
    raw_tokens: rawTokens,
    kept_tokens: keptTokens,
    prevented_tokens: preventedTokens,
  };
}

module.exports = { enforceContextBudget, estTokens };
