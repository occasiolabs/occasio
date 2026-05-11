'use strict';

/**
 * Scanner — uniform `transform(input) → { hits, content }` interface over
 * the existing secret scanner and distiller.
 *
 * Stage 1 wraps:
 *   - analyzer.scanSecrets   → secret detection on string content
 *   - distiller.distill      → content reduction for tool results
 *
 * The dispatcher's TRANSFORM branch will call these in Stage 2 when the
 * policy engine starts emitting TRANSFORM Decisions natively. For now the
 * scanner is exported as a layer module so callers can use the canonical
 * contract; legacy interceptToolUse still does its own scanner/distill calls.
 */

const { scanSecrets, redactSecrets } = require('../analyzer');
const { distill }                    = require('../distiller');

/**
 * Run the secret scanner over a string.
 * @returns {{ hits: Array<{label, line, snippet}>, content: string }}
 */
function scan(content) {
  const text = typeof content === 'string' ? content : (content?.toString?.() || '');
  return { hits: scanSecrets(text), content: text };
}

/**
 * Run the distiller against (label, content). Returns the distill result
 * unchanged so callers can choose to use the distilled or the raw form.
 */
function reduce(label, content) {
  const text = typeof content === 'string' ? content : (content?.toString?.() || '');
  return distill(label || 'tool-result', text);
}

/**
 * Redact secrets in-place: scan first (to preserve accurate line metadata),
 * then replace each match with [REDACTED:label].
 * @returns {{ hits: Array<{label, line, snippet}>, content: string }}
 */
function redact(content) {
  const text = typeof content === 'string' ? content : (content?.toString?.() || '');
  const hits = scanSecrets(text);
  return { hits, content: redactSecrets(text) };
}

module.exports = { scan, reduce, redact };
