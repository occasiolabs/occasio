'use strict';

/**
 * Agent router — picks an adapter for an incoming proxy request.
 *
 * Detection signal: the `x-occasio-agent` HTTP header.
 *   - Header value matches a registered agent → that adapter.
 *   - Header missing or unknown               → claude-code (default).
 *
 * The header is Occasio-internal: callers (Cline, etc.) set it; the
 * proxy strips it before forwarding to Anthropic.
 *
 * This module deliberately knows about no specific adapter. Adapters are
 * passed in as a map by the proxy bootstrap. That keeps this file
 * agent-agnostic and testable in isolation.
 */

/**
 * Content fingerprint — given an Anthropic SSE response buffer and the
 * registry, find the agent whose tool-name map best matches the tool blocks
 * in the response. Returns the agentId or null if no agent claims any name.
 *
 * Used as a fallback signal when the explicit header is absent (e.g., the
 * user's tool doesn't expose a custom-headers UI). Content fingerprint is
 * deterministic and cannot misroute Claude Code traffic — Claude Code's
 * tool names (`Read`, `Bash`) only exist in the claude-code map.
 */
function detectAgentFromSse(sseBody, adapters, registry) {
  if (!sseBody || !adapters || !registry) return null;
  try {
    const { parseSSE } = require('../interceptor');
    const parsed = parseSSE(sseBody);
    const blocks = parsed && parsed.blocks ? Object.values(parsed.blocks) : [];
    const names = blocks.filter(b => b && b.type === 'tool_use').map(b => b.name);
    if (!names.length) return null;

    let best = null;
    let bestScore = 0;
    for (const agentId of Object.keys(adapters)) {
      const score = names.reduce(
        (n, name) => n + (registry.toCanonical(agentId, name) ? 1 : 0),
        0,
      );
      if (score > bestScore) { best = agentId; bestScore = score; }
    }
    return bestScore > 0 ? best : null;
  } catch {
    return null;
  }
}

/**
 * Pick an adapter for an incoming proxy request.
 *
 * Resolution order:
 *   1. Explicit header  `x-occasio-agent`  → that adapter
 *   2. Content fingerprint (when sseBody + registry supplied)
 *   3. defaultAgent
 *
 * @param {object} headers
 * @param {object} adapters       { [agentId]: adapterModule, ... }
 * @param {string} defaultAgent   agentId to pick when nothing else matches
 * @param {object} [opts]         { sseBody, registry } for content fingerprint
 * @returns {{ adapter, agentId, source: 'header' | 'fingerprint' | 'default' }}
 */
function selectAdapter(headers, adapters, defaultAgent, opts = {}) {
  const raw = headers && headers['x-occasio-agent'];
  if (typeof raw === 'string') {
    const id = raw.trim().toLowerCase();
    if (adapters && adapters[id]) {
      return { adapter: adapters[id], agentId: id, source: 'header' };
    }
  }

  // Content fingerprint — used when the header is missing or the tool's
  // request configuration didn't forward it. Only fires when sseBody and
  // registry are provided (proxy supplies them; unit tests can omit).
  if (opts.sseBody && opts.registry) {
    const detected = detectAgentFromSse(opts.sseBody, adapters, opts.registry);
    if (detected && detected !== defaultAgent) {
      return { adapter: adapters[detected], agentId: detected, source: 'fingerprint' };
    }
  }

  if (!adapters || !adapters[defaultAgent]) {
    throw new Error(`agent-router: defaultAgent "${defaultAgent}" not in adapters map`);
  }
  return { adapter: adapters[defaultAgent], agentId: defaultAgent, source: 'default' };
}

const HEADER_NAME = 'x-occasio-agent';

module.exports = { selectAdapter, detectAgentFromSse, HEADER_NAME };
