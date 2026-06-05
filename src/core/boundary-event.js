'use strict';

/**
 * BoundaryEvent — the canonical record of one cross-boundary interaction
 * between an AI agent and the user's machine.
 *
 * Every cross-boundary event in the system flows through this shape.
 * Adapters produce them; policy evaluates them; executors act on them;
 * auditors record them; observability reads them.
 *
 * Stage 1: the shape is minimal. Speculative fields are deliberately omitted.
 * Add fields only when there is live evidence that a downstream layer needs them.
 *
 * Hard rule for the `raw` field: only the adapter touches it. The pipeline
 * never introspects it. If a downstream layer needs a value out of `raw`,
 * the adapter must promote it to a normalized field first.
 */

const { randomUUID } = require('crypto');

/**
 * Build a BoundaryEvent. All optional fields default to undefined.
 *
 * @param {object} input
 * @param {'outbound'|'inbound'} input.direction
 * @param {'request'|'tool_call'|'tool_result'|'response'} input.kind
 * @param {string} input.agent           Stable agent identity, e.g. 'claude-code'
 * @param {string} input.protocol        Stable protocol identity, e.g. 'anthropic-http'
 * @param {string} [input.sessionId]
 * @param {string} [input.runId]
 * @param {string} [input.toolName]      Canonical tool name (mapped by adapter)
 * @param {object} [input.toolInput]     Canonical input shape
 * @param {object|string} [input.toolResult]
 * @param {object|string} [input.payload]
 * @param {unknown}  [input.raw]         Adapter-private; opaque to other layers
 * @param {string} [input.actorType]    Who is acting. Default 'ai_agent'. Used
 *   by the identity gate's audit rows (an agent is an untrusted actor that may
 *   request, not assume, an identity).
 * @param {string} [input.trustLevel]   Trust level of the actor. Default
 *   'untrusted'.
 * @param {object} [input.delegator]    Who the actor acts on behalf of
 *   ({ type, id }). Optional; the auditor resolves a default when absent.
 */
function makeBoundaryEvent({
  direction,
  kind,
  agent,
  protocol,
  sessionId,
  runId,
  toolName,
  toolInput,
  toolResult,
  payload,
  raw,
  actorType,
  trustLevel,
  delegator,
}) {
  if (!direction) throw new Error('BoundaryEvent.direction is required');
  if (!kind)      throw new Error('BoundaryEvent.kind is required');
  if (!agent)     throw new Error('BoundaryEvent.agent is required');
  if (!protocol)  throw new Error('BoundaryEvent.protocol is required');

  return {
    id:        randomUUID(),
    timestamp: new Date().toISOString(),
    sessionId,
    runId,
    agent,
    protocol,
    direction,
    kind,
    toolName,
    toolInput,
    toolResult,
    payload,
    raw,
    // Identity-gate actor context. Defaulted so existing callers/tests that
    // omit them keep working unchanged.
    actorType:  actorType  || 'ai_agent',
    trustLevel: trustLevel || 'untrusted',
    delegator:  delegator,
  };
}

const KINDS      = ['request', 'tool_call', 'tool_result', 'response'];
const DIRECTIONS = ['outbound', 'inbound'];

module.exports = { makeBoundaryEvent, KINDS, DIRECTIONS };
