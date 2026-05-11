'use strict';

/**
 * Pipeline — the canonical orchestration for a single boundary event.
 *
 *     adapter (in caller)  →  policy.evaluate  →  dispatcher.dispatch  →  auditor.record
 *
 * The pipeline does not own state. It is a pure orchestration function:
 * given an event, the layers, and any per-call context, it returns a Result.
 *
 * Stage 1: this function exists and has clean contracts, but the index.js
 * request handler does not yet call it. Stage 2 migrates the request path
 * onto the pipeline; for now it is exercised by tests and `processToolEvent`
 * provides a wired end-to-end demonstration with the default layers.
 */

/**
 * Run one BoundaryEvent through the pipeline with caller-provided layers.
 *
 * @param {object} args
 * @param {object} args.event       BoundaryEvent
 * @param {object} args.policy      { evaluate(event) → Decision }
 * @param {object} args.dispatcher  { dispatch(event, decision, ctx) → Result }
 * @param {object} [args.auditor]   { record(event, decision, result) }
 * @param {object} [args.ctx]       Per-call context forwarded to dispatcher
 * @returns {object} { event, decision, result }
 */
async function process({ event, policy, dispatcher, auditor, ctx }) {
  const decision = policy.evaluate(event);
  const result   = await dispatcher.dispatch(event, decision, ctx);
  if (auditor && typeof auditor.record === 'function') {
    // v0.6.4: auditor.record now returns { ok, error, droppedRow }. A failed
    // append is session-fatal — propagate as AuditWriteError so the proxy
    // can abort before the cloud call completes. A missing audit row must
    // not coexist with a successful tool dispatch.
    const status = auditor.record(event, decision, result);
    if (status && status.ok === false) {
      const { AuditWriteError } = require('../audit/errors');
      throw new AuditWriteError(status.error, status.droppedRow);
    }
  }
  return { event, decision, result };
}

/**
 * Convenience: run one BoundaryEvent through the default Stage 1 layers
 * (policy.engine, executor.dispatcher, optional auditor). This is the wired
 * demonstration of the architecture; index.js does not yet call it for the
 * proxy's request flow — Stage 2 owns that migration.
 *
 * @param {object} event   BoundaryEvent
 * @param {object} [opts]  { auditor, ctx }
 */
async function processToolEvent(event, opts = {}) {
  const policy     = require('../policy/engine');
  const dispatcher = require('../executor/dispatcher');
  return process({
    event,
    policy,
    dispatcher,
    auditor: opts.auditor,
    ctx:     opts.ctx,
  });
}

module.exports = { process, processToolEvent };
