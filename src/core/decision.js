'use strict';

/**
 * Decision — the result of evaluating policy against a BoundaryEvent.
 *
 * The policy engine produces a Decision; the dispatcher acts on it.
 * Decisions are pure data: no functions, no closures. They can be logged
 * and replayed.
 *
 * Stage 1: minimal shape. `policySource` is always 'default' until Stage 2
 * introduces user-authored YAML rules.
 */

const ACTIONS = ['PASS', 'LOCAL', 'TRANSFORM', 'BLOCK'];

/**
 * Build a Decision.
 *
 * @param {object} input
 * @param {'PASS'|'LOCAL'|'TRANSFORM'|'BLOCK'} input.action
 * @param {string} input.reason          Stable code, e.g. 'native-handleable'
 * @param {string} [input.policySource]  'default' in Stage 1
 * @param {string} [input.executor]      Required when action === 'LOCAL'
 * @param {string} [input.transform]     Required when action === 'TRANSFORM'
 * @param {object} [input.syntheticResponse]  Required when action === 'BLOCK'
 */
function makeDecision({ action, reason, policySource = 'default', executor, transform, syntheticResponse }) {
  if (!ACTIONS.includes(action)) {
    throw new Error(`Decision.action must be one of ${ACTIONS.join('/')} — got ${action}`);
  }
  if (!reason) throw new Error('Decision.reason is required');
  if (action === 'LOCAL'     && !executor)          throw new Error('Decision.executor is required for LOCAL');
  if (action === 'TRANSFORM' && !transform)         throw new Error('Decision.transform is required for TRANSFORM');
  if (action === 'BLOCK'     && !syntheticResponse) throw new Error('Decision.syntheticResponse is required for BLOCK');
  return { action, reason, policySource, executor, transform, syntheticResponse };
}

// Convenience constructors for the common cases.
const PASS      = (reason, policySource)              => makeDecision({ action: 'PASS',      reason, policySource });
const LOCAL     = (executor, reason, policySource)    => makeDecision({ action: 'LOCAL',     reason, policySource, executor });
const TRANSFORM = (transform, reason, policySource)   => makeDecision({ action: 'TRANSFORM', reason, policySource, transform });
const BLOCK     = (syntheticResponse, reason, policySource) =>
  makeDecision({ action: 'BLOCK', reason, policySource, syntheticResponse });

/**
 * Build a chained TRANSFORM decision that applies multiple named transforms
 * in sequence. `transforms` must be an ordered array of ≥ 2 names.
 *
 * The `transform` field on the decision is set to `transforms.join('+')` so
 * audit consumers that only read the scalar field see a stable, readable name.
 * The dispatcher reads `decision.transforms` (array) to execute the chain.
 */
const TRANSFORM_CHAIN = (transforms, reason, policySource) => {
  if (!Array.isArray(transforms) || transforms.length < 2) {
    throw new Error('TRANSFORM_CHAIN requires an array of at least 2 transforms');
  }
  const d = makeDecision({ action: 'TRANSFORM', reason: reason || 'chain', policySource, transform: transforms.join('+') });
  return Object.freeze({ ...d, transforms });
};

module.exports = { makeDecision, PASS, LOCAL, TRANSFORM, TRANSFORM_CHAIN, BLOCK, ACTIONS };
