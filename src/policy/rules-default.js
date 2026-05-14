'use strict';

/**
 * Default rule set — Stage 2.
 *
 * In Stage 2 the policy file at ~/.occasio/policy.yml supplies two
 * named decisions; everything else is still produced by the legacy
 * classifier (`interceptor.classifyBlock`).
 *
 *   1. tool_call where adapter.classify(event).handled === true
 *      → LOCAL (executor='native')
 *      Source: `policy.engine::evaluate` delegating to classifyBlock.
 *      (Stage 3 will move tool routing into the YAML rule set.)
 *
 *   2. tool_call where adapter.classify(event).handled === false
 *      → PASS (forwarded to Anthropic for cloud-side execution)
 *
 *   3. tool_result content matching SECRET_PATTERNS
 *      → policy.evaluateToolResults reads `block_secrets_in_tool_results`
 *      → BLOCK in `block_secrets` mode, PASS+surface-secrets otherwise
 *      Implemented in `policy.engine::evaluateToolResults`. STAGE 2.
 *
 *   4. session.cost ≥ budget
 *      → policy.evaluateRequest reads `block_requests_over_budget`
 *      → BLOCK with HTTP 402 synthetic response
 *      Implemented in `policy.engine::evaluateRequest`. STAGE 2.
 *
 * Default policy values (DEFAULT_POLICY in `policy/loader.js`):
 *
 *   block_secrets_in_tool_results: true
 *   block_requests_over_budget:    true
 *
 * Users override by writing ~/.occasio/policy.yml.
 */

module.exports = {};
