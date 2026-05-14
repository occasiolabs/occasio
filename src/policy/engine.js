'use strict';

/**
 * PolicyEngine — evaluates a BoundaryEvent and returns a Decision.
 *
 * Stage 1: rules are hard-coded by delegating to existing classifiers
 * (interceptor.classifyBlock for tool calls; analyzer.scanSecrets for content).
 * The engine emits canonical Decision objects; downstream layers (dispatcher,
 * auditor) act on the Decision, not on the legacy classifyBlock shape.
 *
 * Stage 2 will replace the body of `evaluate` with a YAML-driven rule
 * evaluator. The contract of this module — `evaluate(event) → Decision` —
 * stays stable across that change.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const adapter = require('../adapters/claude-code');
const { PASS, LOCAL, BLOCK, TRANSFORM, TRANSFORM_CHAIN } = require('../core/decision');
const loader = require('./loader');
const builtIn = require('./built-in-classifiers');
const toolNames = require('../core/tool-names');
const { scanSecrets } = require('../analyzer');
const { extractShellReadPaths } = require('./shell-path');

// ── Path-based access control (ARCH-27) ──────────────────────────────────────

const PATH_BEARING_TOOLS = new Set(['read_file', 'find_files', 'grep']);
const SHELL_TOOLS        = new Set(['shell_bash', 'shell_powershell']);

/** Extract the primary filesystem path from a tool's inputs. */
function primaryInputPath(toolName, toolInput) {
  if (!toolInput) return null;
  if (toolName === 'read_file')  return toolInput.file_path  || null;
  if (toolName === 'find_files') return toolInput.path       || null;
  if (toolName === 'grep')       return toolInput.path       || null;
  return null;
}

/**
 * Resolve an input path to its canonical absolute form, following symlinks
 * where the file exists. Falls back to path.resolve() for non-existent paths.
 */
function resolveInputPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return null;
  const expanded = rawPath.startsWith('~') ? os.homedir() + rawPath.slice(1) : rawPath;
  try {
    return fs.realpathSync(expanded);
  } catch {
    return path.resolve(expanded);
  }
}

/**
 * Safe prefix match: prevents ~/.aws from matching ~/.awskeys.
 * On Windows, comparison is case-insensitive.
 */
function matchesPrefix(inputNorm, denyNorm) {
  return inputNorm === denyNorm || inputNorm.startsWith(denyNorm + path.sep);
}

const normCase = process.platform === 'win32'
  ? (p) => p.toLowerCase()
  : (p) => p;

/**
 * Apply deny_paths / allow_paths to a single absolute path string.
 * Returns a BLOCK Decision if denied/not-allowed, null otherwise.
 */
function evaluatePathAgainstPolicy(resolvedAbsPath, policy) {
  if (!resolvedAbsPath) return null;
  const inputNorm = normCase(resolvedAbsPath);

  const denyPaths  = policy.deny_paths  || [];
  const allowPaths = policy.allow_paths || [];

  for (const denyPath of denyPaths) {
    if (matchesPrefix(inputNorm, normCase(denyPath))) {
      return BLOCK(
        { type: 'policy', reason: 'path-denied' },
        'path-denied'
      );
    }
  }

  if (allowPaths.length > 0) {
    const allowed = allowPaths.some(ap => matchesPrefix(inputNorm, normCase(ap)));
    if (!allowed) {
      return BLOCK(
        { type: 'policy', reason: 'path-not-allowed' },
        'path-not-allowed'
      );
    }
  }
  return null;
}

/**
 * Check a tool input path against deny_paths and allow_paths.
 * Returns a BLOCK Decision if the path is denied/not-allowed, null otherwise.
 */
function checkPathPolicy(toolName, toolInput, policy) {
  const rawPath = primaryInputPath(toolName, toolInput);
  if (!rawPath) return null;
  const resolved = resolveInputPath(rawPath);
  return evaluatePathAgainstPolicy(resolved, policy);
}

/**
 * Shell-mediated read enforcement: close the deny_paths bypass via
 * `cat` / `Get-Content` / `head` / `tail` / `type` / `bat`.
 *
 * Walks the shell command for every file path the native handler would
 * actually read (including across `cd … && …` / `Set-Location …; …` chains)
 * and applies deny_paths / allow_paths to each one. A denied operand denies
 * the whole command.
 */
function checkShellPathPolicy(toolInput, policy) {
  const denyPaths  = policy.deny_paths  || [];
  const allowPaths = policy.allow_paths || [];
  if (denyPaths.length === 0 && allowPaths.length === 0) return null;

  const command = toolInput && toolInput.command;
  if (typeof command !== 'string' || !command) return null;

  const paths = extractShellReadPaths(command);
  for (const p of paths) {
    // Re-resolve through realpath where the file exists so a symlink that
    // points into a denied directory is still denied (matches read_file).
    const resolved = (() => {
      try { return fs.realpathSync(p); } catch { return path.resolve(p); }
    })();
    const verdict = evaluatePathAgainstPolicy(resolved, policy);
    if (verdict) return verdict;
  }
  return null;
}

/**
 * Map a tool-call BoundaryEvent to a Decision using the legacy classifier.
 *
 * Stage 1 mapping:
 *   handled === true  → LOCAL (executor='native', reason from classifyBlock)
 *   handled === false → PASS  (reason from classifyBlock)
 *
 * Stage 2 will introduce TRANSFORM (redact / distill) and BLOCK
 * (secret / budget) decisions natively; today those still happen inside
 * legacy interceptToolUse and are not surfaced as Decisions.
 */
function evaluate(event) {
  if (!event) throw new Error('policy.evaluate requires a BoundaryEvent');

  if (event.kind !== 'tool_call') {
    return PASS('non-tool-call-event-passthrough');
  }

  const policy = loader.load();

  // Path enforcement (ARCH-27): must run before any routing decision so that
  // deny_paths / allow_paths block access regardless of tool routing config.
  if (PATH_BEARING_TOOLS.has(event.toolName)) {
    const pathBlock = checkPathPolicy(event.toolName, event.toolInput, policy);
    if (pathBlock) return pathBlock;
  }

  // Shell-mediated read enforcement: deny_paths / allow_paths also gate
  // `Bash { cat … }`, `PowerShell { Get-Content … }`, and the same shapes
  // inside cd-prefixed compound chains. Closes the bypass where shell tools
  // were unguarded because they are not in PATH_BEARING_TOOLS.
  if (SHELL_TOOLS.has(event.toolName)) {
    const shellBlock = checkShellPathPolicy(event.toolInput, policy);
    if (shellBlock) return shellBlock;
  }

  // Stage 3: tool routing is policy-driven. Read ~/.occasio/policy.yml's
  // `tools:` block. Default tools entries reproduce the previous hardcoded
  // routing exactly (see DEFAULT_TOOLS in loader.js).
  const tools  = (policy && policy.tools) || {};

  // Direct lookup by canonical name. If the event's toolName is an
  // agent-specific alias (e.g., test code passes 'Read' instead of
  // 'read_file'), reverse-resolve via the registry.
  let entry = tools[event.toolName];
  if (!entry && !toolNames.isCanonical(event.toolName)) {
    const canonical = toolNames.firstCanonicalFor(event.toolName);
    if (canonical) entry = tools[canonical];
  }

  // Unknown tool — preserve legacy 'tool_not_handled' reason code so dashboard
  // / fallback_reasons surfaces are unchanged.
  if (!entry) {
    return PASS('tool_not_handled');
  }

  if (entry.action === 'PASS') {
    return PASS(entry.reason || 'tool_not_handled');
  }

  // Per-tool TRANSFORM: explicit policy override. When the other global flag is
  // also active, chain the two known transforms in security-first order
  // (redact-secrets → distill-output). Unknown per-tool transforms pass through
  // without chaining — only the two built-in names participate in auto-chain.
  if (entry.action === 'TRANSFORM') {
    if (entry.transform === 'redact-secrets' && policy.distill_tool_results) {
      return TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'per-tool-chain');
    }
    if (entry.transform === 'distill-output' && policy.redact_secrets_in_tool_results) {
      return TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'per-tool-chain');
    }
    return TRANSFORM(entry.transform, entry.reason || 'per-tool-policy');
  }

  if (entry.action === 'LOCAL') {
    if (entry.classifier) {
      const cls = builtIn.lookup(entry.classifier);
      if (!cls) {
        // Policy references an unknown classifier — fail safe (PASS) and
        // surface a clear reason in fallback_reasons.
        return PASS(`unknown-classifier:${entry.classifier}`);
      }
      const result = cls(event);
      const handled = !!(result && result.handled);
      const reason  = (result && result.reason) || 'classifier-rejected';
      if (!handled) return PASS(reason);
      if (policy.redact_secrets_in_tool_results && policy.distill_tool_results) {
        return TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], reason);
      }
      if (policy.redact_secrets_in_tool_results) {
        return TRANSFORM('redact-secrets', reason);
      }
      if (policy.distill_tool_results) {
        return TRANSFORM('distill-output', reason);
      }
      return LOCAL(entry.executor || 'native', reason);
    }
    // No classifier specified → unconditional LOCAL (caller's executor must
    // handle invalid input gracefully).
    if (policy.redact_secrets_in_tool_results && policy.distill_tool_results) {
      return TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'ok');
    }
    if (policy.redact_secrets_in_tool_results) {
      return TRANSFORM('redact-secrets', entry.reason || 'ok');
    }
    if (policy.distill_tool_results) {
      return TRANSFORM('distill-output', entry.reason || 'ok');
    }
    return LOCAL(entry.executor || 'native', entry.reason || 'ok');
  }

  // Unknown action — fail safe.
  return PASS(`unknown-action:${entry.action}`);
}

/**
 * Evaluate a batch of tool_results against the secret-scan policy.
 * Returns:
 *   { action: 'PASS', secrets: [...] }     - scan ran but policy says don't block
 *   { action: 'BLOCK', secrets, syntheticResponse, reason }
 *
 * Stage 2 wiring:
 *   - Reads `block_secrets_in_tool_results` from ~/.occasio/policy.yml.
 *   - In legacy `block_secrets` mode, the policy's BLOCK is honored if
 *     enabled; in normal `intercept` mode, scan still runs (callers can
 *     surface warnings) but no block.
 *
 * @param {Array}  toolResults  tool_result content blocks
 * @param {object} ctx          { mode } the runToolLoop mode
 * @returns {object} Decision shape with extra `secrets` field for the caller.
 */
function evaluateToolResults(toolResults, ctx = {}) {
  const policy = loader.load();
  const extraPatterns = (policy.deny_patterns && policy.deny_patterns.length)
    ? policy.deny_patterns : undefined;
  const secrets = [];
  for (const r of toolResults || []) {
    if (typeof r?.content !== 'string') continue;
    for (const hit of scanSecrets(r.content, extraPatterns ? { extraPatterns } : undefined)) {
      secrets.push({ ...hit, tool_use_id: r.tool_use_id });
    }
  }
  if (secrets.length === 0) {
    return { action: 'PASS', reason: 'no-secrets-detected', secrets };
  }
  // Secrets present. Honor the policy + legacy mode contract:
  //   block_secrets_in_tool_results === true AND mode === 'block_secrets'
  //   → BLOCK with synthetic refusal
  // Otherwise: PASS but surface secrets to caller for logging.
  const blockEnabled = policy.block_secrets_in_tool_results !== false;
  if (blockEnabled && ctx.mode === 'block_secrets') {
    return Object.assign(
      BLOCK(
        { type: 'fallback', reason: `secret in tool result: ${secrets[0].label}` },
        `secret in tool result: ${secrets[0].label}`
      ),
      { secrets },
    );
  }
  return { action: 'PASS', reason: 'secrets-detected-not-blocked', secrets };
}

/**
 * Evaluate an outbound request against the budget policy.
 *
 * @param {object} ctx { sessionCost, budget }
 * @returns {object} Decision: PASS or BLOCK with synthetic 402 response.
 */
function evaluateRequest(ctx = {}) {
  const policy = loader.load();
  const { sessionCost, budget } = ctx;
  if (
    policy.block_requests_over_budget !== false &&
    typeof budget === 'number' && budget > 0 &&
    typeof sessionCost === 'number' && sessionCost >= budget
  ) {
    // syntheticResponse mirrors the legacy 402 body so the proxy can write it
    // to the wire unchanged. Stage 3 may enrich the body with policy metadata.
    return Object.assign(
      BLOCK(
        {
          status: 402,
          body: {
            error: {
              type:   'budget_exceeded',
              budget,
              spent:  sessionCost,
              by:     'Occasio',
            },
          },
        },
        'budget-exceeded'
      ),
      { sessionCost, budget },
    );
  }
  return { action: 'PASS', reason: 'within-budget' };
}

module.exports = { evaluate, evaluateToolResults, evaluateRequest };
