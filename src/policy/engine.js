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
const { PASS, LOCAL, BLOCK, TRANSFORM, TRANSFORM_CHAIN } = require('../core/decision');
const loader = require('./loader');
const builtIn = require('./built-in-classifiers');
const toolNames = require('../core/tool-names');
const { scanSecrets } = require('../analyzer');
const { extractShellReadPaths, extractCommandPathTokens } = require('./shell-path');

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

// deny_paths / allow_paths matching lives in one shared module so the tool-call
// gate (here) and the outbound auto-context gate (src/outbound-policy.js) can
// never drift on glob vs prefix semantics.
const { normCase, matchesPrefix, isGlobEntry, globToRegExp, pathMatchesEntry } = require('./path-match');

/**
 * Apply deny_paths / allow_paths to a single absolute path string.
 * Returns a BLOCK Decision if denied/not-allowed, null otherwise.
 */
function evaluatePathAgainstPolicy(resolvedAbsPath, policy) {
  if (!resolvedAbsPath) return null;

  const denyPaths  = policy.deny_paths  || [];
  const allowPaths = policy.allow_paths || [];

  for (const denyPath of denyPaths) {
    if (pathMatchesEntry(resolvedAbsPath, denyPath)) {
      return BLOCK(
        { type: 'policy', reason: 'path-denied' },
        'path-denied'
      );
    }
  }

  if (allowPaths.length > 0) {
    const allowed = allowPaths.some(ap => pathMatchesEntry(resolvedAbsPath, ap));
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
 * Does a raw input path fall under a raw policy prefix? Resolves both the same
 * way enforcement does (~ expansion + realpath + platform case-folding) and
 * applies the safe prefix match. Exported for `occasio explain` to re-derive
 * which deny_paths/allow_paths entry produced a block (the matched rule is not
 * stored in the audit row).
 */
function pathPrefixMatch(rawInputPath, rawPrefix) {
  if (typeof rawInputPath !== 'string' || typeof rawPrefix !== 'string') return false;
  const i = resolveInputPath(rawInputPath);
  if (!i) return false;
  // Glob entries are not resolved (resolveInputPath would mangle the wildcards);
  // expand ~ only and glob-match the resolved input path.
  if (isGlobEntry(rawPrefix)) {
    const pat = rawPrefix.startsWith('~') ? require('os').homedir() + rawPrefix.slice(1) : rawPrefix;
    return globToRegExp(pat).test(i.replace(/\\/g, '/'));
  }
  const d = resolveInputPath(rawPrefix);
  if (!d) return false;
  return matchesPrefix(normCase(i), normCase(d));
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

  // Verb-agnostic DENY backstop: a shell can read a file a thousand ways
  // (less / awk / cp / grep / dd / python -c …). Rather than enumerate verbs,
  // test every path-like token in the command against deny_paths only. This is
  // what makes a sensitive *file* (e.g. `**/.env`) tool-agnostic instead of
  // depending on a command-string coincidence. Deny-only: it can add a block,
  // never grant access, so over-inclusion stays safe (allow_paths is enforced
  // only on the precise read-operand pass above).
  if (denyPaths.length > 0) {
    for (const p of extractCommandPathTokens(command)) {
      const resolved = (() => {
        try { return fs.realpathSync(p); } catch { return path.resolve(p); }
      })();
      for (const denyPath of denyPaths) {
        if (pathMatchesEntry(resolved, denyPath)) {
          return BLOCK({ type: 'policy', reason: 'path-denied' }, 'path-denied');
        }
      }
    }
  }
  return null;
}

/**
 * Identity gate — hard deny (v2). Tests the shell command string against the
 * compiled `deny_commands` rules ([{ label, regex }]). First match wins; the
 * label is the deny reason. Fail-closed by construction: a match always blocks.
 * Returns a BLOCK Decision on match, null otherwise.
 */
function checkDenyCommands(toolInput, policy) {
  const rules = policy.deny_commands || [];
  if (rules.length === 0) return null;
  const command = toolInput && toolInput.command;
  if (typeof command !== 'string' || !command) return null;

  const { classify } = require('./identity-classifier');
  for (const { label, regex } of rules) {
    if (regex.test(command)) {
      const block = BLOCK(
        { type: 'policy', reason: label, message: `denied: ${label}` },
        label
      );
      // Tag identity-bearing denials so the auditor records a rich identity
      // event. A plain command deny (classifier returns null) is left untagged.
      const cls = classify(command);
      if (cls) {
        block.identity = {
          event_type:     cls.action === 'secret_identity_access'
            ? 'secret_identity_access_blocked'
            : 'identity_borrow_denied',
          identity_type:  cls.identity_type,
          target_class:   cls.target_class,
          risk:           cls.risk,
          matched_rule:   label,
          classification: cls.action,
          classify_reason: cls.reason,
          decided_by:     'policy',
        };
      }
      return block;
    }
  }
  return null;
}

// Control-plane mutations an AI agent must never perform: approving/denying its
// own borrow, or changing the authorizing identity. Matches an occasio
// invocation (occasio / oc / occasio.js / npx occasio) followed by a mutating
// subcommand. Best-effort on the invocation spelling; the `~/.occasio/**`
// deny_paths backstop covers direct file forgery of the store/identity.
const CONTROL_PLANE_RE =
  /(?:\boccasio\b|\boc\b|occasio\.js|npx\s+occasio)[\s\S]*?\b(?:approvals\s+(?:approve|deny)|identity\s+set)\b/i;

// P0 single-agent approval actor (request and lookup must use the same value).
const APPROVAL_ACTOR = 'ai_agent';

/**
 * Built-in control-plane guard (always on). Hard-BLOCK an agent shell command
 * that would mutate the approval control plane. Returns a BLOCK Decision or null.
 */
function checkControlPlane(toolInput) {
  const command = toolInput && toolInput.command;
  if (typeof command !== 'string' || !command) return null;
  if (!CONTROL_PLANE_RE.test(command)) return null;
  const message =
    'Denied: an AI agent may not mutate the approval control plane ' +
    '(approvals approve/deny, identity set). A human authorizes out-of-band, ' +
    'in their own terminal.';
  return Object.assign(
    BLOCK({ type: 'policy', reason: 'control_plane_denied', message }, 'control_plane_denied'),
    {
      identity: {
        event_type:      'control_plane_blocked',
        identity_type:   'control_plane',
        target_class:    'secrets',
        risk:            'high',
        matched_rule:    'control_plane_guard',
        classification:  'control_plane',
        classify_reason: 'control_plane_mutation',
      },
    }
  );
}

/**
 * Identity gate — approval (v2). Tests the shell command against the compiled
 * `identity_approval` rules. On the first match, enriches with the built-in
 * identity classifier and returns a fail-closed approval-required BLOCK.
 *
 * P0 posture: there is no approval store yet, so a matched identity borrow is
 * always blocked with a clear "requires human approval" refusal. An AI agent
 * may request an identity; it may not silently assume one. The approval id +
 * re-attempt flow is a follow-up; until then this never silently allows.
 *
 * Returns a BLOCK Decision on match, null otherwise.
 */
function checkIdentityApproval(toolInput, policy) {
  const rules = policy.identity_approval || [];
  if (rules.length === 0) return null;
  const command = toolInput && toolInput.command;
  if (typeof command !== 'string' || !command) return null;

  const { classify } = require('./identity-classifier');
  const { commandHash, normalizeCommand } = require('./command-normalize');

  for (const rule of rules) {
    if (!rule.regex.test(command)) continue;

    // Enrich with the classifier; fall back to the rule's own fields.
    const cls = classify(command) || {};
    const identityType = cls.identity_type || rule.label;
    const targetClass  = cls.target_class  || rule.target_class || 'unknown';
    const risk         = cls.risk          || 'high';

    const store        = require('./identity-store').getStore();
    const command_hash = commandHash(command);
    // P0: single agent — scope the token to the canonical agent actor. lookup and
    // requestApproval use the same value so they pair. (Per-agent scoping later.)
    const actor        = APPROVAL_ACTOR;

    // ── valid one-time token? → tagged PASS (the re-attempt passes through). ──
    // lookup is READ-ONLY (no consume here); runToolLoop consumes once at the
    // PASS decision (the single write point that has the auditor).
    const token = store.lookup({ command_hash, actor });
    if (token) {
      return Object.assign(
        PASS('identity_approved'),
        {
          identityApprovalGranted: true,
          approval_id:             token.id,
          command_hash,
          identity_requested:      identityType,
          target_class:            targetClass,
          risk,
          identity: {
            event_type:      'identity_borrow_consumed',
            identity_type:   identityType,
            target_class:    targetClass,
            risk,
            matched_rule:    rule.label,
            classification:  cls.action || 'identity_borrow',
            classify_reason: cls.reason || rule.reason,
            approval_id:     token.id,
            approved_by:     token.approved_by,
            identity_source: token.identity_source,
          },
        }
      );
    }

    // ── no token → record/refresh the pending request and deny it. ──
    // requestApproval is an idempotent upsert (safe under the evaluate-twice path).
    const apr = store.requestApproval({
      command_hash, normalized_command: normalizeCommand(command),
      actor, identity_type: identityType, target_class: targetClass, risk,
    });
    const message =
      `Denied: ${identityType} requires human approval (${rule.reason}). ` +
      `This action borrows a ${targetClass} identity; an AI agent may request it, not assume it. ` +
      `A human can authorize once with: occasio approvals approve ${apr.id} --once`;

    return Object.assign(
      BLOCK(
        { type: 'policy', reason: 'approval_required', message },
        'approval_required'
      ),
      {
        approval_required:  true,
        approval_id:        apr.id,
        identity_requested: identityType,
        target_class:       targetClass,
        risk,
        matched_rule:       rule.label,
        identity: {
          event_type:      'identity_borrow_request',
          identity_type:   identityType,
          target_class:    targetClass,
          risk,
          matched_rule:    rule.label,
          classification:  cls.action || 'identity_borrow',
          classify_reason: cls.reason || rule.reason,
          approval_id:     apr.id,
        },
      }
    );
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

  // Carry the policy's deny_patterns on any redact-secrets decision so the
  // dispatcher's path-1 redaction uses the SAME pattern set as the outbound
  // path-2 redaction (src/outbound-policy.js). Without this, a custom
  // deny_pattern secret is redacted on the auto-context stream but leaks on a
  // locally-executed tool result. Spread (not Object.assign) handles the frozen
  // TRANSFORM_CHAIN decision; only attaches when the transform redacts.
  const denyPatterns = policy.deny_patterns;
  const withRedactPatterns = (d) =>
    (denyPatterns && denyPatterns.length && d && typeof d.transform === 'string' && /redact-secrets/.test(d.transform))
      ? { ...d, extraPatterns: denyPatterns }
      : d;

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
    // One shared shell-decision core (also used by gateShellCommand → the gate
    // CLI + the PreToolUse hook), so the proxy and the hook can never diverge.
    const shellDecision = decideShellCommand(event.toolInput, policy);
    if (shellDecision) return shellDecision;
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
      return withRedactPatterns(TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'per-tool-chain'));
    }
    if (entry.transform === 'distill-output' && policy.redact_secrets_in_tool_results) {
      return withRedactPatterns(TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'per-tool-chain'));
    }
    return withRedactPatterns(TRANSFORM(entry.transform, entry.reason || 'per-tool-policy'));
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
        return withRedactPatterns(TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], reason));
      }
      if (policy.redact_secrets_in_tool_results) {
        return withRedactPatterns(TRANSFORM('redact-secrets', reason));
      }
      if (policy.distill_tool_results) {
        return TRANSFORM('distill-output', reason);
      }
      return LOCAL(entry.executor || 'native', reason);
    }
    // No classifier specified → unconditional LOCAL (caller's executor must
    // handle invalid input gracefully).
    if (policy.redact_secrets_in_tool_results && policy.distill_tool_results) {
      return withRedactPatterns(TRANSFORM_CHAIN(['redact-secrets', 'distill-output'], entry.reason || 'ok'));
    }
    if (policy.redact_secrets_in_tool_results) {
      return withRedactPatterns(TRANSFORM('redact-secrets', entry.reason || 'ok'));
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
  // Opt-in (policy.entropy_secret_detection, default off): also run the richer
  // prefix/JWT/.env/entropy detectors. Lazy-require so the module only loads
  // when enabled; default-off keeps the existing scanSecrets path unchanged.
  const richDetect = (policy.entropy_secret_detection === true)
    ? require('../scanner/detectors').detectSecrets : null;
  for (const r of toolResults || []) {
    if (typeof r?.content !== 'string') continue;
    for (const hit of scanSecrets(r.content, extraPatterns ? { extraPatterns } : undefined)) {
      secrets.push({ ...hit, tool_use_id: r.tool_use_id });
    }
    if (richDetect) {
      for (const hit of richDetect(r.content)) {
        secrets.push({ ...hit, tool_use_id: r.tool_use_id });
      }
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

/**
 * Gate a single shell command string against the identity gate, in the same
 * order the live engine uses (path policy → deny_commands → identity_approval).
 * Returns the BLOCK Decision that would fire, or a PASS Decision if the command
 * is allowed. Shared by `occasio gate` and (later) the PreToolUse hook so the
 * CLI preview and live enforcement can never disagree.
 *
 * @param {string} command  raw shell command
 * @param {object} [policy] policy object (defaults to the active policy)
 * @returns {object} Decision (PASS or BLOCK)
 */
function gateShellCommand(command, policy) {
  const pol = policy || loader.load();
  const d = decideShellCommand({ command }, pol);
  return d || PASS('allow');
}

/**
 * The single shell-decision core, in the load-bearing order
 * control-plane → path → deny_commands → identity_approval. Returns the BLOCK or
 * approval decision, or null when the command is not gated by any of them. Both
 * `evaluate` (proxy) and `gateShellCommand` (gate CLI + PreToolUse hook) call
 * this, so the two enforcement points cannot drift (a parity test pins it).
 */
function decideShellCommand(toolInput, policy) {
  // Control-plane guard FIRST (always on, structural): an actor=ai_agent may
  // never mutate the approval control plane — self-approval would forge the
  // provenance the gate sells. The human authorizes out-of-band.
  const cp = checkControlPlane(toolInput);
  if (cp) return cp;
  // Path enforcement (deny_paths / allow_paths over shell-mediated reads).
  const pathBlock = checkShellPathPolicy(toolInput, policy);
  if (pathBlock) return pathBlock;
  // Hard deny (deny_commands).
  const denyBlock = checkDenyCommands(toolInput, policy);
  if (denyBlock) return denyBlock;
  // Identity-borrow approval: valid token → grant (PASS); else fail-closed BLOCK.
  const approvalDecision = checkIdentityApproval(toolInput, policy);
  if (approvalDecision) return approvalDecision;
  return null;
}

module.exports = { evaluate, evaluateToolResults, evaluateRequest, pathPrefixMatch, primaryInputPath, gateShellCommand, decideShellCommand };
