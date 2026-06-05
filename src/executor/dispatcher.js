'use strict';

/**
 * Dispatcher — given a BoundaryEvent and a Decision, performs the action and
 * returns a Result. Pure dispatch: knows no policy, no audit, no protocol.
 *
 * Stage 1 mapping:
 *   PASS      → { passThrough: true }                      (caller forwards)
 *   LOCAL     → executes via legacy native handlers, returns { output, exitCode }
 *   TRANSFORM → reserved (Stage 2: redact / distill paths)
 *   BLOCK     → returns { blocked: true, response: decision.syntheticResponse }
 *
 * The LOCAL branch maps event.toolName to the legacy handler. Tool-name
 * literals here are a Stage 1 leak: this is acknowledged in ARCHITECTURE.md
 * and resolved in Stage 3 by introducing a canonical-name registry that the
 * adapter populates.
 */

const {
  handleReadTool,
  handleGlobTool,
  handleGrepTool,
  handleTodoWriteTool,
  handleTodoReadTool,
} = require('../runtime');

const { scanSecrets, redactSecrets } = require('../analyzer');
const { distill }                    = require('../distiller');

const { nativeHandle, expandPsEnvVars, runLocally } = require('../interceptor');
const { CANONICAL } = require('../core/tool-names');

// Stage 3: NATIVE_HANDLERS keyed on canonical tool names. The dispatcher is
// agent-agnostic; agent-specific names live in adapters and are translated
// to canonical names at the BoundaryEvent boundary.
const NATIVE_HANDLERS = {
  [CANONICAL.READ_FILE]:  (input) => handleReadTool(input),
  [CANONICAL.FIND_FILES]: (input) => handleGlobTool(input),
  [CANONICAL.GREP]:       (input) => handleGrepTool(input),
  [CANONICAL.TODO_WRITE]: (input, ctx) => handleTodoWriteTool(input, ctx?.todoStore || []),
  [CANONICAL.TODO_READ]:  (input, ctx) => handleTodoReadTool(ctx?.todoStore || []),

  // Bash: native handler first; if isInterceptable said routeLocally was OK
  // but nativeHandle returned null, fall back to the exec subprocess. The
  // returned `native` field tells the caller which path was taken.
  [CANONICAL.SHELL_BASH]: async (input) => {
    const cmd = (typeof input?.command === 'string' ? input.command : '').trim();
    if (!cmd) return null;
    const nr = nativeHandle(cmd);
    if (nr !== null) {
      return { output: nr.output, exitCode: nr.exitCode, native: true };
    }
    const r = await runLocally(cmd);
    const rawOutput = (r.stdout + (r.stderr ? `\nstderr: ${r.stderr}` : '')).trimEnd();
    return {
      output:   rawOutput || `(exit ${r.exitCode})`,
      exitCode: r.exitCode,
      native:   false,
    };
  },

  // PowerShell: expand $env:VAR (mirrors isPowerShellNativeHandleable's check)
  // then native-only execution. expandedCmd is returned so the caller can
  // record the actually-executed command in toolsRun.
  [CANONICAL.SHELL_POWERSHELL]: (input) => {
    const rawCmd = (typeof input?.command === 'string' ? input.command : '').trim();
    if (!rawCmd) return null;
    const cmd = expandPsEnvVars(rawCmd);
    const nr = nativeHandle(cmd);
    if (nr === null) {
      return { output: '(not handled natively)', exitCode: 1, native: false, expandedCmd: cmd };
    }
    const rawOutput = nr.output.trimEnd() || `(exit ${nr.exitCode})`;
    return { output: rawOutput, exitCode: nr.exitCode, native: true, expandedCmd: cmd };
  },
};

/**
 * Dispatch a Decision against an Event.
 *
 * @param {object} event     BoundaryEvent
 * @param {object} decision  Decision
 * @param {object} [ctx]     { todoStore } per-session state
 * @returns {Promise<object>} Result
 */
async function dispatch(event, decision, ctx = {}) {
  if (!decision) throw new Error('dispatcher.dispatch requires a Decision');

  switch (decision.action) {
    case 'PASS':
      return { passThrough: true, reason: decision.reason };

    case 'BLOCK':
      // Forward any identity-gate approval metadata the engine attached to the
      // Decision (via Object.assign) so the caller can render the approval UX
      // and the audit row can record what identity was requested.
      return {
        blocked:  true,
        response: decision.syntheticResponse,
        reason:   decision.reason,
        ...(decision.approval_required && { approval_required: true }),
        ...(decision.identity_requested && { identity_requested: decision.identity_requested }),
        ...(decision.target_class && { target_class: decision.target_class }),
        ...(decision.risk && { risk: decision.risk }),
      };

    case 'TRANSFORM': {
      // ── Chained transforms ─────────────────────────────────────────────────
      // When the decision carries a `transforms` array (from TRANSFORM_CHAIN),
      // execute the handler once and apply each transform in sequence. The
      // output of one step becomes the input of the next. Security-first
      // ordering (redact before distill) is enforced by the engine.
      if (Array.isArray(decision.transforms) && decision.transforms.length > 1) {
        const chainToolNames = require('../core/tool-names');
        let chainHandler = NATIVE_HANDLERS[event.toolName];
        if (!chainHandler && !chainToolNames.isCanonical(event.toolName)) {
          const canonical = chainToolNames.firstCanonicalFor(event.toolName);
          if (canonical) chainHandler = NATIVE_HANDLERS[canonical];
        }
        if (!chainHandler) {
          return { passThrough: true, reason: `transform-chain-no-handler:${event.toolName}` };
        }
        const chainRaw = await chainHandler(event.toolInput, ctx);
        if (!chainRaw) return { passThrough: true, reason: 'transform-chain-handler-returned-null' };
        if (chainRaw.passThrough) return chainRaw;

        let chainOutput = typeof chainRaw.output === 'string' ? chainRaw.output : String(chainRaw.output || '');
        let chainSecretsRedacted = [];
        let chainDistilled = false, chainSavedTokens = 0, chainLabel = null, chainRawContent = null;

        // Same deny_patterns the engine matched on (carried on the decision),
        // so path-1 redaction sees the identical secret set as path-2 outbound.
        const chainOpts = (decision.extraPatterns && decision.extraPatterns.length)
          ? { extraPatterns: decision.extraPatterns } : undefined;
        for (const tf of decision.transforms) {
          if (tf === 'redact-secrets') {
            chainSecretsRedacted = scanSecrets(chainOutput, chainOpts);
            chainOutput = redactSecrets(chainOutput, chainOpts);
          } else if (tf === 'distill-output') {
            const cmd = event.toolInput?.command || event.toolInput?.script || event.toolName || '';
            const dr = distill(cmd, chainOutput);
            chainOutput       = dr.content;
            chainDistilled    = dr.distilled;
            chainSavedTokens  = dr.savedTokens;
            chainLabel        = dr.label;
            chainRawContent   = dr.rawContent;
          }
          // Unknown transform names: skip silently (forward-compatible).
        }

        return {
          transformed:     true,
          transform:       decision.transform,    // 'redact-secrets+distill-output'
          transforms:      decision.transforms,   // array for structured consumers
          output:          chainOutput,
          secretsRedacted: chainSecretsRedacted.length ? chainSecretsRedacted : undefined,
          distilled:       chainDistilled,
          savedTokens:     chainSavedTokens,
          label:           chainLabel,
          rawContent:      chainRawContent,
          exitCode:        chainRaw.exitCode,
        };
      }

      const { transform } = decision;
      if (transform === 'redact-secrets') {
        const toolNames = require('../core/tool-names');
        let handler = NATIVE_HANDLERS[event.toolName];
        if (!handler && !toolNames.isCanonical(event.toolName)) {
          const canonical = toolNames.firstCanonicalFor(event.toolName);
          if (canonical) handler = NATIVE_HANDLERS[canonical];
        }
        if (!handler) {
          return { passThrough: true, reason: `transform-no-handler:${event.toolName}` };
        }
        const raw = await handler(event.toolInput, ctx);
        if (!raw) return { passThrough: true, reason: 'transform-handler-returned-null' };
        if (raw.passThrough) return raw;

        const output = typeof raw.output === 'string' ? raw.output : String(raw.output || '');
        const redactOpts = (decision.extraPatterns && decision.extraPatterns.length)
          ? { extraPatterns: decision.extraPatterns } : undefined;
        const secretsRedacted = scanSecrets(output, redactOpts);
        const redacted = redactSecrets(output, redactOpts);
        return {
          transformed:     true,
          transform,
          output:          redacted,
          secretsRedacted,
          exitCode:        raw.exitCode,
        };
      }
      if (transform === 'distill-output') {
        const toolNames = require('../core/tool-names');
        let handler = NATIVE_HANDLERS[event.toolName];
        if (!handler && !toolNames.isCanonical(event.toolName)) {
          const canonical = toolNames.firstCanonicalFor(event.toolName);
          if (canonical) handler = NATIVE_HANDLERS[canonical];
        }
        if (!handler) {
          return { passThrough: true, reason: `transform-no-handler:${event.toolName}` };
        }
        const raw = await handler(event.toolInput, ctx);
        if (!raw) return { passThrough: true, reason: 'transform-handler-returned-null' };
        if (raw.passThrough) return raw;

        const output = typeof raw.output === 'string' ? raw.output : String(raw.output || '');
        const cmd    = event.toolInput?.command || event.toolInput?.script || event.toolName || '';
        const dr     = distill(cmd, output);
        return {
          transformed: true,
          transform,
          output:      dr.content,
          distilled:   dr.distilled,
          savedTokens: dr.savedTokens,
          label:       dr.label,
          rawContent:  dr.rawContent,
          exitCode:    raw.exitCode,
        };
      }

      return { transformed: false, reason: `transform-not-implemented:${transform}` };
    }

    case 'LOCAL': {
      // Direct canonical-name lookup. If the event's toolName is an
      // agent-specific alias (e.g., a test passes 'Read'), reverse-resolve
      // through the registry.
      const toolNames = require('../core/tool-names');
      let handler = NATIVE_HANDLERS[event.toolName];
      if (!handler && !toolNames.isCanonical(event.toolName)) {
        const canonical = toolNames.firstCanonicalFor(event.toolName);
        if (canonical) handler = NATIVE_HANDLERS[canonical];
      }
      if (!handler) {
        return { passThrough: true, reason: `unknown-local-tool:${event.toolName}` };
      }
      const out = await handler(event.toolInput, ctx);
      return out || { passThrough: true, reason: 'handler-returned-null' };
    }

    default:
      throw new Error(`dispatcher.dispatch: unknown decision.action ${decision.action}`);
  }
}

module.exports = { dispatch, NATIVE_HANDLERS };
