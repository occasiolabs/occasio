'use strict';

/**
 * outbound-policy.js — Path-2 defense for deny_paths.
 *
 * The tool-call gate in src/policy/engine.js intercepts BoundaryEvents
 * derived from `tool_use` blocks the cloud model emits in its response.
 * That gate fires correctly. But Claude Code (and other agent runtimes)
 * also INJECT synthetic tool_use + tool_result pairs into the OUTBOUND
 * request body — file contents that have been read by the host process
 * as agentic context BEFORE the model has had a chance to call any tool.
 *
 * Those pre-baked tool_results never trigger the engine because no
 * agent-initiated tool call happened. The file content reaches the
 * model anyway through the request body.
 *
 * This module walks the outbound body, finds Read-style tool_use blocks
 * paired by tool_use_id with their tool_result content, and STRIPS the
 * content of any tool_result whose source file path falls under
 * deny_paths / outside allow_paths. The strip mirrors the redact-secrets
 * TRANSFORM convention: the tool_result is preserved (so the model sees
 * structural continuity), but its content is replaced with a one-line
 * synthetic refusal marker.
 *
 * One audit row is written per stripped tool_result, with the same shape
 * the engine writes for tool-call-time BLOCKs, so `localfirst report` and
 * `audit verify` see them uniformly. The audit reason is
 * `outbound-context-denied` to distinguish it from `path-denied` (which
 * is the tool-call-time path) — both are governance enforcement, but
 * which gate caught it matters for diagnosing what kind of bypass attempt
 * was made.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const STRIP_MARKER =
  '[content stripped by LocalFirst outbound deny_paths — file is under a denied path]';

// Path normalisation mirrors src/policy/engine.js so deny_paths semantics
// stay byte-identical across both gates.
const normCase = process.platform === 'win32'
  ? (p) => p.toLowerCase()
  : (p) => p;

function expandHome(p) {
  return p.startsWith('~') ? os.homedir() + p.slice(1) : p;
}

function resolveInputPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return null;
  const expanded = expandHome(rawPath);
  try { return fs.realpathSync(expanded); }
  catch { return path.resolve(expanded); }
}

function matchesPrefix(inputNorm, denyNorm) {
  return inputNorm === denyNorm || inputNorm.startsWith(denyNorm + path.sep);
}

function pathIsDenied(resolved, policy) {
  if (!resolved) return null;
  const inputNorm  = normCase(resolved);
  const denyPaths  = policy.deny_paths  || [];
  const allowPaths = policy.allow_paths || [];

  for (const d of denyPaths) {
    if (matchesPrefix(inputNorm, normCase(d))) return 'path-denied';
  }
  if (allowPaths.length > 0) {
    const ok = allowPaths.some(a => matchesPrefix(inputNorm, normCase(a)));
    if (!ok) return 'path-not-allowed';
  }
  return null;
}

/**
 * Build a Map<tool_use_id, { path, toolName }> from every `tool_use` block
 * found in the outbound body. Covers Read (file_path), find_files / grep
 * (path), and Bash/PowerShell file-read shapes via shell-path extraction.
 */
function buildToolUsePathMap(messages) {
  const { extractShellReadPaths } = require('./policy/shell-path');
  const map = new Map();
  for (const msg of messages || []) {
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (block.type !== 'tool_use' || !block.id) continue;
      const inp = block.input || {};
      const name = block.name || '';
      let filePaths = [];

      // Read tool (Claude Code / canonical read_file)
      if (/^(Read|read_file)$/i.test(name) && typeof inp.file_path === 'string') {
        filePaths.push(inp.file_path);
      } else if (/^(Read|read_file)$/i.test(name) && typeof inp.path === 'string') {
        filePaths.push(inp.path);
      }
      // Glob / find_files (the search root)
      else if (/^(Glob|find_files)$/i.test(name) && typeof inp.path === 'string') {
        filePaths.push(inp.path);
      }
      // Grep (the search root)
      else if (/^(Grep|grep)$/i.test(name) && typeof inp.path === 'string') {
        filePaths.push(inp.path);
      }
      // Shell tools: extract file operands the same way the tool-call gate does
      else if (/^(Bash|PowerShell|shell_bash|shell_powershell)$/i.test(name) &&
               typeof inp.command === 'string') {
        const ps = extractShellReadPaths(inp.command);
        for (const p of ps) filePaths.push(p);
      }

      if (filePaths.length > 0) {
        // First path is the primary; the rest are auxiliary for shell
        // chains. Store as a single record keyed by tool_use_id; if the
        // primary is denied, we strip; if any of the aux paths is denied
        // we also strip.
        map.set(block.id, { paths: filePaths, toolName: name });
      }
    }
  }
  return map;
}

/**
 * Walk the outbound body and STRIP any tool_result whose source file path
 * is denied by policy. Returns the modified messages array plus a list of
 * strips for audit. Pure function — does NOT write to disk; the caller
 * (proxy request handler) is responsible for emitting the audit rows
 * since the auditor and session context live there.
 *
 * @param {object} reqBody Parsed Anthropic request body (has .messages)
 * @param {object} policy  Loaded policy with .deny_paths / .allow_paths
 * @returns {{ messages: Array, strips: Array<{tool_use_id, path, toolName, reason}> }}
 */
function enforceOutboundDenyPaths(reqBody, policy) {
  const messages = (reqBody && reqBody.messages) || [];
  const noChange = { messages, strips: [] };
  const denyPaths  = (policy && policy.deny_paths)  || [];
  const allowPaths = (policy && policy.allow_paths) || [];
  if (denyPaths.length === 0 && allowPaths.length === 0) return noChange;

  const idToInfo = buildToolUsePathMap(messages);
  if (idToInfo.size === 0) return noChange;

  // Pre-resolve per-id deny verdicts so we strip every tool_result with
  // that id, even if the model interleaved multiple tool_results.
  const idVerdict = new Map();
  for (const [id, info] of idToInfo) {
    for (const raw of info.paths) {
      const resolved = resolveInputPath(raw);
      const reason   = pathIsDenied(resolved, policy);
      if (reason) {
        idVerdict.set(id, { resolved, reason, toolName: info.toolName });
        break;
      }
    }
  }
  if (idVerdict.size === 0) return noChange;

  const strips = [];
  const newMessages = messages.map(msg => {
    if (!Array.isArray(msg.content)) return msg;
    let changed = false;
    const newContent = msg.content.map(block => {
      if (block.type !== 'tool_result' || !block.tool_use_id) return block;
      const v = idVerdict.get(block.tool_use_id);
      if (!v) return block;
      strips.push({
        tool_use_id: block.tool_use_id,
        path:        v.resolved,
        toolName:    v.toolName,
        reason:      v.reason,
      });
      changed = true;
      return { ...block, content: STRIP_MARKER };
    });
    return changed ? { ...msg, content: newContent } : msg;
  });

  return { messages: newMessages, strips };
}

// ── Path-2 secret redaction (symmetric with path-1 redact-secrets) ──────────
//
// Path-1 (src/policy/engine.js + dispatcher TRANSFORM redact-secrets) scans
// the *result* of a tool_use the cloud model emits and replaces matching
// secret bytes before the result re-enters the model context. That path
// works correctly today.
//
// Path-2 covers the same defense gap as the deny_paths outbound fix: when
// Claude Code (or another agent runtime) injects pre-baked
// `tool_use Read` + `tool_result <content>` pairs into the OUTBOUND body
// as agentic context, those tool_results never trigger path-1 because no
// model-initiated tool call happened. Secrets in that content reach the
// model unless we scan and redact here.
//
// Design choice — REDACT, not request-BLOCK:
//   At path-1, block_secrets_in_tool_results under `--preset strict` is a
//   request-block. At path-2 the request body is already constructed by
//   the agent runtime; refusing the whole turn is destructive (the agent
//   loses its prompt round) while redaction is the smallest surgical fix
//   that preserves the workflow. We always REDACT path-2 secrets, never
//   request-block. The strict-mode tool-call-time block still fires for
//   tool_use blocks the model emits — the two gates remain complementary.
//
//   This gate fires when EITHER `redact_secrets_in_tool_results` OR
//   `block_secrets_in_tool_results` is true. The latter, on its own, does
//   not perform a request-block here (see above); it is treated as
//   permission to redact at the outbound boundary. The audit row reason
//   distinguishes the two flags so a reviewer can tell which policy was
//   the proximate cause.
//
// Implementation reuses analyzer.scanSecrets / analyzer.redactSecrets so
// the path-1 and path-2 detection sets stay identical. `deny_patterns` is
// honoured via the existing extraPatterns surface.

const SECRET_REDACT_REASONS = Object.freeze({
  redact_flag: 'outbound-secret-redacted',  // user explicitly opted into redaction
  block_flag:  'outbound-secret-redacted-strict',  // user has block_secrets on; path-2 redacts symmetrically
});

function enforceOutboundSecretRedaction(reqBody, policy) {
  const messages = (reqBody && reqBody.messages) || [];
  const noChange = { messages, redactions: [] };

  const redactOn = policy && policy.redact_secrets_in_tool_results === true;
  const blockOn  = policy && policy.block_secrets_in_tool_results  === true;
  if (!redactOn && !blockOn) return noChange;

  const { scanSecrets, redactSecrets } = require('./analyzer');
  const denyPatternsRaw = (policy && policy.deny_patterns) || [];
  // policy.deny_patterns is already normalized to [{ label, regex }] by
  // src/policy/loader.js — scanSecrets expects exactly that shape.
  const extraPatterns = denyPatternsRaw.length > 0 ? denyPatternsRaw : undefined;
  const opts = extraPatterns ? { extraPatterns } : undefined;

  // Source attribution (best-effort): if a tool_result is paired with a
  // known tool_use Read/find/grep/shell, we can record the source path in
  // the audit row. Untied tool_results still get redacted; their audit
  // row just lacks a path.
  const idToInfo = buildToolUsePathMap(messages);

  const reason = redactOn ? SECRET_REDACT_REASONS.redact_flag
                          : SECRET_REDACT_REASONS.block_flag;

  const redactions = [];
  const newMessages = messages.map(msg => {
    if (!Array.isArray(msg.content)) return msg;
    let changed = false;
    const newContent = msg.content.map(block => {
      if (block.type !== 'tool_result') return block;
      // v1 scope: scan string content. tool_results with array-of-text
      // content also occur; v2 can extend to that shape if a real bypass
      // surfaces through it.
      if (typeof block.content !== 'string' || !block.content) return block;
      const hits = scanSecrets(block.content, opts);
      if (hits.length === 0) return block;
      const redacted = redactSecrets(block.content, opts);
      if (redacted === block.content) return block;  // defensive
      const info = idToInfo.get(block.tool_use_id);
      redactions.push({
        tool_use_id:    block.tool_use_id,
        path:           (info && info.paths && info.paths[0]) || null,
        toolName:       info && info.toolName || null,
        secretsRedacted: hits.length,
        labels:         [...new Set(hits.map(h => h.label))],
        reason,
      });
      changed = true;
      return { ...block, content: redacted };
    });
    return changed ? { ...msg, content: newContent } : msg;
  });

  return { messages: newMessages, redactions };
}

module.exports = {
  enforceOutboundDenyPaths,
  enforceOutboundSecretRedaction,
  buildToolUsePathMap,
  pathIsDenied,
  resolveInputPath,
  STRIP_MARKER,
  SECRET_REDACT_REASONS,
};
