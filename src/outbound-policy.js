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

module.exports = {
  enforceOutboundDenyPaths,
  buildToolUsePathMap,
  pathIsDenied,
  resolveInputPath,
  STRIP_MARKER,
};
