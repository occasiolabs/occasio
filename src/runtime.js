'use strict';

/**
 * runtime.js — Pure deterministic local execution core.
 *
 * Owns the structured tool handlers for Read, Glob, Grep, TodoWrite, and TodoRead.
 * These are pure filesystem / in-memory functions with no dependency on the
 * interceptor pipeline, Anthropic API, or shell execution.  Safe to import in
 * any process context: proxy, MCP server, CLI tools.
 *
 * Also exports executeLocalTool() — a higher-level wrapper that adds distillation,
 * token estimation, and secret scanning to the raw handler results.  Used by
 * mcp-server.js so the MCP path has parity with the interceptor path.
 *
 * Imported by:
 *   interceptor.js — for native tool dispatch inside interceptToolUse
 *   mcp-server.js  — for executeLocalTool (hardened execution wrapper)
 */

const { distill }      = require('./distiller');
const { estimateTokens, scanSecrets } = require('./analyzer');

// ── Read tool support ──────────────────────────────────────────────────────────
// Moved to src/executor/native-handlers/read.js as Stage-2 of the executor
// migration (see docs/ADAPTER-STAGE-2-MIGRATION.md). Re-exported here so
// existing consumers (interceptor, MCP server, tests) keep working unchanged.
// MAX_OUTPUT and readFileNative are also consumed by the Grep code below.
const {
  MAX_OUTPUT,
  READ_SKIP_EXTENSIONS,
  readFileNative,
  isReadHandleable,
  handleReadTool,
} = require('./executor/native-handlers/read');

// ── Glob tool support ──────────────────────────────────────────────────────────
// Moved to src/executor/native-handlers/glob.js as Stage-2 Step 3 of the
// executor migration. GLOB_SKIP and globToRegex are also consumed by the Grep
// code below.
const {
  GLOB_INJECTION_RE,
  GLOB_SKIP,
  GLOB_MAX,
  isGlobHandleable,
  globToRegex,
  walkGlob,
  handleGlobTool,
} = require('./executor/native-handlers/glob');

// ── Grep tool support ──────────────────────────────────────────────────────────
// Moved to src/executor/native-handlers/grep.js as Stage-2 Step 4.
const {
  GREP_MAX_RESULTS,
  GREP_FILE_CAP,
  GREP_TYPE_EXTS,
  VALID_GREP_MODES,
  isGrepHandleable,
  tryReadGrep,
  walkGrepFiles,
  handleGrepTool,
} = require('./executor/native-handlers/grep');

// ── Todo tool support ──────────────────────────────────────────────────────────
// Moved to src/executor/native-handlers/todo.js as Stage-2 of the executor
// migration (see docs/ADAPTER-STAGE-2-MIGRATION.md). Re-exported here so
// existing consumers (interceptor, tests) keep working unchanged.
const {
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
} = require('./executor/native-handlers/todo');

// ── MCP execution wrapper ──────────────────────────────────────────────────────

/**
 * Execute a normalized local tool call with distillation, token estimation,
 * and secret scanning applied.  Returns a canonical result shape for MCP use.
 *
 * @param {string}   toolName        'read_file' | 'find_files' | 'grep' | 'TodoWrite' | 'TodoRead'
 * @param {object}   normalizedInput Already normalized (via mcp-normalize.js or similar)
 * @param {Array}    [todoStore=[]]  Mutable session todo list (passed through to Todo handlers)
 * @returns {{
 *   content:      string,   // final text to send to the model
 *   exitCode:     number,
 *   outputTokens: number,
 *   bytes:        number,
 *   distilled:    boolean,
 *   distillSaved: number,   // tokens saved by distillation (0 if not distilled)
 *   distillLabel: string|null,
 *   rawContent:   string|null, // original pre-distill content (null if not distilled)
 *   secrets:      Array,    // [{label, line, snippet}]
 *   matchCount?:  number,   // grep / glob only
 *   taskCount?:   number,   // todo only
 * }}
 */
function executeLocalTool(toolName, normalizedInput, todoStore = []) {
  let raw, extra = {};

  if (toolName === 'read_file') {
    raw = handleReadTool(normalizedInput);
  } else if (toolName === 'find_files') {
    raw = handleGlobTool(normalizedInput);
    extra.matchCount = raw.matchCount;
  } else if (toolName === 'grep') {
    raw = handleGrepTool(normalizedInput);
    extra.matchCount = raw.matchCount;
  } else if (toolName === 'TodoWrite') {
    raw = handleTodoWriteTool(normalizedInput, todoStore);
    extra.taskCount = raw.taskCount;
  } else if (toolName === 'TodoRead') {
    raw = handleTodoReadTool(todoStore);
    extra.taskCount = raw.taskCount;
  } else {
    return {
      content: `Unknown tool: ${toolName}`, exitCode: 1,
      outputTokens: 0, bytes: 0,
      distilled: false, distillSaved: 0, distillLabel: null, rawContent: null,
      secrets: [],
    };
  }

  const rawOutput = raw.output;
  const bytes     = Buffer.byteLength(rawOutput, 'utf8');

  // Choose synthetic cmd string so classifyCmd fires correctly.
  let distillCmd;
  if (toolName === 'grep') {
    distillCmd = 'grep ' + (normalizedInput.pattern || '');
  } else if (toolName === 'find_files') {
    distillCmd = 'find . -name ' + (normalizedInput.pattern || '');
  } else {
    // read_file and todo tools: no distillation category — pass file path so
    // classifyCmd returns null and the output passes through unchanged.
    distillCmd = normalizedInput.file_path || toolName;
  }

  const dr = distill(distillCmd, rawOutput);
  const content      = dr.content;
  const distilled    = dr.distilled || false;
  const rawContent   = distilled ? dr.rawContent : null;
  const distillSaved = distilled ? estimateTokens(rawOutput) - estimateTokens(content) : 0;
  const distillLabel = dr.label || null;
  const outputTokens = estimateTokens(content);
  const secrets      = scanSecrets(content);

  return {
    content,
    exitCode:     raw.exitCode,
    outputTokens,
    bytes,
    distilled,
    distillSaved,
    distillLabel,
    rawContent,
    secrets,
    ...extra,
  };
}

// ── Exports ────────────────────────────────────────────────────────────────────

module.exports = {
  // Shared
  MAX_OUTPUT,
  readFileNative,
  // Read
  READ_SKIP_EXTENSIONS,
  isReadHandleable,
  handleReadTool,
  // Glob
  GLOB_INJECTION_RE,
  GLOB_SKIP,
  GLOB_MAX,
  isGlobHandleable,
  globToRegex,
  walkGlob,
  handleGlobTool,
  // Grep
  GREP_MAX_RESULTS,
  GREP_FILE_CAP,
  GREP_TYPE_EXTS,
  VALID_GREP_MODES,
  isGrepHandleable,
  tryReadGrep,
  walkGrepFiles,
  handleGrepTool,
  // Todo
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
  // MCP execution wrapper
  executeLocalTool,
};
