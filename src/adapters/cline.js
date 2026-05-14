'use strict';

/**
 * Cline adapter — second AI agent supported by Occasio.
 *
 * Cline (https://github.com/cline/cline) is a VS Code extension that uses
 * the Anthropic Messages API for tool calls. Because both Cline and Claude
 * Code speak Anthropic SSE, this adapter shares the multi-round protocol
 * loop with `claude-code` and only contributes:
 *   1. its tool name → canonical name mapping (registered with tool-names)
 *   2. per-tool input shape translation (Cline's `path` → canonical `file_path`)
 *   3. a thin runToolLoop wrapper that calls the Anthropic loop with its
 *      own parser and agent identity
 *
 * ### LIVE_VALIDATION_PENDING
 *
 * The mappings below are based on Cline's published source (2025/2026
 * cline/cline repository). Live validation against a real Cline session
 * routed through the proxy is required before this adapter is considered
 * production-ready. Specific items to verify:
 *
 *  - tool name strings (currently best-effort; Cline tool names occasionally
 *    change between releases)
 *  - input field names per tool (currently translated from public docs)
 *  - whether Cline routes through the Anthropic /v1/messages endpoint or
 *    a different path when a custom base URL is configured
 *
 * Until live-validated, do not document Cline support as a launched feature.
 */

const claudeCode = require('./claude-code');
const toolNames  = require('../core/tool-names');
const { makeBoundaryEvent } = require('../core/boundary-event');
const { parseSSE } = require('../interceptor');

const AGENT    = 'cline';
const PROTOCOL = 'anthropic-http';

// Cline → canonical tool-name map. Only the tools whose semantics map
// cleanly onto canonical handlers are registered here. Tools without a
// Occasio-native equivalent (write_to_file, browser_action, etc.) are
// left unmapped — they fall through to PASS via the policy engine.
toolNames.register(AGENT, {
  read_file:        toolNames.CANONICAL.READ_FILE,        // identity name; input differs
  search_files:     toolNames.CANONICAL.GREP,
  list_files:       toolNames.CANONICAL.FIND_FILES,
  execute_command:  toolNames.CANONICAL.SHELL_BASH,
});

/**
 * Per-tool input transformers: agent shape → canonical shape.
 * The canonical shape is currently equivalent to Claude Code's input shape
 * (since the dispatcher's NATIVE_HANDLERS expect that). When a richer
 * canonical shape is introduced (Stage 4+), update accordingly.
 *
 * Mappings, all subject to LIVE_VALIDATION_PENDING:
 *
 *   read_file       :  { path }                  → { file_path }
 *   search_files    :  { regex, path?, file_pattern? }
 *                                                → { pattern, path?, glob? }
 *   list_files      :  { path, recursive? }     → { pattern: `${path}/${recursive?'**\/*':'*'}` }
 *   execute_command :  { command, requires_approval? }
 *                                                → { command }
 */
const INPUT_TRANSFORMERS = {
  read_file: (input) => ({
    file_path: input?.path || input?.file_path,
    ...(input && typeof input.offset === 'number' ? { offset: input.offset } : {}),
    ...(input && typeof input.limit  === 'number' ? { limit:  input.limit  } : {}),
  }),

  search_files: (input) => ({
    pattern: input?.regex || input?.pattern,
    ...(input?.path           ? { path: input.path } : {}),
    ...(input?.file_pattern   ? { glob: input.file_pattern } : {}),
  }),

  list_files: (input) => {
    const base = (input?.path || '.').replace(/\\$/, '');
    const recurse = input?.recursive === true || input?.recursive === 'true';
    return { pattern: recurse ? `${base}/**/*` : `${base}/*` };
  },

  execute_command: (input) => ({
    command: (input?.command || '').toString().trim(),
  }),
};

function translateInput(clineToolName, input) {
  const t = INPUT_TRANSFORMERS[clineToolName];
  return t ? t(input || {}) : input;
}

/**
 * Parse a Cline conversation turn (Anthropic SSE shape with Cline tool blocks).
 * Returns the same `{ blocks, stopReason, message, events }` shape as
 * `claudeCode.parseConversationTurn`, but:
 *  - block.input is rewritten in place to canonical shape (so downstream
 *    `runOneRound` / dispatcher / handlers see a uniform input)
 *  - events carry canonical toolNames AND canonical inputs
 *  - agent is 'cline'
 */
function parseConversationTurn(sseBuffer, ctx = {}) {
  // Cline speaks Anthropic SSE, so the structural parse is identical to
  // Claude Code's. Use parseSSE directly (no need to round-trip through
  // claudeCode.parseConversationTurn just to build events we'd discard).
  const parsed = parseSSE(sseBuffer);

  // Rewrite each tool_use block's input from Cline's shape to canonical,
  // and emit BoundaryEvents with canonical names + canonical inputs.
  const events = [];
  for (const idx of Object.keys(parsed.blocks || {})) {
    const block = parsed.blocks[idx];
    if (!block || block.type !== 'tool_use') continue;
    // Preserve the original Cline-shape input on raw_input for diagnostics
    // (e.g., audit / dashboard would want to surface Cline's actual fields).
    block.raw_input = block.input;
    block.input     = translateInput(block.name, block.input);
    const canonical = toolNames.toCanonical(AGENT, block.name);
    if (!canonical) continue;
    events.push(makeBoundaryEvent({
      direction: 'inbound',
      kind:      'tool_call',
      agent:     AGENT,
      protocol:  PROTOCOL,
      sessionId: ctx.sessionId,
      runId:     ctx.runId,
      toolName:  canonical,
      toolInput: block.input,
      raw:       block,
    }));
  }
  return {
    blocks:     parsed.blocks,
    stopReason: parsed.stopReason,
    message:    parsed.message,
    events,
  };
}

/**
 * runToolLoop — thin wrapper around claudeCode.runToolLoop that supplies
 * Cline's parser and agent identity. Both adapters speak Anthropic API,
 * so the multi-round logic is shared.
 */
async function runToolLoop(opts) {
  return claudeCode.runToolLoop({
    ...opts,
    _agent:  AGENT,
    _parser: parseConversationTurn,
  });
}

module.exports = {
  AGENT,
  PROTOCOL,
  parseConversationTurn,
  runToolLoop,
  // Exposed for tests + diagnostics; callers should not rely on the shape.
  INPUT_TRANSFORMERS,
};
