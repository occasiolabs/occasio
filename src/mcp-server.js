'use strict';

/**
 * mcp-server.js — LocalFirst MCP server (registered as "lf").
 *
 * Exposes three tools under the mcp__lf__* namespace:
 *   read_file   — reads a local file, returns cat-n formatted content
 *   find_files  — finds files matching a glob pattern or name fragment
 *   grep        — searches file content with a regex
 *
 * Input schemas match the shapes Claude actually sends (lao server convention).
 * Normalization from wire shapes to internal handleR* shapes is done in
 * mcp-normalize.js before execution.
 *
 * Every call is logged to ~/.localfirst/mcp-experiment.jsonl for adoption
 * measurement via `localfirst mcp-experiment`.
 *
 * Runs on stdio (JSON-RPC 2.0). Registered in .claude/settings.json as "lf".
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { normalizeReadInput, normalizeFindInput, normalizeGrepInput } = require('./mcp-normalize');
const { incrementSessionMcpCount } = require('./session');
const pipeline       = require('./core/pipeline');
const { makeBoundaryEvent } = require('./core/boundary-event');
const { createAuditor }     = require('./audit/jsonl-auditor');

const LOG_FILE = path.join(os.homedir(), '.localfirst', 'mcp-experiment.jsonl');

// v0.6.5 (Step 2): MCP traffic is now governed by the same canonical pipeline
// as the Claude Code adapter. Tool calls are evaluated by policy.engine,
// dispatched by executor.dispatcher, and recorded by audit.jsonl-auditor —
// the same components, the same policy.yml, the same hash-chained log.
//
// Concurrency note: mcp-server.js runs as a child process of the agent (e.g.
// Claude Desktop) and writes to the same ~/.localfirst/pipeline-events.jsonl
// as the Claude Code proxy. v0.6.5 ASSUMES single-writer discipline — only
// one of (Claude Code proxy, MCP server) appends to the file at a time. If
// both are running concurrently with audit traffic, an interleaved append on
// Windows can corrupt the chain. A dedicated slice (deferred) will harden
// concurrent audit writing; until then, run one or the other.
// Audit-file override via env var (symmetric with the Claude Code proxy
// in src/index.js). Used by `localfirst harness --scenario mcp-*` to
// keep MCP test traffic out of the user's real ~/.localfirst chain.
let mcpAuditor = createAuditor(process.env.LOCALFIRST_AUDIT_FILE || undefined);

// v0.6.6: emit a policy_loaded row on first policy load and on every
// hot-reload that changes the policy file's bytes. The MCP server is a
// separate process from the Claude Code proxy; each process emits its
// own policy_loaded row when it observes the change. Both rows are
// correct and attributed by their own session_id (absent on these rows;
// the policy-loaded event is process-scoped, not session-scoped).
{
  const policyLoaderM = require('./policy/loader');
  policyLoaderM.onPolicyChange((change) => {
    const status = mcpAuditor.recordPolicyLoaded(change);
    if (status && status.ok === false) {
      const dropped = status.droppedRow ? JSON.stringify(status.droppedRow) : '(no row attached)';
      process.stderr.write(`\n[localfirst-mcp][audit-fatal] policy_loaded write failed: ${status.error?.message}\n`);
      process.stderr.write(`[localfirst-mcp][audit-fatal] dropped row: ${dropped}\n`);
      process.stderr.write(`[localfirst-mcp][audit-fatal] aborting MCP server.\n`);
      setTimeout(() => process.exit(1), 250);
    }
  });
  // Cold-start trigger so the row lands before the first tool call.
  try { policyLoaderM.load(); } catch (e) {
    process.stderr.write(`[localfirst-mcp] policy load failed at startup: ${e.message}\n`);
  }
}

// Captured from the MCP `initialize` request's clientInfo.name. Falls back to
// the literal 'mcp-client' if the client did not provide one. Used as the
// `agent` field on every BoundaryEvent / audit row from this server.
let mcpClientName = 'mcp-client';

// Test hook: respond() writes JSON-RPC frames to stdout in production, but
// tests need to capture them without interleaving with the test runner's
// output. Default is process.stdout.write; tests override via the exported
// __setRespondHookForTests.
let respondHook = (frame) => process.stdout.write(frame + '\n');

function logCall(entry) {
  try {
    const dir = path.dirname(LOG_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
  } catch {}
}

// ── Tool definitions (lao-compatible schemas) ──────────────────────────────────

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a file from the local filesystem. Returns contents with line numbers.',
    inputSchema: {
      type: 'object',
      properties: {
        path:       { type: 'string',  description: 'Path to the file to read' },
        start_line: { anyOf: [{ type: 'integer' }, { type: 'null' }], default: null,
                      description: 'First line to read (1-based, inclusive)' },
        end_line:   { anyOf: [{ type: 'integer' }, { type: 'null' }], default: null,
                      description: 'Last line to read (1-based, inclusive)' },
      },
      required: ['path'],
    },
  },
  {
    name: 'find_files',
    description: 'Find files by glob pattern, name fragment, or extension.',
    inputSchema: {
      type: 'object',
      properties: {
        pattern:     { type: 'string',  description: 'Glob pattern (e.g. "**/*.js") or name fragment (e.g. "interceptor")' },
        path:        { type: 'string',  default: '.', description: 'Directory to search in' },
        extension:   { anyOf: [{ type: 'string' }, { type: 'null' }], default: null,
                       description: 'File extension filter, e.g. ".js" or "ts"' },
        max_results: { type: 'integer', default: 50, description: 'Maximum results (capped at 500)' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'grep',
    description: 'Search file contents with a regular expression. Case-insensitive by default.',
    inputSchema: {
      type: 'object',
      properties: {
        pattern:        { type: 'string',  description: 'Regular expression to search for' },
        path:           { type: 'string',  default: '.', description: 'File or directory to search in' },
        case_sensitive: { type: 'boolean', default: false, description: 'Use case-sensitive matching (default: false)' },
        file_glob:      { anyOf: [{ type: 'string' }, { type: 'null' }], default: null,
                          description: 'Glob to filter files, e.g. "*.ts"' },
        max_results:    { type: 'integer', default: 50, description: 'Maximum results' },
        output_mode:    { type: 'string',  enum: ['content', 'files_with_matches', 'count'],
                          description: 'Output format (default: content)' },
      },
      required: ['pattern'],
    },
  },
];

// ── JSON-RPC dispatch ──────────────────────────────────────────────────────────

function respond(id, result) {
  respondHook(JSON.stringify({ jsonrpc: '2.0', id, result }));
}

function respondError(id, code, message) {
  respondHook(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }));
}

async function handleRequest(req) {
  const { id, method, params } = req;

  if (method === 'initialize') {
    // v0.6.5: capture clientInfo.name so audit rows are attributed to the
    // calling agent (e.g. 'claude-ai', 'cursor', 'continue'). Falls back to
    // 'mcp-client' if the client omitted clientInfo or its name field.
    const ci = params && params.clientInfo;
    if (ci && typeof ci.name === 'string' && ci.name.trim()) {
      mcpClientName = ci.name.trim();
    }
    respond(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'lf', version: '0.6.5' },
    });
    return;
  }

  if (method === 'notifications/initialized') return;

  if (method === 'tools/list') {
    respond(id, { tools: TOOLS });
    return;
  }

  if (method === 'tools/call') {
    const toolName  = params?.name;
    const rawInput  = params?.arguments || {};
    const ts        = new Date().toISOString();

    try {
      let normalizedInput, logExtra = {};

      if (toolName === 'read_file') {
        normalizedInput = normalizeReadInput(rawInput);
        logExtra = { file: normalizedInput.file_path };
      } else if (toolName === 'find_files') {
        normalizedInput = normalizeFindInput(rawInput);
        logExtra = { pattern: normalizedInput.pattern };
      } else if (toolName === 'grep') {
        normalizedInput = normalizeGrepInput(rawInput);
        logExtra = { pattern: rawInput.pattern };
      } else {
        respondError(id, -32601, `Unknown tool: ${toolName}`);
        logCall({ ts, tool: toolName, error: 'unknown tool', source: 'mcp_lf' });
        return;
      }

      // v0.6.5: route through the canonical governance pipeline.
      // Tool names are already canonical (read_file, find_files, grep) by
      // construction in this MCP server's TOOLS list, so no name translation
      // is needed. The same policy.yml that governs Claude Code's Read also
      // governs this read_file call.
      const event = makeBoundaryEvent({
        direction: 'inbound',
        kind:      'tool_call',
        agent:     mcpClientName,
        protocol:  'mcp',
        toolName:  toolName,
        toolInput: normalizedInput,
      });

      const out = await pipeline.processToolEvent(event, { auditor: mcpAuditor });
      const r   = out.result || {};

      // BLOCK: policy denied this call (deny_paths, deny_patterns, etc.).
      // Return an isError MCP response with the synthetic refusal text and
      // do NOT increment the adoption counter — the call did not run locally.
      if (r.blocked) {
        logCall({ ts, tool: toolName, blocked: true, reason: r.reason, source: 'mcp_lf', ...logExtra });
        respond(id, {
          content: [{ type: 'text', text: '(blocked by policy)' }],
          isError: true,
        });
        return;
      }

      // PASS: defensive — the three default-LOCAL tools should never PASS,
      // but if a user policy reroutes them we surface a clear error rather
      // than silently returning empty content.
      if (r.passThrough) {
        logCall({ ts, tool: toolName, passthrough: true, reason: r.reason, source: 'mcp_lf', ...logExtra });
        respond(id, {
          content: [{ type: 'text', text: `(not configured: ${r.reason || 'unknown'})` }],
          isError: true,
        });
        return;
      }

      // LOCAL or TRANSFORM success. The dispatcher's handler returns
      // { output, exitCode, ... }; TRANSFORM may add secretsRedacted or
      // savedTokens, which we surface in the adoption log only.
      const content = (typeof r.output === 'string') ? r.output : String(r.output || '');

      if (r.matchCount !== undefined)    logExtra.matchCount    = r.matchCount;
      if (r.distilled)                    logExtra.distillSaved = r.savedTokens || 0;
      if (r.secretsRedacted?.length)      logExtra.secretsFound = r.secretsRedacted.length;

      incrementSessionMcpCount();
      logCall({ ts, tool: toolName, exitCode: r.exitCode, source: 'mcp_lf', ...logExtra });
      respond(id, {
        content: [{ type: 'text', text: content }],
        isError: false,
      });

    } catch (e) {
      // v0.6.5: AuditWriteError from the pipeline must abort the MCP server
      // for the same reason the Claude Code proxy aborts on it — a
      // successful tool call cannot coexist with a missing audit row. The
      // supervisor (or Claude Desktop's MCP-server restart logic) brings us
      // back up.
      if (e && e.name === 'AuditWriteError') {
        const dropped = e.droppedRow ? JSON.stringify(e.droppedRow) : '(no row attached)';
        process.stderr.write(`\n[localfirst-mcp][audit-fatal] ${e.message}\n`);
        process.stderr.write(`[localfirst-mcp][audit-fatal] dropped row: ${dropped}\n`);
        process.stderr.write(`[localfirst-mcp][audit-fatal] aborting MCP server.\n`);
        try {
          respond(id, {
            content: [{ type: 'text', text: 'audit-fatal: MCP server aborting' }],
            isError: true,
          });
        } catch {}
        setTimeout(() => process.exit(1), 250);
        return;
      }
      logCall({ ts, tool: toolName, rawInput, error: e.message, source: 'mcp_lf' });
      respond(id, {
        content: [{ type: 'text', text: `Error: ${e.message}` }],
        isError: true,
      });
    }
    return;
  }

  if (id !== undefined) respondError(id, -32601, `Method not found: ${method}`);
}

// ── Stdio framing ──────────────────────────────────────────────────────────────

let _buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  _buf += chunk;
  const lines = _buf.split('\n');
  _buf = lines.pop();
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { handleRequest(JSON.parse(trimmed)); } catch (e) { /* malformed JSON-RPC frame */ }
  }
});
process.stdin.on('end', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));

// Test hooks. Exposed so test-interceptor.js can drive handleRequest
// directly with a temp auditor and a captured stdout, without spawning a
// child process. Production callers (bin/localfirst-mcp.js) ignore these.
module.exports = {
  handleRequest,
  TOOLS,
  __setAuditorForTests(a)        { mcpAuditor = a || createAuditor(); },
  __getClientName()              { return mcpClientName; },
  __setClientNameForTests(name)  { mcpClientName = name || 'mcp-client'; },
  __setRespondHookForTests(fn)   { respondHook = fn || ((s) => process.stdout.write(s + '\n')); },
};
