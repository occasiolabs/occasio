'use strict';

/**
 * ClaudeCodeAdapter — owns all Anthropic-HTTP and Claude-Code-tool-name
 * knowledge. Every protocol-specific concern about Claude Code's wire format
 * lives here.
 *
 * Stage 1 contract:
 *   - Wraps existing parseSSE / classifyBlock / interceptToolUse from the
 *     legacy interceptor module. Does NOT decompose them.
 *   - Translates between Claude Code's tool-block shape and the canonical
 *     BoundaryEvent shape.
 *
 * Stage 2+ will move SSE parsing, name canonicalization, and follow-up call
 * logic in here as native code (not just wrappers around interceptor).
 *
 * Leak detector: any string literal 'Read'/'Glob'/'Bash'/etc. outside this
 * module is a Stage 1 architecture leak. Tracked as a known leak; Stage 2
 * introduces a canonical name registry.
 */

const {
  parseSSE,
  classifyBlock,
  isInterceptable,
  buildFollowUpHeaders,
} = require('../interceptor');
const { makeBoundaryEvent } = require('../core/boundary-event');
const toolNames = require('../core/tool-names');

const AGENT    = 'claude-code';
const PROTOCOL = 'anthropic-http';

// Claude Code → canonical tool-name map. Registered at adapter load so that
// any pipeline / policy / dispatcher / audit code that runs afterwards sees
// canonical names regardless of the originating agent.
toolNames.register(AGENT, {
  Read:       toolNames.CANONICAL.READ_FILE,
  Glob:       toolNames.CANONICAL.FIND_FILES,
  Grep:       toolNames.CANONICAL.GREP,
  TodoWrite:  toolNames.CANONICAL.TODO_WRITE,
  TodoRead:   toolNames.CANONICAL.TODO_READ,
  Bash:       toolNames.CANONICAL.SHELL_BASH,
  PowerShell: toolNames.CANONICAL.SHELL_POWERSHELL,
});

/**
 * Translate a Claude tool block name to its canonical name.
 * Falls back to the original name if unmapped (lets unknown tools flow
 * through to the policy engine, which will PASS them).
 */
function canonicalNameOf(claudeBlockName) {
  return toolNames.toCanonical(AGENT, claudeBlockName) || claudeBlockName;
}

// Anthropic-specific outbound HTTP. Owned by the adapter because it is the
// only place the cloud-side wire format lives. Stage 1 keeps the underlying
// HTTPS call inside legacy `anthropicRequest`; the adapter wraps it so that
// `interceptToolUse` no longer reaches into Anthropic-specific HTTP directly.
const https = require('https');

/**
 * Forward an assembled follow-up body to Anthropic. Returns
 * { status, body } where body is the parsed JSON response.
 *
 * @param {object} reqBody     Anthropic /v1/messages body (with messages array)
 * @param {object} authHeaders Caller's request headers (for auth + anthropic-version)
 */
function forwardToCloud(reqBody, authHeaders) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ ...reqBody, stream: false });
    const headers = buildFollowUpHeaders(authHeaders, Buffer.byteLength(payload));
    const req = https.request(
      { hostname: 'api.anthropic.com', port: 443, path: '/v1/messages', method: 'POST', headers },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try   { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }); }
          catch (e) { reject(e); }
        });
      }
    );
    req.on('error', reject);
    req.end(payload);
  });
}

/**
 * Parse an SSE response buffer and emit one BoundaryEvent per tool_use block.
 * Wraps interceptor.parseSSE — does not reimplement.
 *
 * @param {Buffer} sseBuffer
 * @param {object} [ctx] { sessionId, runId }
 * @returns {object[]} BoundaryEvents (kind: 'tool_call', direction: 'inbound')
 */
function parseResponse(sseBuffer, ctx = {}) {
  const parsed = parseSSE(sseBuffer);
  const events = [];
  const blocks = parsed.blocks || {};
  for (const idx of Object.keys(blocks)) {
    const block = blocks[idx];
    if (!block || block.type !== 'tool_use') continue;
    events.push(makeBoundaryEvent({
      direction: 'inbound',
      kind:      'tool_call',
      agent:     AGENT,
      protocol:  PROTOCOL,
      sessionId: ctx.sessionId,
      runId:     ctx.runId,
      // Stage 3: emit canonical names. The original Claude name is preserved
      // in `raw` for any callers that need protocol-specific access.
      toolName:  canonicalNameOf(block.name),
      toolInput: block.input,
      raw:       block,
    }));
  }
  return events;
}

/**
 * Parse one conversation turn from an Anthropic SSE buffer.
 *
 * Returned shape exposes both the legacy structural fields (blocks, stopReason,
 * message) and a canonical events array. interceptToolUse needs all three
 * during its current state-threading; the events array is what the pipeline
 * consumes. Stage 2/D moves this into adapter-only territory.
 *
 * @param {Buffer} sseBuffer
 * @param {object} [ctx] { sessionId, runId }
 * @returns {{ blocks: object, stopReason: string|null, message: object|null, events: object[] }}
 */
function parseConversationTurn(sseBuffer, ctx = {}) {
  const parsed = parseSSE(sseBuffer);
  const events = [];
  const blocks = parsed.blocks || {};
  for (const idx of Object.keys(blocks)) {
    const block = blocks[idx];
    if (!block || block.type !== 'tool_use') continue;
    events.push(makeBoundaryEvent({
      direction: 'inbound',
      kind:      'tool_call',
      agent:     AGENT,
      protocol:  PROTOCOL,
      sessionId: ctx.sessionId,
      runId:     ctx.runId,
      toolName:  block.name,
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
 * Build a Claude-protocol tool_use block from a BoundaryEvent.
 * Used by adapter.classify (and other code that needs to consult
 * `interceptor.classifyBlock`, which still uses Claude protocol names).
 *
 * Translates canonical → Claude name via the registry.
 */
function eventToToolBlock(event) {
  const claudeName = toolNames.toAgentName(AGENT, event.toolName) || event.toolName;
  return {
    type:  'tool_use',
    id:    event.id,
    name:  claudeName,
    input: event.toolInput,
  };
}

/**
 * Adapter-level classification helper. Delegates to existing classifyBlock.
 * The policy engine consumes this, not BoundaryEvent internals directly.
 */
function classify(event) {
  return classifyBlock(eventToToolBlock(event));
}

/**
 * Adapter-level interceptability check. Delegates to existing isInterceptable.
 */
function adapterIsInterceptable(event) {
  return isInterceptable(eventToToolBlock(event));
}

/**
 * runToolLoop — the canonical multi-round orchestration for an Anthropic
 * conversation that contains tool_use turns.
 *
 * Owns:
 *   - parsing the initial SSE                       (parseConversationTurn)
 *   - per-round dispatch through the pipeline       (runOneRound)
 *   - cross-round secret accumulation                (scanToolResults)
 *   - follow-up calls to Anthropic                   (forwardToCloud)
 *   - token-usage threading (toolCallUsage / middleRoundsUsage)
 *   - partial-batch round-0 short-circuit
 *   - max-rounds guard
 *
 * Returns the same shape `interceptToolUse` returned previously — the contract
 * is preserved exactly so that `interceptToolUse` is now a 4-line shim and
 * `index.js` is unaffected.
 *
 * Stage 2 will collapse the inline secret-scan + verbose-pre-send-manifest
 * code into pipeline TRANSFORM Decisions and observability sinks.
 */
async function runToolLoop({
  initialSse, reqBody, reqHeaders,
  maxRounds = 5, verbose = false, mode = 'intercept', todoStore = [],
  auditor = null, sessionId, runId,
  // Stage 3 multi-agent plumbing. Defaults preserve Claude Code behavior;
  // a second adapter (e.g., cline) supplies its own _agent + _parser to
  // route the same loop body through its own protocol-specific parsing.
  _agent  = AGENT,
  _parser = parseConversationTurn,
}) {
  // Lazy-require interceptor helpers (cyclic-require — interceptor depends on
  // this adapter, so we resolve at call time, not module-load time).
  const fs   = require('fs');
  const path = require('path');
  const {
    blocksToContent, runOneRound,
    FALLBACK_REASONS,
  } = require('../interceptor');

  const { blocks: initialBlocks, stopReason: initialStop, message: initialMessage } =
    _parser(initialSse, { sessionId, runId });

  if (verbose) {
    const os = require('os');
    const dbg = {
      ts: new Date().toTimeString().slice(0, 8),
      stopReason: initialStop,
      blocks: Object.keys(initialBlocks).length,
      bodyLen: initialSse.length,
      preview: initialSse.toString('utf8').slice(0, 200),
    };
    fs.appendFileSync(path.join(os.homedir(), '.occasio', 'interceptor-debug.log'), JSON.stringify(dbg) + '\n');
  }

  if (initialStop !== 'tool_use') return { intercepted: false, toolsAttempted: 0, fallbackReasons: [] };

  const toolCallUsage = {
    input_tokens:  initialMessage?.usage?.input_tokens  ?? 0,
    output_tokens: initialMessage?.usage?.output_tokens ?? 0,
  };
  const savedInputTokens = toolCallUsage.input_tokens;

  const initialToolBlocks = Object.values(initialBlocks).filter(b => b.type === 'tool_use');
  if (!initialToolBlocks.length) return { intercepted: false, toolsAttempted: 0, fallbackReasons: [] };

  // Stage 3: classify via the policy engine + canonical-name registry rather
  // than the Claude-specific classifyBlock. For Claude Code, this produces
  // identical results (the default policy reproduces classifyBlock's output);
  // for Cline / future agents, it correctly recognizes their tool calls.
  //
  // Slice E (BLOCK enforcement): "handled by the pipeline" means LOCAL, BLOCK,
  // or TRANSFORM — every action the dispatcher knows how to terminate locally.
  // Only PASS (and unregistered tool names) fall through to the cloud. Without
  // this distinction a BLOCK Decision silently degraded to a cloud passthrough,
  // so deny_paths / deny_patterns / secret-block events never produced an
  // audit-log BLOCK row or a synthetic refusal to the agent.
  const policyEng = require('../policy/engine');
  const classifyForAgent = (b) => {
    const canonical = toolNames.toCanonical(_agent, b.name);
    if (!canonical) return { handled: false, reason: 'tool_not_handled', action: 'PASS' };
    const ev = makeBoundaryEvent({
      direction: 'inbound', kind: 'tool_call',
      agent: _agent, protocol: PROTOCOL,
      toolName: canonical, toolInput: b.input,
    });
    const dec = policyEng.evaluate(ev);
    return { handled: dec.action !== 'PASS', reason: dec.reason, action: dec.action };
  };
  const initialClassified = initialToolBlocks.map(b => classifyForAgent(b));
  const allHandled         = initialClassified.every(c => c.handled);
  const someHandled        = !allHandled && initialClassified.some(c => c.handled);
  const partialBatch    = someHandled;
  // BLOCK is "handled" but is *not* a fallback — exclude it from unhandled
  // bookkeeping so debug logs and fallback_reason strings don't misattribute
  // an enforced refusal as "tool not handled, passing through to cloud."
  const unhandledNames  = initialToolBlocks.filter((_, i) => !initialClassified[i].handled).map(b => b.name);
  const uniqueReasons   = [...new Set(initialClassified.filter(c => !c.handled).map(c => c.reason))];

  if (!allHandled) {
    if (verbose) {
      const os = require('os');
      const allNames    = initialToolBlocks.map(b => b.name);
      const handledNames = initialToolBlocks.filter((_, i) => initialClassified[i].handled).map(b => b.name);
      const unhandledCmds = initialToolBlocks
        .filter((_, i) => !initialClassified[i].handled)
        .filter(b => b.name === 'Bash' || b.name === 'PowerShell')
        .map(b => (b.input?.command || '').trim())
        .filter(Boolean);
      fs.appendFileSync(
        path.join(os.homedir(), '.occasio', 'interceptor-debug.log'),
        JSON.stringify({
          ts: new Date().toTimeString().slice(0, 8),
          fallback: partialBatch ? 'partial batch' : 'tool not handled',
          allNames, unhandled: unhandledNames,
          ...(partialBatch ? { handled: handledNames } : {}),
          reasons: uniqueReasons,
          ...(unhandledCmds.length ? { cmds: unhandledCmds } : {}),
        }) + '\n',
      );
    }
    if (!partialBatch) {
      return {
        intercepted: false,
        toolsAttempted:  initialToolBlocks.length,
        fallbackReasons: uniqueReasons,
        fallbackReason:  `tool not handled: ${[...new Set(unhandledNames)].join(', ')}`,
      };
    }
  }

  // toolsAttempted accumulates across rounds so the "Ran locally: X of Y"
  // invariant (numerator ≤ denominator) holds for multi-round sessions.
  // Round 0 = initialToolBlocks.length (includes any unhandled in mixed batches).
  // Round 1+ = each round's toolBlocks.length (all interceptable since
  // mid-loop unhandled bails out before reaching dispatch).
  let toolsAttempted = initialToolBlocks.length;
  const round0Blocks   = partialBatch
    ? initialToolBlocks.filter((_, i) => initialClassified[i].handled)
    : null;

  const toolsRun          = [];
  const allSecretsInResults = [];
  let messages   = reqBody.messages.slice();
  let curBlocks  = initialBlocks;
  const middleRoundsUsage = { input_tokens: 0, output_tokens: 0 };

  for (let round = 0; round < maxRounds; round++) {
    let toolBlocks;
    if (round === 0 && round0Blocks) {
      toolBlocks = round0Blocks;
    } else {
      toolBlocks = Object.values(curBlocks).filter(b => b.type === 'tool_use');
      // Stage 3: mid-loop interceptability check is also registry+policy-driven.
      const midClassified = toolBlocks.map(b => classifyForAgent(b));
      if (!midClassified.every(c => c.handled)) {
        const midReasons = [...new Set(midClassified.filter(c => !c.handled).map(c => c.reason))];
        return {
          intercepted: false,
          toolsAttempted,
          fallbackReasons: midReasons,
          fallbackReason: `mid-loop tool not handled: ${midReasons.join(', ')}`,
          // Counter-bug fix: surface tools that ran in earlier rounds so the
          // proxy's per-request log credits them. Without this, a fallback
          // hit on round N silently discards the toolsRun from rounds 0..N-1.
          toolsRun,
          secretsInResults: allSecretsInResults,
        };
      }
      // Round > 0: every block here is interceptable and will be dispatched.
      // Add its count so toolsAttempted spans all rounds, matching toolsRun.
      toolsAttempted += toolBlocks.length;
    }

    if (!partialBatch) {
      const assistantContent = blocksToContent(curBlocks);
      messages = [...messages, { role: 'assistant', content: assistantContent }];
    }

    const _round = await runOneRound(toolBlocks, {
      mode, todoStore, sessionId, runId, auditor, verbose,
      agent: _agent,
    });
    const toolResults = _round.toolResults;
    if (_round.toolsRun.length) toolsRun.push(..._round.toolsRun);
    if (_round.secrets.length)  allSecretsInResults.push(..._round.secrets);

    if (partialBatch && round === 0) {
      if (verbose) {
        process.stderr.write(
          `  [interceptor] partial batch: ran [${round0Blocks.map(b => b.name).join(', ')}], ` +
          `passing through [${unhandledNames.join(', ')}]\n`
        );
      }
      return {
        intercepted:      false,
        partialIntercept: true,
        partialResults:   toolResults,
        toolsRun,
        toolsAttempted,
        fallbackReasons:  uniqueReasons,
        fallbackReason:   `partial: ${[...new Set(unhandledNames)].join(', ')} not handled`,
        toolCallUsage,
      };
    }

    messages = [...messages, { role: 'user', content: toolResults }];

    // Stage 2: secret-scan-on-tool-results runs through the policy engine.
    // The engine reads ~/.occasio/policy.yml and emits PASS or BLOCK.
    // Legacy `mode === 'block_secrets'` semantics are preserved by passing
    // the mode into the evaluator.
    const policy = require('../policy/engine');
    const resultsDecision = policy.evaluateToolResults(toolResults, { mode });
    if (resultsDecision.secrets?.length) {
      allSecretsInResults.push(...resultsDecision.secrets);
    }
    if (resultsDecision.action === 'BLOCK') {
      if (verbose) {
        const lbl = resultsDecision.secrets?.[0]?.label || 'unknown';
        process.stderr.write(
          `  [interceptor] secret in tool result (${lbl}) — policy BLOCK, falling back to proxy scanner\n`
        );
      }
      return {
        intercepted: false,
        toolsAttempted,
        fallbackReasons: [FALLBACK_REASONS.SECRET_IN_RESULT],
        fallbackReason: resultsDecision.reason,
      };
    }

    if (verbose) {
      const D = '\x1b[2m', C = '\x1b[36m', R = '\x1b[0m';
      const ts = new Date().toTimeString().slice(0, 8);
      let followUpChars = 0;
      for (const msg of messages) {
        const mc = msg.content;
        if (typeof mc === 'string') {
          followUpChars += mc.length;
        } else if (Array.isArray(mc)) {
          for (const b of mc) {
            if (typeof b === 'string')              followUpChars += b.length;
            else if (typeof b.text === 'string')    followUpChars += b.text.length;
            else if (typeof b.content === 'string') followUpChars += b.content.length;
            else if (Array.isArray(b.content)) {
              for (const cb of b.content) followUpChars += (typeof cb === 'string' ? cb : cb.text || '').length;
            }
          }
        }
      }
      const fEst  = Math.ceil(followUpChars / 4);
      const fStr  = fEst > 0
        ? `~${fEst >= 1000 ? (fEst / 1000).toFixed(1) + 'kt' : fEst + 't'}  ·  `
        : '';
      const roundTools = toolsRun.slice(toolsRun.length - toolBlocks.length);
      const toolSummary = roundTools.map(t => {
        const c = t.cmd.length > 32 ? t.cmd.slice(0, 32) + '…' : t.cmd;
        let extra = '';
        if (t.matchCount != null)        extra = ` →${t.matchCount}`;
        else if (t.outputTokens >= 1000) extra = ` ~${(t.outputTokens / 1000).toFixed(1)}kt`;
        else if (t.outputTokens > 0)     extra = ` ~${t.outputTokens}t`;
        return `${t.tool}(${c})${extra}`;
      }).join('  ');
      const body = `${fStr}${messages.length} msgs${toolSummary ? '  ·  ' + toolSummary : ''}`;
      process.stderr.write(`${D}${ts}${R}  ${C}↑${R}  ${D}${body}${R}\n`);
    }

    const { status, body: nextBody } = await forwardToCloud(
      { ...reqBody, messages },
      reqHeaders
    );

    if (status !== 200) {
      if (verbose) process.stderr.write(`  [interceptor] Anthropic ${status}, bailing\n`);
      return {
        intercepted: false,
        toolsAttempted,
        fallbackReasons: [FALLBACK_REASONS.API_ERROR],
        fallbackReason: `Anthropic ${status} on follow-up`,
      };
    }

    if (nextBody.stop_reason !== 'tool_use') {
      return {
        intercepted: true, response: nextBody, toolsRun,
        toolsAttempted,
        fallbackReasons: [],
        savedInputTokens, toolCallUsage, middleRoundsUsage,
        secretsInResults: allSecretsInResults,
      };
    }

    middleRoundsUsage.input_tokens  += nextBody.usage?.input_tokens  || 0;
    middleRoundsUsage.output_tokens += nextBody.usage?.output_tokens || 0;

    curBlocks = {};
    (nextBody.content || []).forEach((blk, i) => {
      curBlocks[i] = {
        type:  blk.type,
        id:    blk.id   || null,
        name:  blk.name || null,
        text:  blk.type === 'text'     ? blk.text  : '',
        input: blk.type === 'tool_use' ? blk.input : null,
      };
    });
  }

  return {
    intercepted: false,
    toolsAttempted,
    fallbackReasons: [FALLBACK_REASONS.MAX_ROUNDS],
    fallbackReason: 'max rounds exceeded',
  };
}

module.exports = {
  AGENT,
  PROTOCOL,
  parseResponse,
  parseConversationTurn,
  eventToToolBlock,
  classify,
  isInterceptable: adapterIsInterceptable,
  forwardToCloud,
  runToolLoop,
};
