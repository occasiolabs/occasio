'use strict';

/**
 * localrouter.js — Routes simple requests to local Ollama instead of Anthropic.
 *
 * shouldRouteLocal(requestBody) → Promise<{ local, reason, model?, confidence? }>
 * handleLocally(req, res, body) → streams Anthropic-compatible SSE from Ollama
 *
 * Routing criteria (ALL must pass):
 *   1. No tool_result or tool_use blocks in conversation (not in agentic loop)
 *   2. Last user message is plain text, ≤ MAX_MSG_LEN chars
 *   3. Ollama is reachable (checked + cached every 30 s)
 *
 * Env overrides:
 *   OLLAMA_HOST          — default: localhost
 *   OLLAMA_PORT          — default: 11434
 *   LOCALFIRST_MODEL     — default: qwen2.5:7b
 *   LOCALFIRST_MAX_MSG   — default: 600
 */

const http = require('http');

const OLLAMA_HOST = process.env.OLLAMA_HOST        || 'localhost';
const OLLAMA_PORT = parseInt(process.env.OLLAMA_PORT || '11434', 10);
const LOCAL_MODEL = process.env.LOCALFIRST_MODEL   || 'qwen2.5:7b';
const MAX_MSG_LEN = parseInt(process.env.LOCALFIRST_MAX_MSG || '600', 10);

// Simple-question signals — boost confidence but are not required
const SIMPLE_SIGNALS = [
  /^(what|how|why|who|when|where|is|are|can|does|do)\b/i,
  /^(was|wie|warum|wer|wann|wo|ist|sind|kann|macht|erkl[äa]r)/i,
  /^(explain|describe|summarize|translate|list)\b/i,
];

// Ollama reachability cache (30 s TTL)
let ollamaOk        = null;
let ollamaCheckedAt = 0;

function checkOllama() {
  const now = Date.now();
  if (now - ollamaCheckedAt < 30_000 && ollamaOk !== null) return Promise.resolve(ollamaOk);
  return new Promise(resolve => {
    const req = http.request(
      { hostname: OLLAMA_HOST, port: OLLAMA_PORT, path: '/api/tags', method: 'GET', timeout: 1500 },
      res => {
        ollamaOk = res.statusCode === 200;
        ollamaCheckedAt = Date.now();
        res.resume();
        resolve(ollamaOk);
      }
    );
    req.on('error',   () => { ollamaOk = false; ollamaCheckedAt = Date.now(); resolve(false); });
    req.on('timeout', () => { req.destroy(); ollamaOk = false; ollamaCheckedAt = Date.now(); resolve(false); });
    req.end();
  });
}

// ── Public: routing decision ───────────────────────────────────────────────────

/**
 * @param {object} body  Parsed Anthropic /v1/messages request body
 * @returns {Promise<{ local: boolean, reason: string, model?: string, confidence?: number }>}
 */
async function shouldRouteLocal(body) {
  if (!body?.messages?.length) return { local: false, reason: 'no messages' };

  // Not inside an agentic tool loop
  const hasToolActivity = body.messages.some(m =>
    Array.isArray(m.content) &&
    m.content.some(b => b.type === 'tool_result' || b.type === 'tool_use')
  );
  if (hasToolActivity) return { local: false, reason: 'active tool loop' };

  // Last user message must be plain text within the size budget
  const lastUser = [...body.messages].reverse().find(m => m.role === 'user');
  if (!lastUser) return { local: false, reason: 'no user message' };

  const text =
    typeof lastUser.content === 'string'
      ? lastUser.content
      : Array.isArray(lastUser.content)
        ? lastUser.content.filter(b => b.type === 'text').map(b => b.text).join('\n')
        : '';

  if (!text.trim()) return { local: false, reason: 'empty message' };
  if (text.length > MAX_MSG_LEN) {
    return { local: false, reason: `message too long (${text.length} > ${MAX_MSG_LEN})` };
  }

  // Ollama must be up
  const available = await checkOllama();
  if (!available) return { local: false, reason: 'ollama unavailable' };

  const hasSignal  = SIMPLE_SIGNALS.some(r => r.test(text.trim()));
  const confidence = hasSignal ? 0.9 : 0.7;
  return { local: true, reason: 'simple query → Ollama', model: LOCAL_MODEL, confidence };
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Convert Anthropic messages + optional system string → Ollama chat messages */
function toOllamaMessages(messages, system) {
  const out = [];
  if (system) out.push({ role: 'system', content: typeof system === 'string' ? system : JSON.stringify(system) });
  for (const m of messages) {
    const text =
      typeof m.content === 'string'
        ? m.content
        : Array.isArray(m.content)
          ? m.content.filter(b => b.type === 'text').map(b => b.text).join('\n')
          : '';
    out.push({ role: m.role, content: text });
  }
  return out;
}

/** Write one SSE frame */
function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ── Public: local handler ──────────────────────────────────────────────────────

/**
 * Call Ollama and stream the response back as Anthropic SSE.
 *
 * @param {http.IncomingMessage} _req   Original request (unused, kept for symmetry)
 * @param {http.ServerResponse}  res    Response to write into
 * @param {object}               body   Parsed Anthropic request body
 * @returns {Promise<{ inputTokens: number, outputTokens: number }>}
 */
function handleLocally(_req, res, body) {
  const msgId    = `msg_local_${Date.now()}`;
  const ollamaMsgs = toOllamaMessages(body.messages, body.system);
  // Rough input token estimate (chars / 4)
  const inputTokens = Math.round(
    ollamaMsgs.reduce((s, m) => s + (m.content || '').length, 0) / 4
  );

  res.writeHead(200, {
    'Content-Type':                'text/event-stream',
    'Cache-Control':               'no-cache',
    'Connection':                  'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  sse(res, 'message_start', {
    type: 'message_start',
    message: {
      id: msgId, type: 'message', role: 'assistant', content: [],
      model: LOCAL_MODEL, stop_reason: null, stop_sequence: null,
      usage: { input_tokens: inputTokens, output_tokens: 0 },
    },
  });
  sse(res, 'content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'text', text: '' },
  });
  sse(res, 'ping', { type: 'ping' });

  const payload = JSON.stringify({ model: LOCAL_MODEL, messages: ollamaMsgs, stream: true });
  let outputTokens = 0;
  let buf = '';

  return new Promise(resolve => {
    function finish() {
      sse(res, 'content_block_stop', { type: 'content_block_stop', index: 0 });
      sse(res, 'message_delta', {
        type: 'message_delta',
        delta: { stop_reason: 'end_turn', stop_sequence: null },
        usage: { output_tokens: outputTokens },
      });
      sse(res, 'message_stop', { type: 'message_stop' });
      res.end();
      resolve({ inputTokens, outputTokens });
    }

    function processLine(line) {
      if (!line.trim()) return;
      try {
        const d = JSON.parse(line);
        const token = d.message?.content || '';
        if (token) {
          outputTokens++;
          sse(res, 'content_block_delta', {
            type: 'content_block_delta', index: 0,
            delta: { type: 'text_delta', text: token },
          });
        }
        if (d.done) finish();
      } catch { /* skip malformed NDJSON */ }
    }

    const ollamaReq = http.request(
      {
        hostname: OLLAMA_HOST, port: OLLAMA_PORT,
        path: '/api/chat', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
        timeout: 60_000,
      },
      ollamaRes => {
        ollamaRes.on('data', chunk => {
          buf += chunk.toString();
          const lines = buf.split('\n');
          buf = lines.pop();
          for (const line of lines) processLine(line);
        });
        ollamaRes.on('end', () => {
          if (buf.trim()) processLine(buf);
          finish();
        });
        ollamaRes.on('error', err => {
          process.stderr.write(`[localrouter] Ollama stream error: ${err.message}\n`);
          finish();
        });
      }
    );

    ollamaReq.on('error',   err => { process.stderr.write(`[localrouter] connect error: ${err.message}\n`); finish(); });
    ollamaReq.on('timeout', ()  => { ollamaReq.destroy(); process.stderr.write('[localrouter] timeout\n'); finish(); });
    ollamaReq.end(payload);
  });
}

module.exports = { shouldRouteLocal, handleLocally };
