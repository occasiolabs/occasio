'use strict';

/**
 * eyes/capture.js — outbound payload capture for `occasio eyes`.
 *
 * Opt-in via `occasio claude --eyes`. When active, the proxy calls
 * captureOutbound(body, meta) right before forwarding to api.anthropic.com.
 * We extract the user-visible parts (system prompt, messages, tool_results)
 * and write a JSON file under ~/.occasio/eyes/payload-NNNN.json.
 *
 * Privacy posture:
 *   - off by default; must be explicitly enabled per session
 *   - bounded ringbuffer: at most CAPTURE_MAX files retained
 *   - per-payload cap PAYLOAD_MAX_BYTES (truncates tool_result bodies)
 *   - directory wiped on session start so previous sessions don't leak forward
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const EYES_DIR        = path.join(os.homedir(), '.occasio', 'eyes');
const CAPTURE_MAX     = 20;       // most recent N outbounds kept
const PAYLOAD_MAX_BYTES = 200_000; // ~200KB per file — bounds disk usage
const PER_BLOCK_MAX   = 80_000;   // any single tool_result body truncated past this

let SEQ = 0;
let ENABLED = false;

function enable() { ENABLED = true; }
function isEnabled() { return ENABLED; }

function ensureDir() {
  try { fs.mkdirSync(EYES_DIR, { recursive: true }); } catch { /* ignore */ }
}

const contentStore = require('./content-store');

/**
 * Sanitize HTTP headers for capture. We log everything EXCEPT credentials
 * (Authorization, x-api-key) — those are masked to '[REDACTED]'. Lowercase
 * keys for stable comparison.
 */
function sanitizeHeaders(h) {
  if (!h || typeof h !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase();
    if (lk === 'authorization' || lk === 'x-api-key' || lk === 'cookie' || lk === 'set-cookie') out[lk] = '[REDACTED]';
    else out[lk] = String(v);
  }
  return out;
}

/**
 * Wipe stale files so old sessions don't leak into a fresh `occasio eyes`.
 * Called once at session start when --eyes is set.
 */
function resetSession() {
  ensureDir();
  try {
    for (const f of fs.readdirSync(EYES_DIR)) {
      if (f.startsWith('payload-') && f.endsWith('.json')) {
        try { fs.unlinkSync(path.join(EYES_DIR, f)); } catch { /* ignore */ }
      }
    }
  } catch { /* dir may not exist yet */ }
  SEQ = 0;
}

/** truncate a string body, marking how much was cut */
function clipText(s, max) {
  if (typeof s !== 'string') return { text: '', bytes: 0, truncated: false };
  if (s.length <= max) return { text: s, bytes: s.length, truncated: false };
  return {
    text: s.slice(0, max) + `\n…[truncated ${s.length - max} chars]`,
    bytes: s.length,
    truncated: true,
  };
}

/** flatten a message content (string | block[]) into our display blocks */
function flattenContent(content) {
  if (typeof content === 'string') {
    const c = clipText(content, PER_BLOCK_MAX);
    return [{ kind: 'text', text: c.text, bytes: c.bytes, truncated: c.truncated }];
  }
  if (!Array.isArray(content)) return [];
  const out = [];
  for (const block of content) {
    if (!block || typeof block !== 'object') continue;
    if (block.type === 'text') {
      const c = clipText(block.text, PER_BLOCK_MAX);
      out.push({ kind: 'text', text: c.text, bytes: c.bytes, truncated: c.truncated });
    } else if (block.type === 'tool_use') {
      out.push({
        kind: 'tool_use',
        toolName: block.name || 'unknown',
        toolUseId: block.id || null,
        input: block.input || {},
      });
    } else if (block.type === 'tool_result') {
      // content can be string or [{type:'text',text}]
      let body = '';
      if (typeof block.content === 'string') body = block.content;
      else if (Array.isArray(block.content)) {
        for (const b of block.content) {
          if (b && b.type === 'text' && typeof b.text === 'string') body += (body ? '\n' : '') + b.text;
        }
      }
      const c = clipText(body, PER_BLOCK_MAX);
      out.push({
        kind: 'tool_result',
        toolUseId: block.tool_use_id || null,
        isError: !!block.is_error,
        text: c.text,
        bytes: c.bytes,
        truncated: c.truncated,
      });
    } else {
      out.push({ kind: 'other', type: block.type || 'unknown' });
    }
  }
  return out;
}

/**
 * Extract the display payload from an outbound /v1/messages body. Pure.
 * `body` is the parsed JSON object that's about to be forwarded.
 */
function extractPayload(body, meta) {
  meta = meta || {};
  const out = {
    schema: 1,
    seq:    typeof meta.seq === 'number' ? meta.seq : 0,
    ts:     meta.ts || new Date().toISOString(),
    runId:  meta.runId || null,
    model:  body && body.model ? body.model : null,
    byteCount: {
      before: meta.byteCountBefore || 0,
      after:  meta.byteCountAfter  || 0,
    },
    system:   null,
    messages: [],
    laoDropped: meta.laoDropped || [],
    redactionCount: meta.redactionCount || 0,
    blockedCount:   meta.blockedCount   || 0,
  };

  if (body && body.system) {
    if (typeof body.system === 'string') {
      const c = clipText(body.system, PER_BLOCK_MAX);
      out.system = { text: c.text, bytes: c.bytes, truncated: c.truncated };
    } else if (Array.isArray(body.system)) {
      let joined = '';
      for (const b of body.system) {
        if (b && b.type === 'text' && typeof b.text === 'string') joined += (joined ? '\n' : '') + b.text;
      }
      const c = clipText(joined, PER_BLOCK_MAX);
      out.system = { text: c.text, bytes: c.bytes, truncated: c.truncated };
    }
  }

  if (body && Array.isArray(body.messages)) {
    // keep ALL messages so a tool_result can be paired with its tool_use by id;
    // total size is bounded by PAYLOAD_MAX_BYTES guard below.
    for (const m of body.messages) {
      if (!m || typeof m !== 'object') continue;
      out.messages.push({
        role: m.role || 'unknown',
        blocks: flattenContent(m.content),
      });
    }
  }
  return out;
}

/** Persist a payload to disk, then prune older entries. */
function captureOutbound(body, meta) {
  if (!ENABLED) return null;
  ensureDir();
  SEQ += 1;
  meta = meta || {};
  const payload = extractPayload(body, Object.assign({}, meta, { seq: SEQ }));

  // ── NEW: capture HTTP-level metadata ─────────────────────────────────────
  if (meta.method)         payload.method = meta.method;
  if (meta.url)            payload.url    = meta.url;
  if (meta.requestHeaders) payload.requestHeaders = sanitizeHeaders(meta.requestHeaders);

  // ── NEW: capture pre-transform body (originals — secrets in the clear,
  // LAO-dropped files in full). Stored in the content store so we don't
  // bloat the per-exchange JSON.
  if (meta.originalBody) {
    const buf = Buffer.isBuffer(meta.originalBody)
      ? meta.originalBody
      : Buffer.from(typeof meta.originalBody === 'string'
          ? meta.originalBody
          : JSON.stringify(meta.originalBody));
    payload.originalBodyRef = contentStore.store(buf);
    payload.originalBytes   = buf.length;
  }

  // ── NEW: per-redaction before/after refs ──────────────────────────────────
  if (Array.isArray(meta.redactionDiffs) && meta.redactionDiffs.length) {
    payload.redactionDiffs = meta.redactionDiffs.map(d => ({
      toolUseId: d.toolUseId || null,
      path:      d.path || null,
      labels:    d.labels || [],
      beforeRef: d.before ? contentStore.store(d.before) : null,
      afterRef:  d.after  ? contentStore.store(d.after)  : null,
      bytesBefore: d.before ? Buffer.byteLength(d.before) : 0,
      bytesAfter:  d.after  ? Buffer.byteLength(d.after)  : 0,
    }));
  }

  // ── NEW: per-LAO-drop content refs ────────────────────────────────────────
  if (Array.isArray(meta.laoDroppedContent) && meta.laoDroppedContent.length) {
    payload.laoDroppedContent = meta.laoDroppedContent.map(d => ({
      toolUseId: d.tool_use_id || d.toolUseId || null,
      path:      d.path || null,
      bytes:     d.bytes || (d.content ? Buffer.byteLength(d.content) : 0),
      contentRef: d.content ? contentStore.store(d.content) : null,
    }));
  }

  // ── NEW: per-exchange local tool calls (Read/Glob/Grep/Bash with output) ──
  if (Array.isArray(meta.localTools) && meta.localTools.length) {
    payload.localTools = meta.localTools.map(t => ({
      tool: t.tool, cmd: t.cmd, bytes: t.bytes || 0,
      exitCode: typeof t.exitCode === 'number' ? t.exitCode : null,
      distilled: !!t.distilled, distillLabel: t.distillLabel || null,
      distillSaved: t.distillSaved || 0,
      preventionReason: t.preventionReason || null,
      // raw output → content store; clip text only if absurdly large
      outputRef: t.output ? contentStore.store(String(t.output).slice(0, 2_000_000)) : null,
      rawContentRef: t.rawContent ? contentStore.store(String(t.rawContent).slice(0, 2_000_000)) : null,
    }));
  }

  let json = JSON.stringify(payload);
  if (json.length > PAYLOAD_MAX_BYTES) {
    while (json.length > PAYLOAD_MAX_BYTES && payload.messages.length > 1) {
      payload.messages.shift();
      payload._head_trimmed = true;
      json = JSON.stringify(payload);
    }
  }

  const fname = `payload-${String(SEQ).padStart(6, '0')}.json`;
  const fpath = path.join(EYES_DIR, fname);
  try { fs.writeFileSync(fpath, json); }
  catch { return null; }

  pruneOldest();
  return fpath;
}

/**
 * Capture a generic HTTP request (any endpoint, any method). The full
 * request + response bytes are stored in the content store; metadata lands
 * in a lightweight payload file alongside the regular /v1/messages
 * captures. Use this for /v1/messages?count_tokens, /v1/complete, OAuth
 * endpoints, anything else the proxy mediates.
 */
function captureGenericHttp(meta) {
  if (!ENABLED) return null;
  ensureDir();
  SEQ += 1;
  meta = meta || {};
  const payload = {
    schema: 1, seq: SEQ,
    ts: meta.ts || new Date().toISOString(),
    kind: 'http_generic',
    method: meta.method || 'GET',
    url:    meta.url    || '/',
    runId:  meta.runId  || null,
    requestHeaders:  sanitizeHeaders(meta.requestHeaders),
    responseHeaders: sanitizeHeaders(meta.responseHeaders),
    statusCode: meta.statusCode || null,
    requestBodyRef:  meta.requestBody  ? contentStore.store(meta.requestBody)  : null,
    responseBodyRef: meta.responseBody ? contentStore.store(meta.responseBody) : null,
    requestBytes:  meta.requestBody  ? Buffer.byteLength(meta.requestBody)  : 0,
    responseBytes: meta.responseBody ? Buffer.byteLength(meta.responseBody) : 0,
  };
  const fname = `payload-${String(SEQ).padStart(6, '0')}.json`;
  const fpath = path.join(EYES_DIR, fname);
  try { fs.writeFileSync(fpath, JSON.stringify(payload)); } catch { return null; }
  pruneOldest();
  return fpath;
}

function listPayloads() {
  ensureDir();
  let names;
  try { names = fs.readdirSync(EYES_DIR); }
  catch { return []; }
  return names
    .filter(n => n.startsWith('payload-') && n.endsWith('.json'))
    .sort(); // lexicographic == numeric since we zero-pad seq
}

function pruneOldest() {
  const all = listPayloads();
  if (all.length <= CAPTURE_MAX) return;
  const excess = all.length - CAPTURE_MAX;
  for (let i = 0; i < excess; i++) {
    try { fs.unlinkSync(path.join(EYES_DIR, all[i])); } catch { /* ignore */ }
  }
}

function readPayload(file) {
  const full = path.isAbsolute(file) ? file : path.join(EYES_DIR, file);
  try { return JSON.parse(fs.readFileSync(full, 'utf8')); }
  catch { return null; }
}

/**
 * Parse an inbound /v1/messages response into a display object.
 * Handles both the SSE event-stream format (Claude Code uses this) and the
 * plain-JSON non-streaming format. Returns null on any failure.
 *
 *   { role: 'assistant', model, stopReason, usage, blocks: [...] }
 */
function parseInbound(bytes) {
  if (!bytes) return null;
  const text = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);

  // Try plain JSON first
  try {
    const obj = JSON.parse(text);
    if (obj && obj.role === 'assistant' && Array.isArray(obj.content)) {
      return {
        role: 'assistant',
        model: obj.model || null,
        stopReason: obj.stop_reason || null,
        usage: obj.usage || null,
        blocks: flattenContent(obj.content),
      };
    }
  } catch { /* fall through to SSE */ }

  // SSE: lines of `event: X` then `data: <json>` separated by blank lines
  const blocks = [];          // by content_block index
  let model = null, stopReason = null, usage = null;
  for (const line of text.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const json = line.slice(5).trim();
    if (!json || json === '[DONE]') continue;
    let ev;
    try { ev = JSON.parse(json); } catch { continue; }
    if (ev.type === 'message_start' && ev.message) {
      model = ev.message.model || model;
      if (ev.message.usage) usage = Object.assign({}, usage, ev.message.usage);
    } else if (ev.type === 'content_block_start' && typeof ev.index === 'number') {
      const cb = ev.content_block || {};
      if (cb.type === 'text') {
        blocks[ev.index] = { kind: 'text', text: cb.text || '', bytes: (cb.text || '').length, truncated: false };
      } else if (cb.type === 'tool_use') {
        blocks[ev.index] = { kind: 'tool_use', toolName: cb.name, toolUseId: cb.id, input: cb.input || {}, _inputJson: '' };
      } else {
        blocks[ev.index] = { kind: 'other', type: cb.type || 'unknown' };
      }
    } else if (ev.type === 'content_block_delta' && typeof ev.index === 'number') {
      const cb = blocks[ev.index];
      const d = ev.delta || {};
      if (!cb) continue;
      if (cb.kind === 'text' && d.type === 'text_delta') {
        cb.text = (cb.text || '') + (d.text || '');
        cb.bytes = cb.text.length;
      } else if (cb.kind === 'tool_use' && d.type === 'input_json_delta') {
        cb._inputJson = (cb._inputJson || '') + (d.partial_json || '');
      }
    } else if (ev.type === 'content_block_stop' && typeof ev.index === 'number') {
      const cb = blocks[ev.index];
      if (cb && cb.kind === 'tool_use' && cb._inputJson) {
        try { cb.input = JSON.parse(cb._inputJson); } catch { /* keep what we have */ }
        delete cb._inputJson;
      }
    } else if (ev.type === 'message_delta') {
      if (ev.delta && ev.delta.stop_reason) stopReason = ev.delta.stop_reason;
      if (ev.usage) usage = Object.assign({}, usage, ev.usage);
    }
  }
  // Clip oversized text blocks
  for (const b of blocks) {
    if (b && b.kind === 'text') {
      const c = clipText(b.text, PER_BLOCK_MAX);
      b.text = c.text; b.bytes = c.bytes; b.truncated = c.truncated;
    }
  }
  if (!blocks.length && !model) return null;
  return {
    role: 'assistant',
    model, stopReason, usage,
    blocks: blocks.filter(Boolean),
  };
}

/**
 * Augment an existing exchange file with the inbound response. Best-effort;
 * any failure is swallowed since the proxy must never break.
 *
 *   completeExchange(filePath, { responseBytes, intercepted, statusCode })
 */
function completeExchange(filePath, meta) {
  if (!ENABLED || !filePath) return;
  meta = meta || {};
  let obj;
  try { obj = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return; }
  const parsed = parseInbound(meta.responseBytes);
  obj.response = parsed;
  obj.responseMeta = {
    bytes: meta.responseBytes ? meta.responseBytes.length : 0,
    intercepted: !!meta.intercepted,
    statusCode: meta.statusCode || null,
    completedAt: new Date().toISOString(),
  };
  if (meta.responseHeaders) obj.responseHeaders = sanitizeHeaders(meta.responseHeaders);
  // Local tools executed by the interceptor for this exchange (Read/Glob/Grep/
  // Bash). Each output goes through the content store so the per-exchange JSON
  // stays compact while the bytes remain inspectable.
  if (Array.isArray(meta.localTools) && meta.localTools.length) {
    obj.localTools = meta.localTools.map(t => ({
      tool: t.tool, cmd: t.cmd, bytes: t.bytes || 0,
      exitCode: typeof t.exitCode === 'number' ? t.exitCode : null,
      distilled: !!t.distilled, distillLabel: t.distillLabel || null,
      distillSaved: t.distillSaved || 0,
      preventionReason: t.prevention_reason || t.preventionReason || null,
      outputRef:     t.output     ? contentStore.store(String(t.output).slice(0, 2_000_000))     : null,
      rawContentRef: t.rawContent ? contentStore.store(String(t.rawContent).slice(0, 2_000_000)) : null,
    }));
  }
  // Optional: store the raw response bytes (capped) for raw-mode view.
  if (meta.responseBytes && meta.responseBytes.length) {
    const raw = Buffer.isBuffer(meta.responseBytes) ? meta.responseBytes.toString('utf8') : String(meta.responseBytes);
    const c = clipText(raw, PER_BLOCK_MAX);
    obj.responseRaw = { text: c.text, bytes: c.bytes, truncated: c.truncated };
  }
  let json = JSON.stringify(obj);
  if (json.length > PAYLOAD_MAX_BYTES) {
    // shed raw first, then trim oldest messages
    delete obj.responseRaw;
    json = JSON.stringify(obj);
    while (json.length > PAYLOAD_MAX_BYTES && obj.messages && obj.messages.length > 1) {
      obj.messages.shift();
      obj._head_trimmed = true;
      json = JSON.stringify(obj);
    }
  }
  try { fs.writeFileSync(filePath, json); } catch { /* ignore */ }
}

// Inbound completion: also store full response headers if provided.
function completeExchangeWithHeaders(filePath, meta) {
  if (!ENABLED || !filePath) return;
  completeExchange(filePath, meta);
  // re-open + augment with headers (completeExchange writes the file already)
  if (!meta || !meta.responseHeaders) return;
  let obj;
  try { obj = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return; }
  obj.responseHeaders = sanitizeHeaders(meta.responseHeaders);
  try { fs.writeFileSync(filePath, JSON.stringify(obj)); } catch { /* ignore */ }
}

module.exports = {
  enable, isEnabled, resetSession,
  captureOutbound, captureGenericHttp,
  extractPayload, flattenContent, clipText, sanitizeHeaders,
  parseInbound, completeExchange, completeExchangeWithHeaders,
  listPayloads, readPayload,
  EYES_DIR, CAPTURE_MAX, PAYLOAD_MAX_BYTES, PER_BLOCK_MAX,
};
