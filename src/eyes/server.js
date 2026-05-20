'use strict';

/**
 * eyes/server.js — local HTTP server for the Eyes browser UI.
 *
 * Endpoints:
 *   GET  /                  → serves the single-page UI (web-ui.html)
 *   GET  /api/exchanges     → list of all captured exchanges (metadata only)
 *   GET  /api/exchanges/:n  → full payload JSON for one exchange
 *   GET  /events            → Server-Sent Events stream of new exchanges
 *
 * Binds to 127.0.0.1 only — never exposed off-box. No auth, no CORS, no
 * outbound network. Reads `~/.occasio/eyes/payload-NNNN.json` files written
 * by the proxy when started with `--eyes`.
 *
 * Demo mode: `occasio eyes --demo` serves the synthetic payloads from
 * demo-content.js instead of disk, so the UI is testable with zero setup.
 */

const fs   = require('fs');
const path = require('path');
const http = require('http');
const os   = require('os');

const { EYES_DIR } = require('./capture');
const { PAYLOADS: DEMO_PAYLOADS } = require('./demo-content');

const DEFAULT_PORT = 3002;

function readHtml() {
  const p = path.join(__dirname, 'web-ui.html');
  try { return fs.readFileSync(p, 'utf8'); }
  catch { return '<html><body><h1>Eyes UI missing</h1><p>Could not load web-ui.html</p></body></html>'; }
}

function listFiles(dir) {
  try {
    return fs.readdirSync(dir)
      .filter(n => n.startsWith('payload-') && n.endsWith('.json'))
      .sort();
  } catch { return []; }
}

function readPayload(dir, name) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
  catch { return null; }
}

/**
 * Build the lightweight metadata view of an exchange used by the sidebar.
 * Heavy bodies stay on disk until the client opens that exchange.
 */
function summarize(payload) {
  if (!payload) return null;
  // We extract both the FIRST and LAST user-text from the message history.
  // - firstUserText: stable prompt that opened this conversation (for context)
  // - lastUserText:  most recent user prompt — what the agent is *currently*
  //                  working on. Exchanges with the same lastUserText belong
  //                  to the same turn (agentic loop: prompt → tool → prompt
  //                  unchanged → tool again → …). The sidebar groups by this.
  let firstUserText = null;
  let lastUserText  = null;
  let toolUses = 0, toolResults = 0;
  if (Array.isArray(payload.messages)) {
    for (const m of payload.messages) {
      for (const b of m.blocks || []) {
        if (b.kind === 'text' && m.role === 'user' && b.text) {
          const clean = b.text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '').trim();
          if (!clean) continue;
          if (!firstUserText) firstUserText = clean.slice(0, 200);
          lastUserText = clean.slice(0, 200);
        }
        if (b.kind === 'tool_use') toolUses++;
        if (b.kind === 'tool_result') toolResults++;
      }
    }
  }
  let responseTools = 0, responseText = null;
  if (payload.response && Array.isArray(payload.response.blocks)) {
    for (const b of payload.response.blocks) {
      if (b.kind === 'tool_use') responseTools++;
      if (b.kind === 'text' && !responseText) responseText = (b.text || '').slice(0, 160);
    }
  }
  return {
    seq: payload.seq, ts: payload.ts, runId: payload.runId,
    model: payload.model || payload.response?.model || null,
    bytesOut: payload.byteCount?.after || 0,
    bytesIn:  payload.responseMeta?.bytes || 0,
    redactions: payload.redactionCount || 0,
    blocked:    payload.blockedCount   || 0,
    promptPreview: lastUserText || firstUserText,
    firstPromptPreview: firstUserText,
    toolUses, toolResults, responseTools,
    responseText,
    stopReason: payload.response?.stopReason || null,
  };
}

// ── SSE plumbing ────────────────────────────────────────────────────────────

function createServer(opts) {
  opts = opts || {};
  const isDemo = !!opts.demo;
  const eyesDir = opts.eyesDir || EYES_DIR;
  const clients = new Set();
  let lastFileCount = -1;

  function broadcast(event, data) {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of clients) {
      try { res.write(payload); } catch { clients.delete(res); }
    }
  }

  function loadPayloads() {
    if (isDemo) return DEMO_PAYLOADS.slice();
    const files = listFiles(eyesDir);
    const out = [];
    for (const f of files) {
      const p = readPayload(eyesDir, f);
      if (p) out.push(p);
    }
    return out;
  }

  // Poll for new files. Could use fs.watch but watch is unreliable on Windows
  // for files written from a different process — poll is what dashboard.js
  // already does for the proxy session file.
  const pollMs = opts.pollMs || 500;
  const pollTimer = isDemo ? null : setInterval(() => {
    if (clients.size === 0) return;
    const files = listFiles(eyesDir);
    if (files.length === lastFileCount) return;
    lastFileCount = files.length;
    broadcast('exchanges-changed', { count: files.length });
  }, pollMs);

  const html = readHtml();

  function handle(req, res) {
    const url = req.url || '/';

    // Static UI
    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // SSE
    if (url === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.write('retry: 2000\n\n');
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }

    // Files: per-path aggregate across all captured exchanges. Answers
    // "what does Anthropic now know about my codebase?". For each tool_use
    // with a path/file_path input, find the matched tool_result (by
    // tool_use_id) and sum its bytes. Group by path, return sorted desc.
    if (url === '/api/files') {
      const payloads = loadPayloads();
      const byPath = new Map();
      for (const p of payloads) {
        if (!p || !Array.isArray(p.messages)) continue;
        // First pass: id → path
        const idToPath = new Map();
        for (const m of p.messages) {
          for (const b of m.blocks || []) {
            if (b.kind === 'tool_use' && b.toolUseId) {
              const pth = b.input?.path || b.input?.file_path || b.input?.pattern || b.input?.command;
              if (pth) idToPath.set(b.toolUseId, { path: String(pth), tool: b.toolName });
            }
          }
        }
        // Second pass: tool_result bytes → aggregate by path
        for (const m of p.messages) {
          for (const b of m.blocks || []) {
            if (b.kind !== 'tool_result' || !b.toolUseId) continue;
            const info = idToPath.get(b.toolUseId);
            if (!info) continue;
            const cur = byPath.get(info.path) || { path: info.path, tool: info.tool, count: 0, bytes: 0, exchanges: new Set() };
            cur.count += 1;
            cur.bytes += (b.bytes || 0);
            cur.exchanges.add(p.seq);
            byPath.set(info.path, cur);
          }
        }
      }
      const list = [...byPath.values()].map(x => ({
        path: x.path, tool: x.tool, count: x.count, bytes: x.bytes,
        exchanges: [...x.exchanges].sort((a, b) => a - b),
      })).sort((a, b) => b.bytes - a.bytes);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ files: list, totalBytes: list.reduce((s, x) => s + x.bytes, 0) }));
      return;
    }

    // List
    if (url === '/api/exchanges') {
      const payloads = loadPayloads();
      const out = payloads.map(summarize).filter(Boolean);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ exchanges: out, demo: isDemo }));
      return;
    }

    // Content blob (lazy-loaded by UI for tool outputs, originals, LAO drops)
    const cm = url.match(/^\/api\/content\/(sha256-[0-9a-f]+)$/);
    if (cm) {
      const ref = cm[1];
      const cs = require('./content-store');
      const buf = cs.read(ref);
      if (!buf) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found', ref }));
        return;
      }
      // Cap response size at 5 MB even though store accepts up to 2 MB per
      // blob — defensive against future content-store changes.
      const out = buf.length > 5_000_000 ? buf.slice(0, 5_000_000) : buf;
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Content-Bytes': String(buf.length),
        'X-Content-Truncated': buf.length > out.length ? '1' : '0',
      });
      res.end(out);
      return;
    }

    // Detail
    const m = url.match(/^\/api\/exchanges\/(\d+)$/);
    if (m) {
      const seq = parseInt(m[1], 10);
      const payloads = loadPayloads();
      const found = payloads.find(p => p && p.seq === seq);
      if (!found) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(found));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  }

  const server = http.createServer(handle);

  return {
    server,
    listen(port, host, cb) {
      const p = (port === 0 || port) ? port : DEFAULT_PORT;
      server.listen(p, host || '127.0.0.1', cb);
    },
    close(cb) {
      if (pollTimer) clearInterval(pollTimer);
      for (const c of clients) { try { c.end(); } catch { /* ignore */ } }
      clients.clear();
      server.close(cb || (() => {}));
    },
    // exposed for testing
    _summarize: summarize,
    _loadPayloads: loadPayloads,
    _broadcast: broadcast,
  };
}

function openBrowser(url) {
  try {
    const { exec } = require('child_process');
    const cmd = process.platform === 'win32' ? `start "" "${url}"`
              : process.platform === 'darwin' ? `open "${url}"`
              : `xdg-open "${url}"`;
    exec(cmd, { shell: true }, () => {});
  } catch { /* ignore */ }
}

module.exports = { createServer, summarize, openBrowser, DEFAULT_PORT };
