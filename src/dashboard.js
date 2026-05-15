'use strict';

/**
 * dashboard.js — Occasio web dashboard on port 3001.
 *
 * Serves a single-page HTML dashboard that receives live updates
 * via Server-Sent Events pushed from the proxy's /api/session endpoint.
 *
 * Usage (standalone):  node dashboard.js
 * Usage (sidecar):     spawned by index.js when --dashboard flag is set
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const DASHBOARD_PORT = 3001;
const LOG_DIR      = path.join(os.homedir(), '.occasio');
const SESSION_FILE = path.join(LOG_DIR, 'session.json');

function todayLogFile() {
  const d = new Date();
  const ds = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  return path.join(LOG_DIR, 'logs', `${ds}.jsonl`);
}

// ── SSE clients ────────────────────────────────────────────────────────────────

const clients = new Set();

function broadcast(data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) {
    try { res.write(payload); } catch { clients.delete(res); }
  }
}

// Poll session.json every second and push diffs to SSE clients
let lastSession = null;
setInterval(() => {
  try {
    const raw = fs.readFileSync(SESSION_FILE, 'utf8');
    if (raw === lastSession) return;
    lastSession = raw;
    const session = JSON.parse(raw);
    const entries = readLog();
    broadcast({ type: 'update', session, entries });
  } catch { /* file may not exist yet */ }
}, 1000);

function readLog() {
  try {
    const logFile = todayLogFile();
    if (!fs.existsSync(logFile)) return [];
    const lines = fs.readFileSync(logFile, 'utf8').split('\n');
    const result = [];
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      try {
        const obj = JSON.parse(line);
        if (typeof obj.input_tokens === 'number') result.push(obj);
      } catch { /* skip */ }
    }
    return result.slice(-200);
  } catch { return []; }
}

// ── HTTP server ────────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  if (req.url === '/events') {
    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 2000\n\n');
    clients.add(res);
    try {
      const session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
      const entries = readLog();
      res.write(`data: ${JSON.stringify({ type: 'update', session, entries })}\n\n`);
    } catch { /* no session yet */ }
    req.on('close', () => clients.delete(res));
    return;
  }

  if (req.url === '/api/session') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try { res.end(fs.readFileSync(SESSION_FILE, 'utf8')); }
    catch { res.end('{}'); }
    return;
  }

  if (req.url === '/api/clear' && req.method === 'POST') {
    try { fs.writeFileSync(todayLogFile(), ''); } catch { /* ignore */ }
    try { fs.writeFileSync(SESSION_FILE, '{}'); } catch { /* ignore */ }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
    broadcast({ type: 'update', session: {}, entries: [] });
    return;
  }

  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDashboardHtml());
    return;
  }

  res.writeHead(404); res.end('Not found');
});

function getDashboardHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Occasio Dashboard</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 13px;
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 24px;
  min-height: 100vh;
}

header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}

h1 { font-size: 18px; font-weight: 600; letter-spacing: 0.01em; }
h1 span { color: #4ec9b0; }

.header-right { display: flex; align-items: center; gap: 12px; }

.dot { width: 8px; height: 8px; border-radius: 50%; background: #4ec9b0; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:.4 } }

.btn {
  background: #2d2d2d;
  color: #d4d4d4;
  border: 1px solid #444;
  padding: 6px 14px;
  border-radius: 5px;
  cursor: pointer;
  font-size: 12px;
}
.btn:hover { background: #3a3a3a; }

.scope-toggle { display: flex; }
.scope-btn {
  background: #2d2d2d;
  color: #666;
  border: 1px solid #444;
  padding: 5px 14px;
  cursor: pointer;
  font-size: 12px;
}
.scope-btn:first-child { border-radius: 5px 0 0 5px; }
.scope-btn:last-child  { border-radius: 0 5px 5px 0; border-left: none; }
.scope-btn.active { background: #3a3a3a; color: #d4d4d4; border-color: #555; }

.hero {
  background: rgba(78, 201, 176, 0.10);
  border: 1px solid rgba(78, 201, 176, 0.25);
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 14px;
}
.hero-saved {
  font-size: 20px;
  font-weight: 600;
  color: #4ec9b0;
  letter-spacing: 0.2px;
}
.hero-sub {
  font-size: 13px;
  color: #888;
  margin-top: 4px;
}

.cards {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}
@media (max-width: 800px) { .cards { grid-template-columns: repeat(3, 1fr); } }

.card {
  background: #252526;
  border-radius: 8px;
  padding: 14px 16px;
  text-align: center;
}

.card-value {
  font-size: 24px;
  font-weight: 700;
  line-height: 1.1;
  color: #d4d4d4;
}
.card-value.green  { color: #4ec9b0; }
.card-value.yellow { color: #dcdcaa; }
.card-value.local  { color: #9cdcfe; }

.card-label {
  font-size: 10px;
  color: #888;
  margin-top: 6px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.card-sub { font-size: 10px; color: #666; margin-top: 3px; }

.insights {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.insight {
  background: #252526;
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 12px;
  flex: 1;
  min-width: 180px;
}
.insight-label { font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
.insight-value { font-weight: 600; }

.graph-wrap {
  background: #252526;
  border-radius: 8px;
  padding: 14px 16px;
  margin-bottom: 20px;
}
.graph-title { font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 10px; }
.graph-svg { width: 100%; display: block; }

table { width: 100%; border-collapse: collapse; font-size: 12px; }

th {
  text-align: left;
  padding: 7px 10px;
  color: #888;
  font-weight: 500;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid #333;
}

td {
  padding: 7px 10px;
  border-bottom: 1px solid #2a2a2a;
  vertical-align: middle;
  white-space: nowrap;
}

tr.data-row { cursor: pointer; }
tr.data-row:hover td { background: #2a2a2a; }
tr.data-row.expanded td { background: #262626; }

/* ── Detail panel (Level 1 + 2 + 3) ─────────────────────────────────────── */

tr.detail-row td { padding: 0; border-bottom: 1px solid #333; }

.detail-panel {
  display: flex;
  gap: 0;
  background: #1a1a1a;
  border-left: 2px solid #333;
}

.detail-section {
  flex: 1;
  padding: 12px 14px;
  border-right: 1px solid #2a2a2a;
  min-width: 0;
}
.detail-section:last-child { border-right: none; }

.detail-title {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #666;
  margin-bottom: 8px;
  font-weight: 600;
}

/* Level 1: file bars */
.file-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
  font-size: 11px;
}
.file-name {
  width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  color: #9cdcfe;
  flex-shrink: 0;
  font-family: 'Consolas', 'Menlo', monospace;
}
.file-bar-wrap {
  flex: 1;
  background: #2a2a2a;
  border-radius: 2px;
  height: 4px;
  overflow: hidden;
}
.file-bar-fill { height: 100%; background: #4a7fa5; border-radius: 2px; }
.file-tok {
  width: 38px;
  text-align: right;
  color: #888;
  font-size: 10px;
  flex-shrink: 0;
}

/* Level 2: secrets */
.secret-row {
  margin-bottom: 5px;
  font-size: 11px;
  line-height: 1.4;
}
.secret-label { color: #f48771; font-weight: 600; }
.secret-line  { color: #888; font-size: 10px; }
.secret-snip  { color: #555; font-family: 'Consolas', 'Menlo', monospace; font-size: 10px; word-break: break-all; white-space: normal; }

/* Level 3: tools */
.tool-row {
  margin-bottom: 5px;
  font-size: 11px;
  line-height: 1.4;
}
.tool-cmd    { color: #4ec9b0; font-family: 'Consolas', 'Menlo', monospace; }
.tool-meta   { color: #666; font-size: 10px; }

/* ── Tags ─────────────────────────────────────────────────────────────────── */

.tag-ok      { color: #4ec9b0; }
.tag-secret  { color: #f48771; }
.tag-local   { color: #9cdcfe; }

.empty { text-align: center; color: #555; padding: 48px 0; }
.footer { margin-top: 16px; font-size: 11px; color: #555; }

.ctx-bar { display:flex; height:5px; border-radius:3px; overflow:hidden; width:70px; background:#333; }
.ctx-new  { background: #4ec9b0; }
.ctx-old  { background: #444; }

#status { font-size: 11px; color: #666; }
#status.connected { color: #4ec9b0; }
</style>
</head>
<body>

<header>
  <h1>⚡ <span>Occasio</span> Dashboard</h1>
  <div class="header-right">
    <div class="scope-toggle">
      <button class="scope-btn active" id="scope-session" onclick="setScope('session')">Session</button>
      <button class="scope-btn"        id="scope-today"   onclick="setScope('today')">Today</button>
    </div>
    <span id="status">connecting…</span>
    <div class="dot" id="dot" style="background:#666"></div>
    <button class="btn" id="clearBtn">Clear</button>
  </div>
</header>

<div class="hero" id="hero" style="display:none">
  <div class="hero-saved" id="hero-saved">—</div>
  <div class="hero-sub" id="hero-sub">—</div>
</div>

<div class="cards">
  <div class="card">
    <div class="card-value" id="c-req">—</div>
    <div class="card-label">Requests</div>
  </div>
  <div class="card">
    <div class="card-value yellow" id="c-in">—</div>
    <div class="card-label">Tokens In</div>
    <div class="card-sub" id="c-in-sub"></div>
  </div>
  <div class="card">
    <div class="card-value yellow" id="c-out">—</div>
    <div class="card-label">Tokens Out</div>
  </div>
  <div class="card">
    <div class="card-value green" id="c-cost">—</div>
    <div class="card-label">Cost</div>
    <div class="card-sub" id="c-cost-sub"></div>
  </div>
  <div class="card">
    <div class="card-value local" id="c-local">—</div>
    <div class="card-label">Run locally</div>
    <div class="card-sub" id="c-saved"></div>
  </div>
</div>

<div class="insights">
  <div class="insight">
    <div class="insight-label">Largest request</div>
    <div class="insight-value" id="i-peak">—</div>
  </div>
  <div class="insight">
    <div class="insight-label">Context overhead</div>
    <div class="insight-value" id="i-ctx">—</div>
  </div>
  <div class="insight">
    <div class="insight-label">Projected / hr</div>
    <div class="insight-value" id="i-proj">—</div>
  </div>
  <div class="insight">
    <div class="insight-label">Breakdown</div>
    <div class="insight-value" id="i-saved">—</div>
  </div>
  <div class="insight">
    <div class="insight-label">Tools intercepted</div>
    <div class="insight-value" id="i-intercepted">—</div>
  </div>
</div>

<div class="graph-wrap" id="graph-wrap" style="display:none">
  <div class="graph-title">Input tokens per request — current session</div>
  <svg class="graph-svg" id="graph" height="60" viewBox="0 0 600 60" preserveAspectRatio="none"></svg>
</div>

<table>
  <thead>
    <tr>
      <th>Time</th>
      <th>Model</th>
      <th>Tokens In</th>
      <th>Tokens Out</th>
      <th>Cost</th>
      <th>New vs Context</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody id="rows">
    <tr><td colspan="7" class="empty">Waiting for Occasio proxy…</td></tr>
  </tbody>
</table>

<div class="footer" id="footer"></div>

<script>
  // ── Helpers ──────────────────────────────────────────────────────────────────

  function fmt(n) {
    if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
    if (n >= 1e3) return (n/1e3).toFixed(1)+'k';
    return String(n||0);
  }

  function shortModel(m) {
    return (m||'?').replace('claude-','').replace(/-\\d{8}$/,'');
  }

  function enrich(entries) {
    return entries.map((e, i) => {
      const prev   = i === 0 ? 0 : entries[i-1].input_tokens;
      const newTok = Math.max(0, e.input_tokens - prev);
      const newPct = e.input_tokens > 0 ? Math.round((newTok / e.input_tokens) * 100) : 100;
      return { ...e, newPct };
    });
  }

  function parseTs(ts) {
    if (!ts) return 0;
    const p = ts.split(':').map(Number);
    return p[0]*3600 + p[1]*60 + (p[2]||0);
  }

  // Filter log entries to only those belonging to the current session.
  // Prefers entry.iso (full ISO string) when available for cross-midnight safety;
  // falls back to HH:MM:SS string comparison for older entries.
  function toSessionEntries(entries, session) {
    if (!session || !session.start || !entries.length) return entries;
    try {
      const startIso = session.start;
      const startHms = new Date(startIso).toTimeString().slice(0, 8);
      const filtered = entries.filter(e => {
        if (e.iso) return e.iso >= startIso;
        return (e.ts || '') >= startHms;
      });
      return filtered.length > 0 ? filtered : entries;
    } catch { return entries; }
  }

  function drawGraph(entries) {
    const wrap = document.getElementById('graph-wrap');
    const svg  = document.getElementById('graph');
    if (entries.length < 2) { wrap.style.display='none'; return; }
    wrap.style.display = '';
    const W=600, H=60, P=4;
    const vals = entries.map(e => e.input_tokens);
    const maxV = Math.max(...vals), minV = Math.min(...vals), range = maxV-minV||1;
    const pts = vals.map((v,i) => {
      const x = P+(i/(vals.length-1))*(W-P*2);
      const y = P+(1-(v-minV)/range)*(H-P*2);
      return x+','+y;
    }).join(' ');
    const f0x = P, f0y = P+(1-(vals[0]-minV)/range)*(H-P*2);
    const fNx = P+(W-P*2), fNy = P+(1-(vals[vals.length-1]-minV)/range)*(H-P*2);
    const area = \`M \${f0x},\${f0y} L \${pts.split(' ').join(' L ')} L \${fNx},\${H-P} L \${P},\${H-P} Z\`;
    const pi = vals.indexOf(maxV);
    const px = P+(pi/(vals.length-1))*(W-P*2);
    const py = P+(1-(maxV-minV)/range)*(H-P*2);
    svg.innerHTML =
      '<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'+
        '<stop offset="0%" stop-color="#4ec9b0" stop-opacity="0.25"/>'+
        '<stop offset="100%" stop-color="#4ec9b0" stop-opacity="0"/>'+
      '</linearGradient></defs>'+
      '<path d="'+area+'" fill="url(#g)"/>'+
      '<polyline points="'+pts+'" fill="none" stroke="#4ec9b0" stroke-width="1.5"/>'+
      '<circle cx="'+px+'" cy="'+py+'" r="3" fill="#dcdcaa"/>';
  }

  // ── Detail panel (Levels 1 + 2 + 3) ──────────────────────────────────────────

  /**
   * Normalise secrets to [{label, line, snippet}] regardless of log version.
   * Old entries stored secrets as string[] (pattern source slices).
   */
  function normaliseSecrets(secrets) {
    if (!Array.isArray(secrets) || !secrets.length) return [];
    if (typeof secrets[0] === 'string') {
      return secrets.map((s, i) => ({ label: s, line: null, snippet: null }));
    }
    return secrets;
  }

  function buildDetailHtml(e) {
    const sections = [];
    const secrets  = normaliseSecrets(e.secrets);
    const tools    = Array.isArray(e.tools) ? e.tools : [];
    const fileToks = Array.isArray(e.file_tokens) ? e.file_tokens : [];

    // Level 1 — file token breakdown
    if (fileToks.length) {
      const maxTok = Math.max(...fileToks.map(f => f.tokens), 1);
      const rows = fileToks.slice(0, 12).map(f => {
        const pct  = Math.round((f.tokens / maxTok) * 100);
        const name = f.name.split('/').slice(-2).join('/');
        return '<div class="file-row">' +
          '<div class="file-name" title="' + escHtml(f.name) + '">' + escHtml(name) + '</div>' +
          '<div class="file-bar-wrap"><div class="file-bar-fill" style="width:' + pct + '%"></div></div>' +
          '<div class="file-tok">' + fmt(f.tokens) + 't</div>' +
          '</div>';
      }).join('');
      sections.push(
        '<div class="detail-section">' +
        '<div class="detail-title">Files (' + fileToks.length + ')</div>' +
        rows +
        '</div>'
      );
    }

    // Level 2 — secret details with line numbers
    if (secrets.length) {
      const rows = secrets.map(s =>
        '<div class="secret-row">' +
        '<span class="secret-label">⚠ ' + escHtml(s.label) + '</span>' +
        (s.line ? ' <span class="secret-line">line ' + s.line + '</span>' : '') +
        (s.snippet ? '<br><span class="secret-snip">' + escHtml(s.snippet) + '</span>' : '') +
        '</div>'
      ).join('');
      sections.push(
        '<div class="detail-section">' +
        '<div class="detail-title">Secrets (' + secrets.length + ')</div>' +
        rows +
        '</div>'
      );
    }

    // Level 3 — local tool runs
    if (tools.length) {
      const rows = tools.map(t => {
        const cmd    = (t.cmd || '').length > 70 ? t.cmd.slice(0, 70) + '…' : t.cmd;
        const meta   = 'exit ' + t.exitCode + ' · ' + fmt(t.bytes) + 'B';
        // Per-tool transform badges — only shown when a transform actually ran.
        let badges = '';
        if (t.secretsRedacted > 0) {
          const n = t.secretsRedacted;
          badges += ' <span style="color:#f48771;font-size:10px">⚠ ' + n + ' secret' + (n > 1 ? 's' : '') + ' redacted</span>';
        }
        if (t.distilled) {
          const saved = t.distillSaved > 0 ? ' −' + fmt(t.distillSaved) + 't' : '';
          badges += ' <span style="color:#dcdcaa;font-size:10px" title="' + escHtml(t.distillLabel || '') + '">✂' + saved + '</span>';
        }
        if (!badges && t.transform) {
          badges = ' <span style="color:#9cdcfe;font-size:10px">→ ' + escHtml(t.transform) + '</span>';
        }
        return '<div class="tool-row">' +
          '<span class="tool-cmd">' + escHtml(cmd) + '</span> ' +
          '<span class="tool-meta">(' + meta + ')</span>' +
          badges +
          '</div>';
      }).join('');
      sections.push(
        '<div class="detail-section">' +
        '<div class="detail-title">Local tools (' + tools.length + ')</div>' +
        rows +
        '</div>'
      );
    }

    return sections.length ? sections.join('') : null;
  }

  function escHtml(s) {
    return String(s || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function toggleDetail(tr) {
    // Collapse if already open
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {
      next.remove();
      tr.classList.remove('expanded');
      return;
    }

    let e;
    try { e = JSON.parse(tr.dataset.entry); } catch { return; }

    const html = buildDetailHtml(e);
    if (!html) return;

    tr.classList.add('expanded');
    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.innerHTML = '<td colspan="7"><div class="detail-panel">' + html + '</div></td>';
    tr.parentNode.insertBefore(detail, tr.nextSibling);
  }

  // ── Scope ─────────────────────────────────────────────────────────────────────

  let activeScope  = 'session';
  let lastPayload  = null;

  function setScope(s) {
    activeScope = s;
    document.getElementById('scope-session').classList.toggle('active', s === 'session');
    document.getElementById('scope-today').classList.toggle('active', s === 'today');
    if (lastPayload) render(lastPayload);
  }

  // Aggregate card totals from raw log entries (used for Today scope).
  // Reads pre-computed cost/savings fields — same values the proxy wrote via calcCost().
  function computeTodayTotals(entries) {
    const r = { requests: entries.length, input_tokens: 0, output_tokens: 0, cost: 0,
                cache_savings: 0, lao_cost_saved: 0, distill_cost_saved: 0,
                tools_local_count: 0, intercepted_count: 0 };
    for (const e of entries) {
      r.input_tokens        += e.input_tokens        || 0;
      r.output_tokens       += e.output_tokens       || 0;
      r.cost                += e.cost                || 0;
      r.cache_savings       += e.cache_savings       || 0;
      r.lao_cost_saved      += e.lao_cost_saved      || 0;
      r.distill_cost_saved  += e.distill_cost_saved  || 0;
      r.tools_local_count   += e.tools_local_count   || 0;
      if (e.intercepted) r.intercepted_count++;
    }
    return r;
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  function render({ session, entries }) {
    const sEntries       = toSessionEntries(entries, session);
    const isToday        = activeScope === 'today';
    const displayEntries = isToday ? entries : sEntries;
    const displayTotals  = isToday ? computeTodayTotals(entries) : session;
    const scopeLabel     = isToday ? 'Today' : 'Current session';

    const req        = displayTotals.requests           || 0;
    const tin        = displayTotals.input_tokens       || 0;
    const tout       = displayTotals.output_tokens      || 0;
    const cost       = displayTotals.cost               || 0;
    const toolsLocal = displayTotals.tools_local_count  || 0;
    const toolsMcp   = displayTotals.tools_mcp_count    || 0;
    const attempted  = displayTotals.tools_attempted    || 0;
    const ranLocal   = toolsLocal + toolsMcp;
    const cacheSaved    = displayTotals.cache_savings      || 0;
    const laoSaved      = displayTotals.lao_cost_saved     || 0;
    const distillSaved  = displayTotals.distill_cost_saved || 0;
    const payloadSaved  = laoSaved + distillSaved;
    const totalSaved    = cacheSaved + payloadSaved;
    const broaderCf     = cost + totalSaved;
    const savedPct      = broaderCf > 0.00001 ? Math.round(totalSaved / broaderCf * 100) : 0;
    const intCount   = displayTotals.intercepted_count  || 0;

    // Hero — single headline savings number
    const hero = document.getElementById('hero');
    if (totalSaved > 0.00001) {
      document.getElementById('hero-saved').textContent =
        'Saved $'+totalSaved.toFixed(4)+' this session — '+savedPct+'% off';
      document.getElementById('hero-sub').textContent =
        'Would have cost $'+broaderCf.toFixed(4)+' without Occasio';
      hero.style.display = 'block';
    } else {
      hero.style.display = 'none';
    }

    document.getElementById('c-req').textContent   = req || '—';
    document.getElementById('c-in').textContent    = req ? fmt(tin)  : '—';
    document.getElementById('c-out').textContent   = req ? fmt(tout) : '—';
    document.getElementById('c-cost').textContent  = req ? '$'+cost.toFixed(4) : '—';
    document.getElementById('c-local').textContent = ranLocal > 0 ? ranLocal : '—';
    document.getElementById('c-saved').textContent =
      attempted > 0 ? ranLocal+' of '+attempted+' ('+Math.round(ranLocal/attempted*100)+'%)' : '';
    document.getElementById('c-in-sub').textContent = req > 1 ? fmt(Math.round(tin/req))+' avg/req' : '';

    const savedParts = [];
    if (payloadSaved > 0.00001) savedParts.push('$'+payloadSaved.toFixed(4)+' payload');
    if (cacheSaved   > 0.00001) savedParts.push('$'+cacheSaved.toFixed(4)+' cache');
    document.getElementById('i-saved').textContent =
      savedParts.length ? savedParts.join(' + ') : 'none yet';

    document.getElementById('i-intercepted').textContent =
      ranLocal > 0 ? ranLocal+' tools ('+intCount+' requests)' : 'none yet';

    document.querySelector('.graph-title').textContent =
      'Input tokens per request — '+scopeLabel.toLowerCase();
    document.getElementById('c-cost-sub').textContent = '';
    document.getElementById('i-ctx').textContent  = '—';
    document.getElementById('i-proj').textContent = '—';

    if (!displayEntries.length) {
      document.getElementById('rows').innerHTML =
        '<tr><td colspan="7" class="empty">Waiting for Occasio proxy…</td></tr>';
      document.getElementById('footer').textContent = '';
      ['i-peak','i-ctx','i-proj'].forEach(id => document.getElementById(id).textContent='—');
      document.getElementById('graph-wrap').style.display='none';
      return;
    }

    const rich = enrich(displayEntries);

    // Insights
    const peak = rich.reduce((a,b) => b.input_tokens>a.input_tokens?b:a);
    document.getElementById('i-peak').textContent =
      'req #'+(rich.indexOf(peak)+1)+' — '+fmt(peak.input_tokens)+' tokens at '+peak.ts;

    const ctxRows = rich.slice(1).filter(e=>e.input_tokens>0);
    if (ctxRows.length) {
      const avg = ctxRows.reduce((s,e)=>s+(100-e.newPct),0)/ctxRows.length;
      document.getElementById('i-ctx').textContent = Math.round(avg)+'% carry-over per request';
    }

    let elapsed = 0;
    if (isToday && displayEntries.length >= 2) {
      elapsed = parseTs(displayEntries[displayEntries.length-1].ts) - parseTs(displayEntries[0].ts);
    } else if (!isToday && session.start) {
      elapsed = (Date.now() - new Date(session.start).getTime()) / 1000;
    }
    if (elapsed > 30 && cost > 0) {
      document.getElementById('i-proj').textContent = '~$'+(cost/elapsed*3600).toFixed(3)+'/hr';
      document.getElementById('c-cost-sub').textContent = '~$'+(cost/elapsed*3600).toFixed(3)+'/hr';
    }

    drawGraph(displayEntries);

    // Table rows
    const rows = [...rich].reverse().slice(0, 200);
    document.getElementById('rows').innerHTML = rows.map(e => {
      const barNew = e.newPct, barOld = 100-e.newPct;
      const ctx = '<div style="display:flex;align-items:center;gap:5px">'+
        '<div class="ctx-bar"><div class="ctx-new" style="width:'+barNew+'%"></div>'+
        '<div class="ctx-old" style="width:'+barOld+'%"></div></div>'+
        '<span style="font-size:10px;color:#888">'+e.newPct+'%</span></div>';

      const secrets = normaliseSecrets(e.secrets);
      const tools   = Array.isArray(e.tools) ? e.tools : [];
      const fileTok = Array.isArray(e.file_tokens) ? e.file_tokens : [];
      const hasDetail = secrets.length || tools.length || fileTok.length;

      // Status tag — uses event_type when present, falls back to legacy flags
      let tag;
      const evType = e.event_type;
      if (evType === 'blocked') {
        tag = '<span class="tag-secret">🛑 blocked</span>';
      } else if (secrets.length) {
        const lineInfo = secrets[0].line ? ' line '+secrets[0].line : '';
        tag = '<span class="tag-secret">⚠ ' + escHtml(secrets[0].label || 'secret') + lineInfo + '</span>';
      } else if (evType === 'local_only' || e.intercepted) {
        const toolNote = tools.length ? ' ×'+tools.length : '';
        tag = '<span class="tag-local">⚡ local' + toolNote + '</span>';
      } else if (evType === 'trimmed') {
        tag = '<span class="tag-ok">✂ cloud·trimmed</span>';
      } else if (evType === 'cloud_sent') {
        tag = '<span class="tag-ok">☁ cloud</span>';
      } else {
        tag = '<span class="tag-ok">✓ ok</span>';
      }

      // Hint when row is expandable
      const expandHint = hasDetail ? ' title="Click to expand"' : '';

      return '<tr class="data-row' + (e.intercepted ? ' intercepted' : '') + '"' +
        (hasDetail ? ' onclick="toggleDetail(this)"' : '') +
        ' data-entry="' + JSON.stringify(e).replace(/"/g,'&quot;') + '"' +
        expandHint + '>' +
        '<td>'+(e.ts||'—')+'</td>' +
        '<td style="color:#888">'+shortModel(e.model)+'</td>' +
        '<td>'+fmt(e.input_tokens)+'</td>' +
        '<td>'+fmt(e.output_tokens)+'</td>' +
        '<td>$'+(e.cost||0).toFixed(4)+'</td>' +
        '<td>'+ctx+'</td>' +
        '<td>'+tag+(hasDetail ? ' <span style="color:#555;font-size:10px">▾</span>' : '')+'</td>' +
        '</tr>';
    }).join('');

    const hiddenCount = isToday ? 0 : (entries.length - sEntries.length);
    document.getElementById('footer').textContent =
      \`\${scopeLabel} · \${rows.length} request\${rows.length===1?'':'s'}\${hiddenCount>0?' · '+hiddenCount+' earlier today not shown':''} · click row to expand · live via SSE\`;
  }

  // ── SSE connection ─────────────────────────────────────────────────────────────

  const dot    = document.getElementById('dot');
  const status = document.getElementById('status');

  function connect() {
    const es = new EventSource('/events');

    es.onopen = () => {
      dot.style.background = '#4ec9b0';
      status.textContent   = 'live';
      status.className     = 'connected';
    };

    es.onmessage = ({ data }) => {
      try { lastPayload = JSON.parse(data); render(lastPayload); } catch (err) { console.error('[Occasio]', err); }
    };

    es.onerror = () => {
      dot.style.background = '#666';
      status.textContent   = 'reconnecting…';
      status.className     = '';
      es.close();
      setTimeout(connect, 3000);
    };
  }

  connect();

  document.getElementById('clearBtn').addEventListener('click', () => {
    fetch('/api/clear', { method: 'POST' });
  });
</script>
</body>
</html>`;
}

// ── Start ──────────────────────────────────────────────────────────────────────

server.listen(DASHBOARD_PORT, '127.0.0.1', () => {
  process.stderr.write(`  dashboard: http://localhost:${DASHBOARD_PORT}\n`);
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') {
    process.stderr.write(`  [dashboard] port ${DASHBOARD_PORT} in use — skipping\n`);
  }
});

module.exports = { server };
