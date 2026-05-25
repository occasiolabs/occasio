'use strict';

/**
 * eyes/index.js — `occasio eyes` entrypoint.
 *
 * Default mode (content): show what the agent is actually sending to the
 * cloud — system prompt, messages, tool_results, with line numbers and
 * redaction highlighting. Reads from ~/.occasio/eyes/payload-NNNN.json
 * which the proxy writes when started with `occasio claude --eyes`.
 *
 * Alternate modes:
 *   --tools                  classic tool-call dashboard (tails pipeline-events.jsonl)
 *   --demo                   synthetic data (works for both content and tools)
 *   --replay <run|last>      replay tool-mode rows from history (--tools only)
 *
 * Common flags:
 *   --no-color   --no-alt   --frames N   --file <path>   --help
 */

const fs   = require('fs');
const path = require('path');

const { tail, readAll, DEFAULT_FILE } = require('./events');
const { initialState, reduce }        = require('./state');
const { render: renderTools, HIDE_CURSOR, SHOW_CURSOR, ALT_ON, ALT_OFF } = require('./render');
const { SCRIPT }                      = require('./demo-script');
const { render: renderContent }       = require('./content-render');
const { PAYLOADS: DEMO_PAYLOADS }     = require('./demo-content');
const capture                         = require('./capture');

function parseArgs(argv) {
  const out = {
    mode: 'web',               // 'web' (default browser UI) | 'tui' | 'tools'
    demo: false,
    replay: null, speed: 1,
    sinceStart: false,
    color: true, alt: true,
    frames: 0,
    file: DEFAULT_FILE,        // for --tools mode
    eyesDir: capture.EYES_DIR, // for content/web modes
    scroll: 0,
    port: 0,                   // 0 = let server pick its default
    noOpen: false,             // --no-open: don't auto-launch browser
    sanitize: false,           // --sanitize: scrub identity from display output
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--tui')          out.mode = 'tui';
    else if (a === '--web')     out.mode = 'web';
    else if (a === '--tools')   out.mode = 'tools';
    else if (a === '--content') out.mode = 'tui';   // backwards-compat alias
    else if (a === '--demo')    out.demo = true;
    else if (a === '--replay')  out.replay = argv[++i] || 'last';
    else if (a === '--speed')   out.speed = Math.max(0.1, parseFloat(argv[++i]) || 1);
    else if (a === '--since-start') out.sinceStart = true;
    else if (a === '--no-color')    out.color = false;
    else if (a === '--no-alt')      out.alt = false;
    else if (a === '--frames')      out.frames = Math.max(1, parseInt(argv[++i], 10) || 1);
    else if (a === '--file')        out.file = argv[++i];
    else if (a === '--eyes-dir')    out.eyesDir = argv[++i];
    else if (a === '--port')        out.port = parseInt(argv[++i], 10) || 0;
    else if (a === '--no-open')     out.noOpen = true;
    else if (a === '--sanitize')    out.sanitize = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function printHelp() {
  process.stdout.write(`
occasio eyes — see what the agent is sending to the cloud

Default: opens a browser UI at http://127.0.0.1:3002 with sidebar of all
captured exchanges, request/response/raw tabs, and live updates. Needs the
proxy to be capturing — start with:
    occasio claude --eyes

Usage:
  occasio eyes                latest outbounds in browser (default)
  occasio eyes --demo         synthetic outbounds, no claude needed
  occasio eyes --tui          terminal UI instead of browser
  occasio eyes --tools        classic tool-call dashboard (terminal)
  occasio eyes --no-open      start server but don't open browser

Flags (web mode):
  --port N          override default port (3002)
  --no-open         don't auto-launch browser
  --eyes-dir <p>    payload directory override

Flags (tui mode):
  --no-color   --no-alt   --frames N

Privacy:
  --sanitize        replace your home path, OS username, git identity, email
                    and hostname with deterministic pseudonyms in the display.
                    Disk contents under ~/.occasio/eyes/ are unchanged — this
                    is a display filter, safe for screencasts and demos.

  What --sanitize covers:
    - Home directory (any path starting with $HOME / %USERPROFILE%)
    - OS username (from os.userInfo() and $USER/$USERNAME/$LOGNAME)
    - git config user.email and user.name
    - hostname

  What it does NOT cover — review before sharing:
    - Project paths outside your home dir (e.g. D:\\Work\\Acme on Windows)
    - Git remote URLs in tool outputs (github.com:org/repo leaks the org)
    - File contents themselves — your name in a comment, commit message,
      or README is not auto-detected
    - The Claude Code TUI banner ("Welcome back X", organization line) —
      that prints before any HTTP traffic and bypasses Eyes entirely
    - Timezone hints embedded in timestamps

  For full coverage on a public screencast: crop the banner manually and
  scan the captured payloads with your eyes before publishing.
`);
}

function termWidth()  { return (process.stdout && process.stdout.columns) || 80; }
function termHeight() { return (process.stdout && process.stdout.rows)    || 28; }

function setupTty(opts) {
  if (!process.stdout.isTTY) return { teardown() {} };
  const out = process.stdout;
  if (opts.alt) out.write(ALT_ON);
  out.write(HIDE_CURSOR);
  let rawOn = false;
  if (process.stdin.isTTY && process.stdin.setRawMode) {
    try { process.stdin.setRawMode(true); rawOn = true; } catch { /* ignore */ }
  }
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  return {
    teardown() {
      try { out.write(SHOW_CURSOR); } catch { /* ignore */ }
      if (opts.alt) { try { out.write(ALT_OFF); } catch { /* ignore */ } }
      if (rawOn) { try { process.stdin.setRawMode(false); } catch { /* ignore */ } }
      try { process.stdin.pause(); } catch { /* ignore */ }
    },
  };
}

// ── Tools mode (existing dashboard) ─────────────────────────────────────────

function pickRunRows(file, runId) {
  const all = readAll(file);
  if (!all.length) return [];
  if (!runId || runId === 'last') {
    const lastRun = [...all].reverse().find(r => r.run_id)?.run_id;
    return lastRun ? all.filter(r => r.run_id === lastRun) : all;
  }
  return all.filter(r => r.run_id === runId);
}

function eventsFromReplay(rows, speed) {
  const events = [];
  let prevMs = null;
  for (const r of rows) {
    const t = Date.parse(r.ts || '');
    let delta = 0;
    if (Number.isFinite(t)) {
      if (prevMs != null) delta = Math.max(0, Math.min(5000, t - prevMs));
      prevMs = t;
    }
    events.push({ delayMs: delta / speed, row: r });
  }
  if (events.length) events[0].delayMs = Math.max(events[0].delayMs, 200);
  return events;
}

function eventsFromDemo() {
  return SCRIPT.map(s => ({ delayMs: s.delayMs, row: s.row }));
}

function runToolsMode(opts) {
  let state = initialState();
  const start = Date.now();
  const tickNow = () => Date.now() - start;
  const tty = setupTty(opts);
  let frameCount = 0, stopped = false, paused = false;

  function paint() {
    if (stopped) return;
    const frame = renderTools(state, tickNow(), { width: termWidth(), color: opts.color, paused });
    try { process.stdout.write(frame); } catch { /* ignore */ }
    frameCount++;
    if (opts.frames && frameCount >= opts.frames) shutdown(0);
  }
  function onKey(buf) {
    const s = buf.toString();
    if (s === '' || s === 'q' || s === 'Q') return shutdown(0);
    if (s === ' ') paused = !paused;
  }
  process.stdin.on('data', onKey);

  let tailer = null;
  const scheduled = [];

  function shutdown(code) {
    if (stopped) return;
    stopped = true;
    clearInterval(renderTimer);
    if (tailer && tailer.stop) tailer.stop();
    for (const t of scheduled) clearTimeout(t);
    tty.teardown();
    process.exit(code);
  }
  process.on('SIGINT',  () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));

  function schedule(events) {
    let acc = 0;
    for (const ev of events) {
      acc += ev.delayMs || 0;
      scheduled.push(setTimeout(() => { if (!paused) state = reduce(state, ev.row, tickNow()); }, acc));
    }
    if (opts.demo) {
      scheduled.push(setTimeout(() => { if (!stopped) { state = initialState(); schedule(eventsFromDemo()); } }, acc + 1500));
    }
  }

  if (opts.demo) schedule(eventsFromDemo());
  else if (opts.replay) {
    const rows = pickRunRows(opts.file, opts.replay);
    if (!rows.length) { tty.teardown(); process.stderr.write(`No events found for run ${opts.replay}\n`); return 1; }
    schedule(eventsFromReplay(rows, opts.speed));
  } else {
    tailer = tail(opts.file, (row) => { if (!paused) state = reduce(state, row, tickNow()); }, { fromStart: opts.sinceStart });
  }

  paint();
  const renderTimer = setInterval(paint, 100);
  return null;
}

// ── Content mode (NEW headline view) ────────────────────────────────────────

function listPayloadFiles(dir) {
  try {
    return fs.readdirSync(dir)
      .filter(n => n.startsWith('payload-') && n.endsWith('.json'))
      .sort();
  } catch { return []; }
}

function readPayloadFile(dir, name) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
  catch { return null; }
}

function runContentMode(opts) {
  // In-memory payload list. demo: hard-coded. Otherwise: tail eyesDir.
  let payloads = [];
  let index = 0;     // which payload we're viewing
  let scroll = 0;
  let pinned = false; // when user navigates, stop auto-jumping to newest
  let showSystem = false;
  let showReminders = false;
  let showRaw = false;
  let showAllTurns = false;   // default: collapse older turns, only latest expanded
  let toast = '';     // brief status line, e.g. "copied 4.2 KB to clipboard"
  let toastUntil = 0;
  const sanitizer = opts.sanitize ? require('./sanitize').createSession() : null;

  if (opts.demo) {
    payloads = DEMO_PAYLOADS.slice();
  } else {
    // Initial load
    for (const f of listPayloadFiles(opts.eyesDir)) {
      const p = readPayloadFile(opts.eyesDir, f);
      if (p) payloads.push(p);
    }
    if (payloads.length) index = payloads.length - 1;
  }

  const tty = setupTty(opts);
  let stopped = false, frameCount = 0, paused = false;

  function currentPayload() {
    if (!payloads.length) return null;
    const p = payloads[index];
    return sanitizer ? sanitizer.payload(p) : p;
  }

  function paint() {
    if (stopped) return;
    const p = currentPayload();
    const frame = renderContent(p, {
      width: termWidth(), height: termHeight(), color: opts.color,
      scroll, total: payloads.length, index: index + 1, paused,
      showSystem, showReminders, showRaw, showAllTurns,
      toast: Date.now() < toastUntil ? toast : '',
    });
    try { process.stdout.write(frame); } catch { /* ignore */ }
    frameCount++;
    if (opts.frames && frameCount >= opts.frames) shutdown(0);
  }

  function setToast(t, ms) {
    toast = t;
    toastUntil = Date.now() + (ms || 1500);
  }

  function onKey(buf) {
    const s = buf.toString();
    if (s === '' || s === 'q' || s === 'Q') return shutdown(0);
    // Up/Down — fine scroll
    if (s === '\x1b[A') { scroll = Math.max(0, scroll - 3); return; }
    if (s === '\x1b[B') { scroll = scroll + 3; return; }
    if (s === 'k')      { scroll = Math.max(0, scroll - 5); return; }
    if (s === 'j')      { scroll = scroll + 5; return; }
    if (s === '\x1b[5~' || s === 'u') { scroll = Math.max(0, scroll - 15); return; } // PgUp
    if (s === '\x1b[6~' || s === 'd') { scroll = scroll + 15; return; }                // PgDn
    // Left/Right — prev/next outbound
    if (s === '\x1b[D' || s === 'h') {
      if (index > 0) { index--; scroll = 0; pinned = true; }
      return;
    }
    if (s === '\x1b[C' || s === 'l') {
      if (index < payloads.length - 1) { index++; scroll = 0; pinned = true; }
      else pinned = false;
      return;
    }
    if (s === '\x1b[H' || s === 'g') { index = 0; scroll = 0; pinned = true; return; }
    if (s === '\x1b[F' || s === 'G') { index = Math.max(0, payloads.length - 1); scroll = 0; pinned = false; return; }
    if (s === 's' || s === 'S')      { showSystem = !showSystem; return; }
    if (s === 'r')                   { showReminders = !showReminders; return; }
    if (s === 'R')                   { showRaw = !showRaw; return; }
    if (s === 'a' || s === 'A')      { showAllTurns = !showAllTurns; return; }
    if (s === 'c' || s === 'C')      {
      const p = currentPayload();
      if (!p) return;
      const { dumpText, copyToClipboard } = require('./dump');
      const text = dumpText(p);
      copyToClipboard(text).then(r => {
        setToast(r.ok ? `✓ copied ${text.length} chars via ${r.via}` : `✗ clipboard failed (${r.via} missing?)`, 2000);
      });
      setToast('copying…', 800);
      return;
    }
    if (s === ' ') paused = !paused;
  }
  process.stdin.on('data', onKey);

  function shutdown(code) {
    if (stopped) return;
    stopped = true;
    clearInterval(renderTimer);
    clearInterval(pollTimer);
    clearInterval(demoTimer);
    tty.teardown();
    process.exit(code);
  }
  process.on('SIGINT',  () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));

  // Demo mode: auto-rotate every 4s so the screen always shows new content
  // (perfect for marketing GIFs). Manual arrow keys still work and pause auto.
  const demoTimer = opts.demo ? setInterval(() => {
    if (paused || pinned || stopped) return;
    if (!payloads.length) return;
    index = (index + 1) % payloads.length;
    scroll = 0;
  }, 4000) : { unref(){} };

  // Poll the eyes dir for new payloads — 500 ms is plenty for a TUI.
  const pollTimer = opts.demo ? { unref(){} } : setInterval(() => {
    if (paused) return;
    const files = listPayloadFiles(opts.eyesDir);
    if (files.length === payloads.length) return;
    // Re-read full list (capture prunes oldest, so seq numbers stay sorted).
    const fresh = [];
    for (const f of files) { const p = readPayloadFile(opts.eyesDir, f); if (p) fresh.push(p); }
    const wasAtNewest = !pinned || index === payloads.length - 1;
    payloads = fresh;
    if (wasAtNewest) { index = Math.max(0, payloads.length - 1); scroll = 0; }
    else { index = Math.min(index, payloads.length - 1); }
  }, 500);

  paint();
  const renderTimer = setInterval(paint, 60);
  return null;
}

function runWebMode(opts) {
  const { createServer, openBrowser, DEFAULT_PORT } = require('./server');
  const srv = createServer({ demo: opts.demo, eyesDir: opts.eyesDir, sanitize: opts.sanitize });
  const port = opts.port || DEFAULT_PORT;
  srv.listen(port, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${port}`;
    process.stderr.write(`\n  ⚡ Agent Eyes — ${url}\n`);
    if (opts.demo)     process.stderr.write(`     mode: demo (synthetic data, no proxy needed)\n`);
    else               process.stderr.write(`     watching: ${opts.eyesDir}\n`);
    if (opts.sanitize) process.stderr.write(`     \x1b[36msanitized: identity scrubbed in display\x1b[0m\n`);
    process.stderr.write(`     Ctrl-C to stop\n\n`);
    if (!opts.noOpen) openBrowser(url);
  });
  // Keep alive until SIGINT/SIGTERM. Don't process.exit here — the HTTP
  // server keeps the event loop alive on its own.
  process.on('SIGINT',  () => { srv.close(() => process.exit(0)); });
  process.on('SIGTERM', () => { srv.close(() => process.exit(0)); });
  return null;
}

function run(argv) {
  const opts = parseArgs(argv || []);
  if (opts.help) { printHelp(); return 0; }
  if (opts.mode === 'tools') return runToolsMode(opts);
  if (opts.mode === 'tui')   return runContentMode(opts);
  return runWebMode(opts);
}

module.exports = {
  run, parseArgs, eventsFromReplay, eventsFromDemo, pickRunRows,
  listPayloadFiles, readPayloadFile,
};
