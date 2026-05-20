'use strict';

/**
 * eyes/events.js — JSONL tail reader for occasio eyes.
 *
 * Watches a file (default ~/.occasio/pipeline-events.jsonl) and emits each
 * newly appended row as a parsed object. Uses fs.watchFile poll-tail rather
 * than fs.watch because the auditor writes via appendFileSync from possibly
 * multiple processes — poll is what dashboard.js already does for session.json.
 *
 * Partial trailing lines are buffered, mirroring src/audit/jsonl-auditor.js's
 * own crash-safety approach: never parse until a newline arrives.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const DEFAULT_FILE = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');

function tail(filePath, onRow, opts) {
  opts = opts || {};
  const interval = opts.interval || 250;
  const fromStart = !!opts.fromStart;

  let offset = 0;
  let buf = '';
  let stopped = false;

  if (fs.existsSync(filePath)) {
    try {
      const st = fs.statSync(filePath);
      offset = fromStart ? 0 : st.size;
    } catch { /* file vanished between exists & stat — start at 0 */ }
  }

  function drain() {
    if (stopped) return;
    let st;
    try { st = fs.statSync(filePath); }
    catch { return; }
    if (st.size < offset) {
      // file was truncated/rotated — restart from 0
      offset = 0;
      buf = '';
    }
    if (st.size === offset) return;
    let fd;
    try { fd = fs.openSync(filePath, 'r'); }
    catch { return; }
    try {
      const len = st.size - offset;
      const b = Buffer.allocUnsafe(len);
      fs.readSync(fd, b, 0, len, offset);
      buf += b.toString('utf8');
      offset = st.size;
    } finally {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let row;
      try { row = JSON.parse(line); }
      catch { continue; }
      try { onRow(row); }
      catch { /* renderer errors must not kill the tailer */ }
    }
  }

  // Initial drain (catches anything that arrived between stat and watchFile).
  drain();
  fs.watchFile(filePath, { interval, persistent: true }, drain);

  return {
    stop() {
      if (stopped) return;
      stopped = true;
      fs.unwatchFile(filePath, drain);
    },
    // Exposed for tests + manual one-shot drains.
    drain,
  };
}

/**
 * readAll(filePath) — eager read of every parsable row. Used by replay mode
 * and by tests that want a deterministic snapshot. Returns [] if missing.
 */
function readAll(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const text = fs.readFileSync(filePath, 'utf8');
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { rows.push(JSON.parse(line)); } catch { /* skip */ }
  }
  return rows;
}

module.exports = { tail, readAll, DEFAULT_FILE };
