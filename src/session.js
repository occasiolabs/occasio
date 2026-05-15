'use strict';

/**
 * session.js — Shared session.json helpers for cross-process accounting.
 *
 * index.js owns the main session lifecycle (init, updateSession, read).
 * mcp-server.js runs in a separate process and cannot call index.js directly.
 * This module provides the single shared function that mcp-server.js needs to
 * increment tools_mcp_count without touching any other session field.
 *
 * Pattern: read-modify-write, same as updateSession() in index.js.
 * No file locking — same accepted tradeoff as the rest of the codebase.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const SESSION_FILE = path.join(os.homedir(), '.occasio', 'session.json');

/**
 * Increment tools_mcp_count in session.json by n (default 1).
 * No-ops if session.json does not exist or has no run_id (no active session).
 * Silent on any I/O error.
 */
function incrementSessionMcpCount(n = 1) {
  try {
    let s;
    try { s = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch { return; }
    if (!s || !s.run_id) return;  // no active proxy session — don't create a stale entry
    s.tools_mcp_count = (s.tools_mcp_count || 0) + n;
    fs.writeFileSync(SESSION_FILE, JSON.stringify(s));
  } catch { /* ignore */ }
}

module.exports = { SESSION_FILE, incrementSessionMcpCount };
