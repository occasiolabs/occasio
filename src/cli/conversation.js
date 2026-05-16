'use strict';

/**
 * conversation.js — read the last conversation snippet from Claude Code's
 * own per-project session files at ~/.claude/projects/<cwd-encoded>/<id>.jsonl
 *
 * Why: pipeline-events.jsonl captures tool calls, but the actual prompts and
 * model replies live in Claude Code's session files. Those already exist on
 * disk — we don't need to add a new capture path in the proxy.
 *
 * Read-only, no I/O outside ~/.claude. Returns null on any miss (no claude
 * dir, no project dir, no session file, malformed JSONL, etc.) — caller
 * degrades gracefully.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// Claude Code encodes the cwd by replacing every path separator (':', '\', '/')
// with a single '-'. So `C:\Users\leona\foo` → `C--Users-leona-foo` because
// `C` + `:` (-) + `\` (-) + `Users`… yields two dashes between C and Users.
function encodeCwd(cwd) {
  return cwd.replace(/[:\\/]/g, '-');
}

function findProjectDir(cwd) {
  const root = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(root)) return null;
  const encoded = encodeCwd(cwd);
  const candidate = path.join(root, encoded);
  if (fs.existsSync(candidate)) return candidate;
  // Case-insensitive fallback (Windows drive letters): scan once.
  try {
    const entries = fs.readdirSync(root);
    const hit = entries.find(n => n.toLowerCase() === encoded.toLowerCase());
    return hit ? path.join(root, hit) : null;
  } catch { return null; }
}

function listSessionFiles(projectDir) {
  if (!projectDir) return [];
  try {
    return fs.readdirSync(projectDir)
      .filter(n => n.endsWith('.jsonl') && /^[0-9a-f-]{36}\.jsonl$/i.test(n))
      .map(n => {
        const full = path.join(projectDir, n);
        let mtime = 0;
        try { mtime = fs.statSync(full).mtimeMs; } catch { /* */ }
        return { name: n, full, mtime };
      })
      .sort((a, b) => b.mtime - a.mtime);
  } catch { return []; }
}

// Pull a string preview out of message.content, which Claude Code stores as
// either a raw string or an array of typed blocks.
function previewText(content, max = 240) {
  if (!content) return '';
  if (typeof content === 'string') return content.slice(0, max).trim();
  if (!Array.isArray(content)) return '';
  for (const block of content) {
    if (!block) continue;
    if (typeof block === 'string') return block.slice(0, max).trim();
    if (block.type === 'text' && typeof block.text === 'string') {
      return block.text.slice(0, max).trim();
    }
  }
  return '';
}

function loadConversation(sessionFile) {
  let text;
  try { text = fs.readFileSync(sessionFile, 'utf8'); }
  catch { return null; }

  let firstUser = null, lastUser = null, lastAssistant = null;
  let firstTs = null, lastTs = null;

  for (const line of text.split('\n')) {
    if (!line) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (row.type !== 'user' && row.type !== 'assistant') continue;
    const msg = row.message;
    if (!msg) continue;
    const preview = previewText(msg.content);
    if (!preview) continue;
    const ts = row.timestamp || null;
    if (ts && !firstTs) firstTs = ts;
    if (ts) lastTs = ts;
    if (row.type === 'user') {
      if (!firstUser) firstUser = preview;
      lastUser = preview;
    } else if (row.type === 'assistant') {
      lastAssistant = preview;
    }
  }

  if (!firstUser && !lastUser && !lastAssistant) return null;
  return { firstUser, lastUser, lastAssistant, firstTs, lastTs };
}

/**
 * Best-effort: find and read the most recent Claude Code conversation for
 * the given cwd. Returns null if none found.
 */
function readLastConversation(cwd) {
  const dir = findProjectDir(cwd);
  if (!dir) return null;
  const sessions = listSessionFiles(dir);
  if (!sessions.length) return null;
  // Try the newest first; fall through to older if newest is empty.
  for (const s of sessions.slice(0, 3)) {
    const conv = loadConversation(s.full);
    if (conv) return { ...conv, sessionFile: s.full };
  }
  return null;
}

module.exports = { readLastConversation, encodeCwd, findProjectDir, listSessionFiles, loadConversation };
