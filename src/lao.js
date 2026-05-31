'use strict';

/**
 * lao.js — LAO context optimization for the Occasio proxy.
 *
 * Before a request goes to Anthropic, optimizeContext() scores every file
 * already loaded into the conversation (via Read / cat tool_results) against
 * the current task using a Python TF-IDF scorer (lao_prep.py).
 * Tool-results for low-relevance files are replaced with a one-line
 * placeholder, keeping conversation structure intact while saving tokens.
 *
 * Only activates when total context exceeds MIN_TOK (default 20 000).
 * Scorer output is cached for 30 s to avoid repeated subprocess spawning.
 */

const { spawn } = require('child_process');
const path = require('path');
const { estimateTokens } = require('./analyzer');

const LAO_PY    = path.join(__dirname, 'lao_prep.py');
const MIN_TOK   = 20_000;
const TRIM_FRAC = 0.10;   // drop files scoring < 10 % of top score
const CACHE_TTL = 30_000;
const PLACEHOLDER = '[content trimmed by Occasio LAO — low relevance to current task]';

let _cache = { key: '', result: [], ts: 0 };

// ── Python subprocess ──────────────────────────────────────────────────────────

// Try one interpreter. Resolves with the parsed scores (or [] on bad/slow
// output); REJECTS only when the binary itself is missing (spawn 'error',
// e.g. ENOENT) so the caller can fall back to the next candidate.
function trySpawnScore(cmd, task, repoPath) {
  return new Promise((resolve, reject) => {
    const py = spawn(cmd, [LAO_PY, task.slice(0, 500), repoPath], {
      windowsHide: true,
    });
    let out = '';
    let settled = false;
    const timer = setTimeout(() => { settled = true; py.kill(); resolve([]); }, 8_000);
    py.stdout.on('data', d => { out += d.toString(); });
    py.on('close', () => {
      if (settled) return;
      clearTimeout(timer);
      try { resolve(JSON.parse(out)); }
      catch { resolve([]); }
    });
    py.on('error', err => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      reject(err);   // binary not found — caller tries the next candidate
    });
  });
}

async function scorePaths(task, repoPath) {
  const key = `${task.slice(0, 120)}|${repoPath}`;
  if (key === _cache.key && Date.now() - _cache.ts < CACHE_TTL) {
    return _cache.result;
  }
  // 'python' first (canonical on Windows), then 'python3' (canonical on
  // macOS / modern Linux, where bare 'python' usually does not exist).
  for (const cmd of ['python', 'python3']) {
    try {
      const result = await trySpawnScore(cmd, task, repoPath);
      _cache = { key, result, ts: Date.now() };
      return result;
    } catch { /* binary missing — try the next candidate */ }
  }
  return [];
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function contextTokens(messages) {
  let total = 0;
  for (const m of messages) {
    if (typeof m.content === 'string') { total += estimateTokens(m.content); continue; }
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content) {
      const t = b.text ?? (typeof b.content === 'string' ? b.content : '') ?? '';
      total += estimateTokens(t);
    }
  }
  return total;
}

function extractTask(messages) {
  return [...messages]
    .reverse()
    .filter(m => m.role === 'user')
    .slice(0, 3)
    .map(m =>
      typeof m.content === 'string' ? m.content :
      Array.isArray(m.content)
        ? m.content.filter(b => b.type === 'text').map(b => b.text || '').join(' ')
        : ''
    )
    .join(' ');
}

/**
 * Build a map of tool_use_id → normalised file path from all assistant messages.
 * Handles: Claude Code Read tool (file_path / path input), MCP read_file (path),
 * and Bash cat/head/tail calls (command input).
 */
function buildToolIdPathMap(messages) {
  const map = new Map();
  for (const msg of messages) {
    if (msg.role !== 'assistant') continue;
    const content = Array.isArray(msg.content) ? msg.content : [];
    for (const block of content) {
      if (block.type !== 'tool_use' || !block.id) continue;
      const inp = block.input || {};
      // Direct file path fields
      const fp = inp.file_path || inp.path || null;
      if (fp) { map.set(block.id, fp.replace(/\\/g, '/')); continue; }
      // Bash: cat/head/tail/bat/type <file>
      if (block.name === 'Bash' && inp.command) {
        const m = inp.command.match(
          /^(?:cat|bat|head|tail|type|Get-Content)\s+(?:-\S+\s+)*(['"]?)(.+?)\1\s*$/i
        );
        if (m) map.set(block.id, m[2].trim().replace(/\\/g, '/'));
      }
    }
  }
  return map;
}

function toolResultText(block) {
  if (typeof block.content === 'string') return block.content;
  if (Array.isArray(block.content)) {
    return block.content.map(b => (typeof b === 'string' ? b : b.text || '')).join('\n');
  }
  return '';
}

// ── Main export ────────────────────────────────────────────────────────────────

/**
 * Trim low-relevance file tool_results from an Anthropic request body.
 *
 * Skips (returns unchanged) if:
 *   - total context < MIN_TOK tokens
 *   - Python scorer returns no results or scores all zero
 *   - no file path could be matched for a tool_result
 *
 * @param {object} reqBody  Parsed request body (has .messages array)
 * @param {string} cwd      Repo root for the scorer
 * @returns {Promise<{ messages: Array, tokensSaved: number, filesDropped: string[] }>}
 */
async function optimizeContext(reqBody, cwd) {
  const messages = reqBody.messages || [];
  const noChange = { messages, tokensSaved: 0, filesDropped: [] };

  if (contextTokens(messages) < MIN_TOK) return noChange;

  const task = extractTask(messages).trim();
  if (!task) return noChange;

  const scored = await scorePaths(task, cwd);
  if (!scored.length) return noChange;

  const maxScore = scored[0].score;
  if (maxScore <= 0) return noChange;

  const threshold = maxScore * TRIM_FRAC;
  const relevance = new Map(scored.map(s => [s.path, s.score]));
  const toolIdPath = buildToolIdPathMap(messages);

  let tokensSaved = 0;
  const filesDropped = [];

  const trimmed = messages.map(msg => {
    if (msg.role !== 'user' || !Array.isArray(msg.content)) return msg;

    let changed = false;
    const newContent = msg.content.map(block => {
      if (block.type !== 'tool_result') return block;

      const filePath = toolIdPath.get(block.tool_use_id);
      if (!filePath) return block;

      const rel = filePath.replace(/\\/g, '/');
      const score = relevance.get(rel)
        ?? relevance.get(path.posix.basename(rel))
        ?? maxScore;  // unknown → keep

      if (score >= threshold) return block;

      const text = toolResultText(block);
      tokensSaved += estimateTokens(text);
      filesDropped.push(path.basename(filePath));
      changed = true;
      return { ...block, content: PLACEHOLDER };
    });

    return changed ? { ...msg, content: newContent } : msg;
  });

  return { messages: trimmed, tokensSaved, filesDropped };
}

module.exports = { optimizeContext, contextTokens, buildToolIdPathMap, extractTask };
