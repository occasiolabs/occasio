'use strict';

/** Flatten a message content block to plain text. */
function flattenContent(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map(b => (typeof b === 'string' ? b : b.text || '')).join('\n');
  return '';
}

/** Rough token estimate: ~4 chars per token (Anthropic approximation). */
function estimateTokens(text) {
  return Math.ceil((text || '').length / 4);
}

// ── Level 1: File-level token accounting ──────────────────────────────────────

/**
 * Parses messages for Read tool results and returns [{name, tokens}] sorted
 * by token count descending (max 20 files).
 *
 * Modern Claude Code sends structured tool_use / tool_result blocks:
 *   assistant: [{type:"tool_use", id:"toolu_01", name:"Read", input:{file_path:"src/foo.ts"}}]
 *   user:      [{type:"tool_result", tool_use_id:"toolu_01", content:"<file text>"}]
 *
 * We walk the full message history to build a map of
 *   tool_use_id → file_path   (from tool_use blocks where name === "Read")
 * then match tool_result blocks by tool_use_id to estimate content tokens.
 *
 * Falls back to the old `--- path ---` delimiter format for legacy sessions.
 */
function parseFileTokens(messages) {
  const fileMap = new Map();
  const msgs = messages || [];

  // Pass 1: collect Read tool_use blocks: id → file_path
  const readIdToPath = new Map();
  for (const msg of msgs) {
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (block.type === 'tool_use' && block.name === 'Read' && block.id && block.input?.file_path) {
        readIdToPath.set(block.id, String(block.input.file_path));
      }
    }
  }

  // Pass 2: match tool_result content to file_path via tool_use_id
  if (readIdToPath.size > 0) {
    for (const msg of msgs) {
      if (!Array.isArray(msg.content)) continue;
      for (const block of msg.content) {
        if (block.type !== 'tool_result' || !block.tool_use_id) continue;
        const filePath = readIdToPath.get(block.tool_use_id);
        if (!filePath) continue;
        // content can be a string or an array of content blocks
        let text = '';
        if (typeof block.content === 'string') {
          text = block.content;
        } else if (Array.isArray(block.content)) {
          text = block.content.map(b => (typeof b === 'string' ? b : b.text || '')).join('\n');
        }
        fileMap.set(filePath, (fileMap.get(filePath) || 0) + estimateTokens(text));
      }
    }
  }

  // Fallback: legacy `--- path ---` delimiter format
  if (fileMap.size === 0) {
    for (const msg of msgs) {
      const text = flattenContent(msg.content);
      const delimRe = /^---[ \t]+(\S+\.[a-zA-Z0-9]\S*)[ \t]+---\r?\n([\s\S]*?)(?=^---[ \t]+\S+\.[\w]\S*[ \t]+---|$(?![\s\S]))/gm;
      for (const m of text.matchAll(delimRe)) {
        const name = m[1].trim();
        fileMap.set(name, (fileMap.get(name) || 0) + estimateTokens(m[2]));
      }
    }
  }

  return [...fileMap.entries()]
    .map(([name, tokens]) => ({ name, tokens }))
    .sort((a, b) => b.tokens - a.tokens)
    .slice(0, 20);
}

// ── Level 2: Secret scanning with line context ────────────────────────────────

const SECRET_PATTERNS = [
  // High-confidence structural patterns — match regardless of surrounding context
  { re: /sk-ant-api03-[A-Za-z0-9_-]{40,}/,                            label: 'anthropic-key'  },
  { re: /ghp_[A-Za-z0-9]{36}/,                                        label: 'github-pat'     },
  { re: /AKIA[0-9A-Z]{16}/,                                           label: 'aws-access-key' },
  { re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/,                 label: 'private-key'    },
  { re: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@/,                  label: 'db-url'         },
  // Generic patterns — require direct assignment (key=value) to reduce false positives.
  // Original broad regexes matched mid-word (apiKeyValidator) and indirect context
  // (TOKEN anywhere then = anywhere on same line). These tightened forms require the
  // keyword immediately before the separator with no intervening tokens.
  { re: /api[_-]?key\s*[:=]\s*['"]?\S{16,}/i,                        label: 'api-key'        },
  { re: /password\s*[:=]\s*['"]?\S{8,}/i,                            label: 'password'       },
  { re: /(?:access|bearer|auth)[_-]?token\s*[:=]\s*['"]?\S{16,}/i,   label: 'token'          },
];

/** Keep line structure, mask alphanumeric chars for safe logging. */
function redactLine(line) {
  const truncated = line.slice(0, 80) + (line.length > 80 ? '…' : '');
  return truncated.replace(/[A-Za-z0-9]/g, '*');
}

/**
 * Scans text line-by-line for known secret patterns plus any caller-supplied extras.
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {Array<{label:string, regex:RegExp}>} [opts.extraPatterns]  Custom compiled patterns
 * Returns [{label, line, snippet}] — deduplicated by pattern+line.
 */
function scanSecrets(text, opts) {
  const extra  = (opts && Array.isArray(opts.extraPatterns)) ? opts.extraPatterns : [];
  const patterns = extra.length
    ? SECRET_PATTERNS.concat(extra.map(p => ({ re: p.regex, label: p.label })))
    : SECRET_PATTERNS;

  const lines = text.split('\n');
  const hits  = [];
  const seen  = new Set();

  for (let i = 0; i < lines.length; i++) {
    for (const { re, label } of patterns) {
      if (re.test(lines[i])) {
        const key = `${label}:${i}`;
        if (!seen.has(key)) {
          seen.add(key);
          hits.push({ label, line: i + 1, snippet: redactLine(lines[i]) });
        }
        break;
      }
    }
  }

  return hits;
}

/**
 * Replace matched secret patterns in text with [REDACTED:label] tokens.
 * Scan runs before replacement so line numbers in hits are accurate.
 * Returns the redacted string (input is not mutated).
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {Array<{label:string, regex:RegExp}>} [opts.extraPatterns]
 */
function redactSecrets(text, opts) {
  if (typeof text !== 'string') return text;
  const extra  = (opts && Array.isArray(opts.extraPatterns)) ? opts.extraPatterns : [];
  const patterns = extra.length
    ? SECRET_PATTERNS.concat(extra.map(p => ({ re: p.regex, label: p.label })))
    : SECRET_PATTERNS;

  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const { re, label } of patterns) {
      if (re.test(lines[i])) {
        lines[i] = lines[i].replace(re, `[REDACTED:${label}]`);
        break;
      }
    }
  }
  return lines.join('\n');
}

module.exports = { flattenContent, estimateTokens, parseFileTokens, SECRET_PATTERNS, redactLine, scanSecrets, redactSecrets };
