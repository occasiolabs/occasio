'use strict';

/**
 * eyes/content-render.js — TUI renderer for "what the agent is sending now".
 *
 * Pure: (payload, opts) → ANSI string. opts.scroll selects which visible
 * window of the body to show; opts.width is terminal width.
 */

const ESC = '\x1b[';
// HOME = move cursor to (0,0) without erasing the screen. Combined with a
// trailing ESC[J (clear-from-cursor-down) per frame, this redraws in place
// without poisoning the terminal's scrollback. Replaces the previous full
// screen-clear (ESC[2J) which polluted conhost scrollback on Windows.
const HOME = ESC + 'H';
const CLEAR_TO_END = ESC + 'J';

function paint(code) { return s => `${ESC}${code}m${s}${ESC}0m`; }
const C = {
  reset: ESC + '0m',
  dim:   paint('2'),
  bold:  paint('1'),
  red:   paint('31'),
  green: paint('32'),
  yellow:paint('33'),
  blue:  paint('34'),
  cyan:  paint('36'),
  mag:   paint('35'),
  white: paint('97'),
  bgYellow: paint('43;30'),
};
function plain(s) { return s; }
function pickColor(useColor) {
  if (useColor) return C;
  const np = { reset: '' };
  for (const k of Object.keys(C)) np[k] = typeof C[k] === 'function' ? plain : '';
  return np;
}

function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024*1024)).toFixed(2) + ' MB';
}

function fmtTime(ts) {
  const m = String(ts || '').match(/T(\d\d):(\d\d):(\d\d)/);
  return m ? `${m[1]}:${m[2]}:${m[3]}` : '--:--:--';
}

function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return String(s || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function shortPath(p, max) {
  if (!p) return '(no path)';
  p = String(p);
  if (p.length <= max) return p;
  return '…' + p.slice(p.length - (max - 1));
}

/** Detect a source-file path inside tool_use input — best effort */
function inputPath(input) {
  if (!input || typeof input !== 'object') return null;
  return input.path || input.file_path || input.pattern || input.command || null;
}

/**
 * Render the body of an outbound payload as a flat list of display lines.
 * Each line is one logical row. The caller windows by opts.scroll.
 *
 * Pairs each `tool_result` with the preceding `tool_use` (matched by id)
 * across the messages array, so the reader sees "Read src/auth.js → here's
 * what came back" — i.e. what the agent then sent BACK to the model.
 */
// system-reminder blocks are wrapped in <system-reminder>...</system-reminder>
// inside user-text. Extract them so the reader can collapse them separately.
const SR_RE = /<system-reminder>([\s\S]*?)<\/system-reminder>/g;
function splitReminders(text) {
  if (typeof text !== 'string' || !text) return { main: text || '', reminders: [] };
  const reminders = [];
  const main = text.replace(SR_RE, (_m, body) => { reminders.push(body.trim()); return ''; }).trim();
  return { main, reminders };
}

/**
 * Group messages into "turns". A turn starts on a user message that has any
 * non-tool_result text block (i.e. an actual prompt, not just tool results
 * coming back). The first user prompt opens turn 1; subsequent text-bearing
 * user messages open turn 2, 3, … Each turn carries the messages that
 * followed it until the next turn-opener.
 */
function groupTurns(messages) {
  if (!Array.isArray(messages) || !messages.length) return [];
  const turns = [];
  for (const m of messages) {
    const isUser = m.role === 'user';
    const hasUserText = isUser && Array.isArray(m.blocks) &&
      m.blocks.some(b => b.kind === 'text' && b.text && b.text.trim());
    if (hasUserText || turns.length === 0) {
      const firstText = (m.blocks || []).find(b => b.kind === 'text' && b.text && b.text.trim());
      turns.push({
        prompt: firstText ? firstText.text.trim() : '(no prompt)',
        messages: [m],
      });
    } else {
      turns[turns.length - 1].messages.push(m);
    }
  }
  return turns;
}

function buildBodyLines(payload, c, innerWidth, opts) {
  opts = opts || {};
  const showSystem    = !!opts.showSystem;
  const showReminders = !!opts.showReminders;
  const showAllTurns  = !!opts.showAllTurns;
  const lines = [];

  // ── system ────────────────────────────────────────────────────────────────
  if (payload.system && payload.system.text) {
    const head = showSystem ? '▼' : '▶';
    lines.push(c.dim(`── ${head} system prompt (${fmtBytes(payload.system.bytes)}) [s]  `) +
               c.dim('─'.repeat(Math.max(0, innerWidth - 36))));
    if (showSystem) {
      for (const ln of payload.system.text.split('\n')) {
        lines.push('  ' + c.dim(clipLine(ln, innerWidth - 2)));
      }
    }
    lines.push('');
  }

  // build id → tool_use map (across all messages) for pairing
  const toolUseById = new Map();
  for (const m of payload.messages || []) {
    for (const b of m.blocks || []) {
      if (b.kind === 'tool_use' && b.toolUseId) toolUseById.set(b.toolUseId, b);
    }
  }

  // ── messages, grouped into turns ──────────────────────────────────────────
  const turns = groupTurns(payload.messages || []);
  const turnsHeaderMode = turns.length > 1 ? (showAllTurns ? 'expanded' : 'last-only') : 'single';
  lines.push(c.dim('── messages (' + (payload.messages?.length || 0) + ' in ' +
    turns.length + ' turn' + (turns.length === 1 ? '' : 's') +
    (turns.length > 1 ? `, ${showAllTurns ? 'all expanded' : 'older collapsed'} [a]` : '') + ') ' +
    '─'.repeat(Math.max(0, innerWidth - 32))));

  // Collapse all turns except the last unless showAllTurns is set.
  const lastTurnIdx = turns.length - 1;
  for (let ti = 0; ti < turns.length; ti++) {
    const turn = turns[ti];
    const isLastTurn = ti === lastTurnIdx;
    if (!showAllTurns && !isLastTurn) {
      // Render a single-line collapsed header for this turn.
      const promptPreview = turn.prompt.split('\n')[0].slice(0, innerWidth - 28);
      const blockCount = turn.messages.reduce((s, m) => s + (m.blocks?.length || 0), 0);
      lines.push(c.dim('  ▶ Turn ' + (ti + 1) + ': ') + c.dim('"' + promptPreview + '"') +
        c.dim(`  (${blockCount} blocks)`));
      continue;
    }
    if (turns.length > 1) {
      lines.push(c.dim('  ▼ Turn ' + (ti + 1) + (isLastTurn && ti > 0 ? ' (current)' : '')));
    }
  for (const m of turn.messages) {
    const tag = m.role === 'user' ? c.cyan('[user]')
              : m.role === 'assistant' ? c.mag('[assistant]')
              : c.dim('[' + m.role + ']');
    for (const b of m.blocks || []) {
      if (b.kind === 'text') {
        const split = splitReminders(b.text);
        const head = `${tag} `;
        if (split.main) {
          const mainLines = split.main.split('\n');
          for (let i = 0; i < mainLines.length; i++) {
            const ln = mainLines[i];
            const prefix = i === 0 ? head : '       ';
            lines.push(prefix + c.white(clipLine(ln, innerWidth - stripAnsi(prefix).length)));
          }
        } else if (split.reminders.length === 0) {
          lines.push(head + c.dim('(empty text block)'));
        }
        for (const rem of split.reminders) {
          const rHead = showReminders ? '▼' : '▶';
          const remBytes = fmtBytes(rem.length);
          lines.push('       ' + c.yellow(`${rHead} system-reminder (${remBytes}) [r]`));
          if (showReminders) {
            for (const rln of rem.split('\n')) {
              lines.push('         ' + c.dim(clipLine(rln, innerWidth - 10)));
            }
          }
        }
        if (b.truncated) lines.push('       ' + c.dim(`…(truncated, full ${fmtBytes(b.bytes)})`));
      } else if (b.kind === 'tool_use') {
        const p = shortPath(inputPath(b.input), innerWidth - 30);
        lines.push(`${tag} ${c.yellow('→ ' + b.toolName)} ${c.dim(p)}`);
      } else if (b.kind === 'tool_result') {
        const paired = b.toolUseId ? toolUseById.get(b.toolUseId) : null;
        const sourceName = paired ? paired.toolName : 'tool_result';
        const sourcePath = paired ? inputPath(paired.input) : null;
        const head = `${tag} ${c.green('← ' + sourceName)} ${c.dim(shortPath(sourcePath, innerWidth - 30))} ${c.dim('(' + fmtBytes(b.bytes) + ')')}`;
        lines.push(head);
        const body = b.text || '';
        if (!body) {
          lines.push('       ' + c.dim('(empty result)'));
        } else {
          const bodyLines = body.split('\n');
          for (let i = 0; i < bodyLines.length; i++) {
            const num = c.dim(String(i + 1).padStart(4) + '│');
            const isRedactionLine = /\[REDACTED|✂✂✂/.test(bodyLines[i]);
            const content = isRedactionLine
              ? c.bgYellow(clipLine(bodyLines[i], innerWidth - 6))
              : c.white(clipLine(bodyLines[i], innerWidth - 6));
            lines.push('  ' + num + ' ' + content);
          }
        }
        if (b.truncated) lines.push('       ' + c.dim(`…(truncated, full ${fmtBytes(b.bytes)})`));
        if (b.isError) lines.push('       ' + c.red('(tool reported error)'));
      } else if (b.kind === 'other') {
        lines.push(`${tag} ${c.dim('[' + (b.type || 'block') + ' block]')}`);
      } else {
        // Future block kinds (image, document, server_tool_use, etc.) — at
        // least surface them rather than silently dropping. JSON-stringify
        // the block summary so the reader sees there's content here.
        lines.push(`${tag} ${c.dim('[' + (b.kind || 'unknown') + ']')}`);
      }
    }
  }
  }

  // ── inbound response (assistant) ─────────────────────────────────────────
  if (payload.response) {
    const r = payload.response;
    const usage = r.usage
      ? ` · ${(r.usage.input_tokens || 0) + (r.usage.cache_read_input_tokens || 0)} in · ${r.usage.output_tokens || 0} out`
      : '';
    lines.push('');
    lines.push(c.dim('── ← ' + c.bold(c.mag('assistant response')) + c.dim(
      ` (${r.model || 'unknown model'}${usage}${r.stopReason ? ' · ' + r.stopReason : ''}) `) +
      c.dim('─'.repeat(Math.max(0, innerWidth - 50)))));
    for (const b of r.blocks || []) {
      if (b.kind === 'text') {
        for (const ln of (b.text || '').split('\n')) {
          lines.push('  ' + c.white(clipLine(ln, innerWidth - 2)));
        }
        if (b.truncated) lines.push('  ' + c.dim(`…(truncated, full ${fmtBytes(b.bytes)})`));
      } else if (b.kind === 'tool_use') {
        const p = shortPath(inputPath(b.input), innerWidth - 30);
        lines.push('  ' + c.yellow('→ ' + b.toolName) + ' ' + c.dim(p));
        const inputStr = JSON.stringify(b.input || {});
        if (inputStr.length > 2) lines.push('    ' + c.dim(clipLine(inputStr, innerWidth - 4)));
      } else {
        lines.push('  ' + c.dim('[' + (b.type || b.kind) + ']'));
      }
    }
  } else if (payload.responseMeta) {
    lines.push('');
    lines.push(c.dim('  (response capture failed to parse — ' + payload.responseMeta.bytes + ' bytes)'));
  }

  // ── raw mode (key R) shows the literal response bytes (capped) ───────────
  if (opts && opts.showRaw && payload.responseRaw && payload.responseRaw.text) {
    lines.push('');
    lines.push(c.dim('── raw response bytes (' + fmtBytes(payload.responseRaw.bytes) + ') [R] ' +
      '─'.repeat(Math.max(0, innerWidth - 38))));
    for (const ln of payload.responseRaw.text.split('\n')) {
      lines.push('  ' + c.dim(clipLine(ln, innerWidth - 2)));
    }
  }

  return lines;
}

function clipLine(s, max) {
  s = String(s == null ? '' : s);
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

/**
 * render(payload, opts) → full-screen string.
 * opts: { width, height, color, scroll, total, index, paused }
 */
function render(payload, opts) {
  opts = opts || {};
  const c = pickColor(opts.color !== false);
  const W = Math.max(72, opts.width || 80);
  const H = Math.max(20, opts.height || 28);
  const inner = W - 4;
  const out = [];

  // ── Header ────────────────────────────────────────────────────────────────
  if (!payload) {
    out.push(c.bold('┌─ AGENT EYES — content ' + '─'.repeat(Math.max(0, inner - 22)) + '─┐'));
    out.push(c.bold('│') + ' '.repeat(inner + 2) + c.bold('│'));
    out.push(c.bold('│  ') + c.dim('(no outbound captured yet — run `occasio claude --eyes` and trigger a tool call)') + ' '.repeat(Math.max(0, inner - 78)) + c.bold('│'));
    out.push(c.bold('│') + ' '.repeat(inner + 2) + c.bold('│'));
    out.push(c.bold('└') + '─'.repeat(inner + 2) + c.bold('┘'));
    if (opts.color === false) return out.join('\n') + '\n';
    return HOME + out.join('\n') + '\n' + CLEAR_TO_END;
  }

  const stats = ` ${fmtBytes(payload.byteCount?.after)} → cloud · ${c.yellow(payload.redactionCount + ' redacted')} · ${c.red(payload.blockedCount + ' blocked')} `;
  const idx = opts.total ? ` ${opts.index || 1}/${opts.total} ` : '';
  const title = ` AGENT EYES · OUTBOUND #${payload.seq} ${idx}→ api.anthropic.com · ${fmtTime(payload.ts)} `;
  const dashes = Math.max(0, inner + 2 - title.length - stripAnsi(stats).length);
  out.push(c.bold('┌') + c.bold(title) + '─'.repeat(dashes) + stats + c.bold('┐'));

  // ── Body (scrollable window) ─────────────────────────────────────────────
  const bodyLines = buildBodyLines(payload, c, inner, {
    showSystem: !!opts.showSystem,
    showReminders: !!opts.showReminders,
    showRaw: !!opts.showRaw,
    showAllTurns: !!opts.showAllTurns,
  });
  // reserve: 1 header (already pushed), 1 border, 2 footer = 3 → body fills H-4
  const bodyHeight = Math.max(5, H - 5);
  const totalLines = bodyLines.length;
  const scroll = Math.max(0, Math.min(Math.max(0, totalLines - 1), opts.scroll || 0));
  const slice = bodyLines.slice(scroll, scroll + bodyHeight);
  while (slice.length < bodyHeight) slice.push('');

  // Scrollbar geometry: thumb position + size proportional to bodyHeight/totalLines.
  // Render the scrollbar inside the right border so it's always visible without
  // stealing content columns. Track = ░, thumb = █.
  const hasScrollbar = totalLines > bodyHeight;
  let thumbStart = 0, thumbEnd = bodyHeight;
  if (hasScrollbar) {
    const ratio = scroll / Math.max(1, totalLines - bodyHeight);
    const thumbSize = Math.max(1, Math.round((bodyHeight / totalLines) * bodyHeight));
    thumbStart = Math.round(ratio * (bodyHeight - thumbSize));
    thumbEnd = Math.min(bodyHeight, thumbStart + thumbSize);
  }

  out.push(c.bold('├') + '─'.repeat(inner + 2) + c.bold('┤'));
  for (let i = 0; i < slice.length; i++) {
    const ln = slice[i];
    const vis = stripAnsi(ln);
    // leave 1 column for scrollbar when active
    const contentWidth = hasScrollbar ? inner + 1 : inner + 2;
    const padN = Math.max(1, contentWidth - vis.length);
    let rightBorder;
    if (hasScrollbar) {
      const inThumb = i >= thumbStart && i < thumbEnd;
      rightBorder = inThumb ? c.cyan('█') + c.bold('│') : c.dim('░') + c.bold('│');
    } else {
      rightBorder = c.bold('│');
    }
    out.push(c.bold('│') + ' ' + ln + ' '.repeat(Math.max(0, padN - 1)) + rightBorder);
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  out.push(c.bold('├') + '─'.repeat(inner + 2) + c.bold('┤'));
  const scrollHint = totalLines > bodyHeight
    ? `${scroll + 1}-${Math.min(totalLines, scroll + bodyHeight)} / ${totalLines}`
    : `${totalLines} lines`;
  const status = opts.toast
    ? c.cyan(opts.toast)
    : (opts.paused ? c.yellow('⏸ paused') : c.green('live'));
  const help = ` ↑↓ scroll · ←→ exchange · a turns · s sys · r rem · R raw · c copy · q quit `;
  const footL = ` ${c.dim(scrollHint)}  ${status} `;
  const footR = c.dim(help);
  const fill = Math.max(1, inner + 2 - stripAnsi(footL).length - stripAnsi(footR).length);
  out.push(c.bold('│') + footL + ' '.repeat(fill) + footR + c.bold('│'));
  out.push(c.bold('└') + '─'.repeat(inner + 2) + c.bold('┘'));

  // Redraw in place: HOME at top, CLEAR_TO_END at bottom. Skip both in
  // --no-color mode so dumps stay plain (no escapes at all).
  if (opts.color === false) {
    return out.join('\n') + '\n';
  }
  return HOME + out.join('\n') + '\n' + CLEAR_TO_END;
}

module.exports = { render, buildBodyLines, groupTurns, stripAnsi, fmtBytes };
