'use strict';

/**
 * eyes/render.js — pure (state, tick, opts) → ANSI framebuffer.
 *
 * tick is a monotonic frame counter (ms-since-start). Pure so tests can pin a
 * frame and snapshot the output, and so replay/demo are deterministic given
 * the same event sequence + tick schedule.
 *
 * Layout target: 80×24 minimum, gracefully grows wider. No external deps; we
 * roll our own ANSI like src/cli/recap.js. Renderer never reads time or fs.
 */

const ESC = '\x1b[';
const CLS = ESC + '2J' + ESC + 'H';   // legacy; superseded by HOME + CLEAR_TO_END for redraw-in-place
const HOME = ESC + 'H';
const CLEAR_TO_END = ESC + 'J';
const HIDE_CURSOR = ESC + '?25l';
const SHOW_CURSOR = ESC + '?25h';
const ALT_ON  = ESC + '?1049h';
const ALT_OFF = ESC + '?1049l';

function paint(code) { return s => `${ESC}${code}m${s}${ESC}0m`; }
const C = {
  reset: ESC + '0m',
  dim:   paint('2'),
  bold:  paint('1'),
  inv:   paint('7'),
  red:   paint('31'),
  green: paint('32'),
  yellow:paint('33'),
  blue:  paint('34'),
  mag:   paint('35'),
  cyan:  paint('36'),
  white: paint('97'),
  bgRed: paint('41;97'),
  bgCyan:paint('46;30'),
};

function plain(s) { return s; }

function pickColor(useColor) {
  if (useColor) return C;
  const np = { reset: '' };
  for (const k of Object.keys(C)) np[k] = typeof C[k] === 'function' ? plain : '';
  return np;
}

function pad(s, n) {
  s = String(s);
  if (s.length >= n) return s.slice(0, n);
  return s + ' '.repeat(n - s.length);
}

function fmtBytes(b) {
  if (b == null) return '';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(2)} MB`;
}

function fmtUsd(n) {
  if (!n) return '$0.0000';
  if (n < 0.01) return '$' + n.toFixed(4);
  if (n < 1)    return '$' + n.toFixed(3);
  return '$' + n.toFixed(2);
}

function fmtTime(ts) {
  if (!ts) return '--:--:--';
  // ISO → HH:MM:SS
  const m = String(ts).match(/T(\d\d):(\d\d):(\d\d)/);
  return m ? `${m[1]}:${m[2]}:${m[3]}` : '--:--:--';
}

function actionBadge(item, c) {
  if (!item) return '';
  if (item.action === 'BLOCK')     return c.red('🛑 BLOCK ');
  if (item.action === 'TRANSFORM') return c.yellow('✂ REDACT');
  if (item.action === 'INFO')      return c.cyan('● POLICY');
  if (item.isLocal)                return c.green('⚡ LOCAL ');
  return c.blue('☁ CLOUD ');
}

// 40-cell progress bar driven by `phase` ∈ [0,1]
function progressBar(phase, width) {
  const filled = Math.max(0, Math.min(width, Math.round(phase * width)));
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function typingSlice(s, phase) {
  if (!s) return '';
  const n = Math.max(0, Math.min(s.length, Math.ceil(phase * s.length)));
  return s.slice(0, n);
}

function shortPath(p, max) {
  if (!p) return '(no path)';
  p = String(p);
  if (p.length <= max) return p;
  return '…' + p.slice(p.length - (max - 1));
}

function pulseHeartbeat(tick, c) {
  // 4-phase blink
  const phase = Math.floor(tick / 200) % 4;
  const glyphs = ['●', '◉', '○', '◌'];
  return c.cyan(glyphs[phase]);
}

/**
 * render(state, tick, opts)
 *   tick: ms since render start (drives animation phase)
 *   opts: { width, color, runLabel, paused }
 * Returns a full-screen ANSI string ready for stdout.write.
 */
function render(state, tick, opts) {
  opts = opts || {};
  const c = pickColor(opts.color !== false);
  const W = Math.max(72, opts.width || 80);
  const inner = W - 4; // border + 2 spaces
  const out = [];

  const sinceLast = Math.max(0, tick - (state.lastEventAt || 0));
  const liveBeat = state.lastEventAt ? pulseHeartbeat(tick, c) : c.dim('○');
  const runStr = state.runId ? state.runId.slice(0, 5) : '-----';
  const status = opts.paused ? c.yellow('⏸ paused') : c.green('live');

  // ── Header ────────────────────────────────────────────────────────────────
  const titleRaw = ' AGENT EYES ';
  const meta = ` run ${runStr} · ${fmtTime(state.now?.ts)} · ${liveBeat}${status} `;
  // visible-length aware (strip ANSI for measuring)
  const visMeta = stripAnsi(meta);
  const dashes = inner - titleRaw.length - visMeta.length;
  out.push(c.bold('┌─') + c.bold(titleRaw) + '─'.repeat(Math.max(0, dashes)) + meta + c.bold('─┐'));
  out.push(border(inner, c));

  // ── NOW ──────────────────────────────────────────────────────────────────
  const now = state.now;
  if (now) {
    // 800 ms animation window after each new event
    const phase = Math.max(0, Math.min(1, sinceLast / 800));
    const toolFull = pad(now.tool, 10);
    const toolShown = typingSlice(toolFull.trim(), phase);
    const badge = actionBadge(now, c);
    const pth = shortPath(now.path, inner - 28);
    const pthShown = phase >= 0.5 ? pth : '';
    const bytes = now.bytes != null ? c.dim(fmtBytes(now.bytes)) : '';

    let line = ` ${c.bold('NOW')}  ${badge}  ${c.white(pad(toolShown, 10))} ${pthShown}`;
    out.push(boxLine(line, inner, c, bytes));

    const bar = progressBar(phase, Math.min(40, inner - 12));
    const barLine = `        ${c.dim(bar)}`;
    out.push(boxLine(barLine, inner, c, ''));
  } else {
    out.push(boxLine(c.dim(' waiting for first event…'), inner, c, ''));
    out.push(boxLine('', inner, c, ''));
  }
  out.push(border(inner, c));

  // ── Recent ────────────────────────────────────────────────────────────────
  out.push(boxLine(' ' + c.bold('LAST CALLS'), inner, c, ''));
  const recent = state.recent.slice(0, 10);
  if (!recent.length) {
    out.push(boxLine(c.dim('  (none yet)'), inner, c, ''));
  } else {
    for (let i = 0; i < recent.length; i++) {
      const r = recent[i];
      const t = c.dim(fmtTime(r.ts));
      const tool = pad(r.tool, 10);
      const badge = actionBadge(r, c);
      // Glitch effect on first frame for REDACT
      const justArrived = i === 0 && sinceLast < 300;
      const p = (justArrived && r.action === 'TRANSFORM')
        ? c.yellow('▓▓▓▓▓▓▓▓▓▓')
        : shortPath(r.path, inner - 38);
      const detail = r.action === 'BLOCK'
        ? c.red(r.reason || 'deny')
        : r.action === 'TRANSFORM'
          ? c.yellow(`${r.redactions} redacted`)
          : r.bytes != null
            ? c.dim(fmtBytes(r.bytes))
            : r.exitCode != null
              ? c.dim(`exit ${r.exitCode}`)
              : '';
      const row = `  ${t}  ${badge}  ${c.white(tool)} ${p}`;
      const flash = justArrived && r.action === 'BLOCK' ? c.bgRed(row) : row;
      out.push(boxLine(flash, inner, c, detail));
    }
  }
  // pad to a stable height — 10 rows max + filler so jitter is bounded
  for (let i = recent.length; i < 10; i++) {
    out.push(boxLine('', inner, c, ''));
  }
  out.push(border(inner, c));

  // ── Totals ────────────────────────────────────────────────────────────────
  const t = state.totals;
  const totalCalls = t.local + t.cloud + t.blocks;
  const localPct = totalCalls ? Math.round((t.local / totalCalls) * 100) : 0;
  const cloudPct = totalCalls ? Math.round((t.cloud / totalCalls) * 100) : 0;
  const barW = Math.min(28, Math.max(10, inner - 40));
  const localFill = Math.round((localPct / 100) * barW);
  const cloudFill = Math.round((cloudPct / 100) * barW);

  out.push(boxLine(' ' + c.bold('LOCAL vs CLOUD'), inner, c, ''));
  out.push(boxLine(
    `  ${c.green('local ')} ${c.green('█'.repeat(localFill))}${c.dim('░'.repeat(barW - localFill))}  ${pad(localPct + '%', 4)}  ${c.dim(t.local + ' calls')}`,
    inner, c, '',
  ));
  out.push(boxLine(
    `  ${c.blue('cloud ')} ${c.blue('█'.repeat(cloudFill))}${c.dim('░'.repeat(barW - cloudFill))}  ${pad(cloudPct + '%', 4)}  ${c.dim(t.cloud + ' calls')}`,
    inner, c, '',
  ));
  // odometer-style saved
  const savedText = `  saved  ${c.bold(c.green(fmtUsd(t.savedUsd)))}  ·  ${c.yellow(t.redactions + ' redactions')}  ·  ${c.red(t.blocks + ' blocks')}`;
  out.push(boxLine(savedText, inner, c, ''));
  out.push(border(inner, c));

  // ── Policy ────────────────────────────────────────────────────────────────
  const polLine = state.policy.hash
    ? ` POLICY  ${c.cyan(state.policy.source || 'default')}  sha ${c.dim(state.policy.hash.slice(0,8))}  ·  hot-reloaded ${state.policy.hotReloads}×`
    : ` POLICY  ${c.dim('(none loaded yet)')}`;
  // pulse banner for 2s after hot reload
  const pulsed = state.policy.hotReloads > 0 && sinceLast < 2000 && state.now?.kind === 'policy_loaded'
    ? c.bgCyan(polLine)
    : polLine;
  out.push(boxLine(pulsed, inner, c, ''));

  // ── Footer ────────────────────────────────────────────────────────────────
  const help = ` q quit · space pause · r replay · d demo `;
  const padDashes = inner - help.length;
  out.push(c.bold('└') + '─'.repeat(Math.max(0, Math.floor(padDashes/2))) + c.dim(help) + '─'.repeat(Math.max(0, Math.ceil(padDashes/2))) + c.bold('┘'));

  // Redraw in place — see content-render.js for rationale.
  if (opts.color === false) return out.join('\n') + '\n';
  return HOME + out.join('\n') + '\n' + CLEAR_TO_END;
}

function border(inner, c) {
  return c.bold('├') + '─'.repeat(inner + 2) + c.bold('┤');
}

function boxLine(text, inner, c, rightDetail) {
  // text may contain ANSI; we right-pad based on visible length only.
  const visText = stripAnsi(text);
  const visDetail = stripAnsi(rightDetail || '');
  const space = inner + 2 - visText.length - visDetail.length;
  const fill = ' '.repeat(Math.max(1, space));
  return c.bold('│') + text + fill + (rightDetail || '') + c.bold('│');
}

function stripAnsi(s) {
  if (!s) return '';
  // eslint-disable-next-line no-control-regex
  return String(s).replace(/\x1b\[[0-9;]*m/g, '');
}

module.exports = {
  render, stripAnsi, fmtBytes, fmtUsd, fmtTime,
  CLS, HIDE_CURSOR, SHOW_CURSOR, ALT_ON, ALT_OFF, C,
};
