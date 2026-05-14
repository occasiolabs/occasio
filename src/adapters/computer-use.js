'use strict';

/**
 * adapters/computer-use.js — policy + decision engine for Anthropic Computer
 * Use traffic.
 *
 * Status: tech-demo scaffold. This module defines the tool schemas,
 * normalises raw tool-use blocks into a stable internal shape, and applies
 * a small set of computer-use-specific deny directives. It is intentionally
 * decoupled from the live proxy adapter — wiring it into the request path
 * (so a real Computer-Use session is policed in real time) requires an
 * Anthropic API key for validation and lives behind the `localfirst
 * computer-use` CLI as a dry-run demo until then.
 *
 * Why a separate adapter at all
 *   Coding agents touch files. Computer-use agents touch the whole
 *   operating system: screen pixels, keyboard, mouse, browser. The blast
 *   radius is qualitatively larger. The same governance primitives (deny,
 *   redact, audit, attest) need a different rule vocabulary:
 *     - "this URL pattern is forbidden navigation"
 *     - "the keyboard input must not match a known-secret pattern"
 *     - "the screenshot must not contain region X" (stub — pixel work
 *       is deferred until we have a real session to validate against)
 *
 * Tool inventory (Anthropic Computer Use API, v20241022 / v20250124)
 *   computer.screenshot              → no inputs
 *   computer.mouse_move              → { coordinate: [x, y] }
 *   computer.left_click              → { coordinate? }
 *   computer.right_click             → { coordinate? }
 *   computer.middle_click            → { coordinate? }
 *   computer.double_click            → { coordinate? }
 *   computer.left_click_drag         → { start_coordinate, coordinate }
 *   computer.type                    → { text }
 *   computer.key                     → { text }   (keysym)
 *   computer.cursor_position         → no inputs
 *   bash                             → { command }   (shell)
 *   str_replace_editor               → file editing (out of scope here;
 *                                       handled by existing Read/Edit path)
 *
 * Decision codes match the rest of LocalFirst: ALLOW | BLOCK | TRANSFORM.
 *
 * NOT YET DONE (explicit deferrals — track at the call sites):
 *   - Live proxy adapter wiring (needs `x-localfirst-agent: computer-use`
 *     header routing and tool-result injection back into the SSE stream).
 *     Today the proxy only knows Claude Code; the Cline adapter is
 *     synthetic; computer-use will be the third live adapter.
 *   - Pixel-region deny rules. Requires lifting screenshot tensors and
 *     either OCR or fixed-region template matching. Deferred until at
 *     least one paying customer asks.
 *   - URL extraction from screenshots / browser state. We can intercept
 *     `bash` calls that issue `curl`/`wget` etc. via existing rules, but
 *     mouse-driven browser navigation will need a hook into the agent's
 *     screen-state stream — likely an MCP-style "browser state" tool.
 */

// ── Tool registry ────────────────────────────────────────────────────────────

const COMPUTER_ACTIONS = new Set([
  'screenshot', 'mouse_move',
  'left_click', 'right_click', 'middle_click', 'double_click',
  'left_click_drag',
  'type', 'key', 'cursor_position',
]);

const KNOWN_TOOL_NAMES = new Set([
  'computer', 'bash', 'str_replace_editor',
]);

/**
 * Normalise a raw tool_use block (as it appears in Anthropic messages
 * API responses) into a stable `{ kind, action, ... }` shape that the
 * policy engine consumes.
 *
 * Returns null for unrecognised inputs so callers can decide whether
 * an unknown tool is itself a policy violation.
 */
function normalizeToolUse(block) {
  if (!block || typeof block !== 'object') return null;
  if (block.type && block.type !== 'tool_use') return null;
  const name = String(block.name || '').toLowerCase();
  if (!KNOWN_TOOL_NAMES.has(name)) return null;
  const input = (block.input && typeof block.input === 'object') ? block.input : {};

  if (name === 'computer') {
    const action = String(input.action || '').toLowerCase();
    if (!COMPUTER_ACTIONS.has(action)) return null;
    return {
      kind:        'computer',
      action,
      coordinate:       Array.isArray(input.coordinate)       ? input.coordinate.slice(0, 2) : null,
      start_coordinate: Array.isArray(input.start_coordinate) ? input.start_coordinate.slice(0, 2) : null,
      text:        typeof input.text === 'string' ? input.text : null,
      raw:         block,
    };
  }
  if (name === 'bash') {
    return {
      kind:    'bash',
      command: typeof input.command === 'string' ? input.command : null,
      raw:     block,
    };
  }
  if (name === 'str_replace_editor') {
    return { kind: 'str_replace_editor', raw: block };
  }
  return null;
}

// ── Policy rules ─────────────────────────────────────────────────────────────

/**
 * A computer-use policy is a plain object — same flavour as policy.yml.
 * Recognised directives (extensions to the existing engine):
 *
 *   deny_keyboard_patterns:
 *     - pattern: '(?i)password\\s*[:=]\\s*\\S+'
 *       reason:  'keyboard-secret-pattern'
 *
 *   deny_command_patterns:        # bash commands
 *     - '(?i)\\bsudo\\b'
 *
 *   deny_screen_regions:          # stub: pixel work deferred
 *     - { x: 0, y: 0, w: 1920, h: 100, reason: 'top-bar-banner-info' }
 *
 *   max_clicks_per_minute: 30     # rate-limit click bursts
 *   allow_browser_hosts:          # if non-empty, anything else denied
 *     - 'github.com'
 *     - 'docs.anthropic.com'
 *
 * Missing directives → no constraint from that directive (additive).
 */

const RESERVED_SHELL_BLACKLIST = [
  /\bsudo\b/i, /\bsu\b/i,
  /\brm\s+-rf\s+\//i,
  /\bmkfs\b/i, /\bdd\s+if=/i,
  /:\(\)\s*\{\s*:\|:\&/,   // fork bomb
];

// Compile a policy pattern string into a JS RegExp. PCRE/RE2-style inline
// flag prefixes `(?i)` and `(?m)` are not native to JS — translate them to
// the corresponding RegExp flags so policy authors can write the syntax
// they already know. Returns null on malformed input (caller treats as
// skip-not-fail to keep one bad rule from disarming the rest of policy).
function compilePolicyPattern(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  let body = raw;
  let flags = '';
  const inlineFlagMatch = body.match(/^\(\?([imsux]+)\)/);
  if (inlineFlagMatch) {
    for (const ch of inlineFlagMatch[1]) {
      if ('ims'.includes(ch) && !flags.includes(ch)) flags += ch;
    }
    body = body.slice(inlineFlagMatch[0].length);
  }
  try { return new RegExp(body, flags); }
  catch { return null; }
}

function evaluate(tool, policy = {}) {
  if (!tool) {
    return { decision: 'BLOCK', reason: 'unrecognised-tool-use', tool: null };
  }

  if (tool.kind === 'computer') {
    if (tool.action === 'type' || tool.action === 'key') {
      const txt = tool.text || '';
      const pats = (policy.deny_keyboard_patterns || []).map(p =>
        typeof p === 'string' ? { pattern: p, reason: 'keyboard-pattern' }
                              : { pattern: p.pattern, reason: p.reason || 'keyboard-pattern' });
      for (const { pattern, reason } of pats) {
        const re = compilePolicyPattern(pattern);
        if (!re) continue;             // malformed → skip, not fatal
        if (re.test(txt)) {
          return {
            decision: 'BLOCK', reason, tool,
            detail: 'keyboard input matches deny pattern',
          };
        }
      }
    }
    // mouse / screenshot / cursor: pass-through under current policy set.
    // Pixel-region rules and rate limits land here when implemented.
    return { decision: 'ALLOW', reason: 'pass-through', tool };
  }

  if (tool.kind === 'bash') {
    const cmd = tool.command || '';
    if (!cmd) return { decision: 'BLOCK', reason: 'empty-command', tool };

    // Built-in lethal-command blacklist — always on, not configurable.
    // Computer-Use agents can invoke shell with little oversight; we
    // refuse the most dangerous one-liners even if policy is permissive.
    for (const re of RESERVED_SHELL_BLACKLIST) {
      if (re.test(cmd)) {
        return { decision: 'BLOCK', reason: 'reserved-blacklist', tool, detail: re.source };
      }
    }
    const customPats = policy.deny_command_patterns || [];
    for (const raw of customPats) {
      const re = compilePolicyPattern(raw);
      if (!re) continue;               // malformed → skip, not fatal
      if (re.test(cmd)) {
        return { decision: 'BLOCK', reason: 'command-pattern', tool, detail: raw };
      }
    }
    return { decision: 'ALLOW', reason: 'pass-through', tool };
  }

  if (tool.kind === 'str_replace_editor') {
    // File-editor calls flow through the existing Read/Write/Edit path;
    // we forward unchanged here.
    return { decision: 'ALLOW', reason: 'delegated-to-editor-adapter', tool };
  }

  return { decision: 'BLOCK', reason: 'unrecognised-tool-kind', tool };
}

module.exports = {
  normalizeToolUse,
  evaluate,
  COMPUTER_ACTIONS,
  KNOWN_TOOL_NAMES,
  // Exposed for tests + custom policy linters.
  _RESERVED_SHELL_BLACKLIST: RESERVED_SHELL_BLACKLIST,
  _compilePolicyPattern:     compilePolicyPattern,
};
