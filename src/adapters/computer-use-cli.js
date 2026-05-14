'use strict';

/**
 * computer-use-cli.js — `localfirst computer-use` (dry-run demo).
 *
 * Reads a JSONL file of synthetic tool_use blocks (or stdin), applies a
 * computer-use policy file, and prints what the engine would decide for
 * each one. Lets us demo the governance story for Anthropic Computer Use
 * without yet wiring up the live proxy adapter.
 *
 * Usage:
 *   localfirst computer-use --dry-run --from <jsonl>   [--policy <yml>]
 *   localfirst computer-use --example                  # built-in sample
 *
 * Live mode (intercept a real Computer-Use session through the proxy) is
 * a follow-up that requires:
 *   - extending the proxy SSE parser to recognise computer-use tool-use
 *     blocks (currently only the Claude Code shape is parsed)
 *   - injecting BLOCK results back as tool_result blocks (mirroring what
 *     the Claude Code adapter does)
 *   - end-to-end validation against the actual Anthropic API
 *
 * That work is deferred until at least one design partner is on it. The
 * adapter logic in src/adapters/computer-use.js is the half that can be
 * built and unit-tested without an API key.
 */

const fs = require('fs');

const { normalizeToolUse, evaluate } = require('./computer-use');

const C = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

// Minimal inline YAML reader for the dry-run CLI — just enough to parse the
// example policies we ship. Real users wire up `policy.yml` through the
// full policy/loader.js path; this CLI is a demo.
function parsePolicyYaml(text) {
  const out = {};
  let currentArray = null;
  let currentKey = null;
  for (const line of text.split('\n')) {
    const clean = line.replace(/#.*$/, '').replace(/\r$/, '');
    if (!clean.trim()) continue;
    const top = clean.match(/^([a-z_]+)\s*:\s*(.*)$/i);
    if (top) {
      currentKey = top[1];
      const value = top[2].trim();
      if (!value) { out[currentKey] = []; currentArray = out[currentKey]; }
      else        { out[currentKey] = parseScalar(value); currentArray = null; }
      continue;
    }
    if (currentArray && /^\s*-\s+/.test(clean)) {
      currentArray.push(parseScalar(clean.replace(/^\s*-\s+/, '')));
    }
  }
  return out;
}

function parseScalar(s) {
  s = s.trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  if (s === 'true')  return true;
  if (s === 'false') return false;
  return s;
}

const EXAMPLE_TRAFFIC = [
  { type: 'tool_use', name: 'computer', input: { action: 'screenshot' } },
  { type: 'tool_use', name: 'computer', input: { action: 'mouse_move', coordinate: [400, 300] } },
  { type: 'tool_use', name: 'computer', input: { action: 'left_click', coordinate: [400, 300] } },
  { type: 'tool_use', name: 'computer', input: { action: 'type', text: 'Hello world' } },
  { type: 'tool_use', name: 'computer', input: { action: 'type', text: 'password: hunter2sekret' } },
  { type: 'tool_use', name: 'bash',     input: { command: 'ls -la' } },
  { type: 'tool_use', name: 'bash',     input: { command: 'sudo rm -rf /tmp/x' } },
  { type: 'tool_use', name: 'bash',     input: { command: 'curl https://github.com/some/repo' } },
];

const EXAMPLE_POLICY = {
  deny_keyboard_patterns: [
    { pattern: '(?i)password\\s*[:=]\\s*\\S+', reason: 'keyboard-secret-pattern' },
    { pattern: '(?i)secret\\s*[:=]\\s*\\S+',   reason: 'keyboard-secret-pattern' },
    '(?i)(sk-ant-|ghp_|AKIA)[A-Za-z0-9]{16,}',
  ],
  deny_command_patterns: [
    '\\bcurl\\b.*\\b(api\\.|admin\\.|prod\\.)',  // exfil patterns
  ],
};

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
function bool(args, name) { return args.indexOf(name) >= 0; }

function runComputerUseCli(args = []) {
  if (bool(args, '--help') || bool(args, '-h')) {
    process.stdout.write(
      'Usage:\n' +
      '  localfirst computer-use --dry-run --from <jsonl> [--policy <yml>]\n' +
      '  localfirst computer-use --example\n\n' +
      'Apply a computer-use policy to a JSONL of synthetic tool_use blocks\n' +
      'and report each decision. Live proxy interception is not yet wired —\n' +
      'this is the adapter\'s policy-engine half, validated in isolation.\n'
    );
    return 0;
  }

  const example = bool(args, '--example');
  const dryRun  = bool(args, '--dry-run') || example;
  if (!dryRun) {
    process.stderr.write(`${C.r('error')}: pass --dry-run (live interception not yet wired)\n`);
    return 2;
  }

  let traffic;
  let policy;

  if (example) {
    traffic = EXAMPLE_TRAFFIC.slice();
    policy  = EXAMPLE_POLICY;
    process.stdout.write(C.d('[example mode: built-in synthetic traffic + sample policy]\n\n'));
  } else {
    const fromPath = flag(args, '--from');
    if (!fromPath) {
      process.stderr.write(`${C.r('error')}: --from <jsonl> required (or use --example)\n`);
      return 2;
    }
    try {
      traffic = fs.readFileSync(fromPath, 'utf8')
        .split('\n').filter(Boolean)
        .map(line => JSON.parse(line));
    } catch (e) {
      process.stderr.write(`${C.r('error')}: cannot read traffic file: ${e.message}\n`);
      return 2;
    }
    const polPath = flag(args, '--policy');
    if (polPath) {
      try { policy = parsePolicyYaml(fs.readFileSync(polPath, 'utf8')); }
      catch (e) {
        process.stderr.write(`${C.r('error')}: cannot read policy: ${e.message}\n`);
        return 2;
      }
    } else {
      policy = EXAMPLE_POLICY;
      process.stdout.write(C.d('[no --policy given; using built-in sample policy]\n\n'));
    }
  }

  let blocked = 0, allowed = 0;
  for (const raw of traffic) {
    const tool     = normalizeToolUse(raw);
    const decision = evaluate(tool, policy);
    if (decision.decision === 'BLOCK') blocked++; else allowed++;
    renderDecision(raw, decision);
  }

  process.stdout.write(
    `\n${C.b('Summary')}: ${C.g(allowed + ' allowed')} · ${C.r(blocked + ' blocked')} ` +
    `· ${traffic.length} total\n`);
  return blocked > 0 ? 1 : 0;
}

function renderDecision(raw, dec) {
  const name = raw.name || 'unknown';
  const sub  = raw.input?.action || '';
  const tag  = sub ? `${name}.${sub}` : name;
  const valuePreview = previewInput(raw);
  if (dec.decision === 'BLOCK') {
    process.stdout.write(`  ${C.r('✗ BLOCK')}  ${C.b(tag.padEnd(28))} ${C.d(valuePreview)}\n`);
    process.stdout.write(`           ${C.d('reason: ' + dec.reason + (dec.detail ? ' (' + dec.detail + ')' : ''))}\n`);
  } else {
    process.stdout.write(`  ${C.g('✓ ALLOW')}  ${C.b(tag.padEnd(28))} ${C.d(valuePreview)}\n`);
  }
}

function previewInput(raw) {
  const inp = raw.input || {};
  if (inp.text) return JSON.stringify(inp.text).slice(0, 60);
  if (inp.command) return inp.command.slice(0, 60);
  if (inp.coordinate) return `[${inp.coordinate.join(',')}]`;
  return '';
}

module.exports = {
  runComputerUseCli,
  EXAMPLE_TRAFFIC,
  EXAMPLE_POLICY,
  _parsePolicyYaml: parsePolicyYaml,
};
