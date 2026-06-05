'use strict';

/**
 * occasio hook — Claude Code `PreToolUse` entrypoint (the second enforcement
 * point, for execution that does NOT flow through the Occasio proxy).
 *
 * Contract (verified against code.claude.com/docs/en/hooks):
 *   - stdin: JSON `{ tool_name, tool_input:{command}, … }`.
 *   - exit 2 blocks (stderr shown to Claude); exit 0 proceeds; **exit 1/other is
 *     NON-blocking (the tool still runs)**. So this hook is wrapped so that ANY
 *     error denies (exit 2) — an error is never a silent pass-through.
 *
 * Coexistence with the proxy is fail-closed: the hook no-ops ONLY on a positive,
 * unforgeable proof that the proxy is enforcing this session (a per-session token
 * the proxy put in Claude Code's own env AND in ~/.occasio/session.json, which the
 * agent can neither set nor read). Absence / mismatch / any doubt → enforce.
 *
 * All policy logic is delegated to `occasio gate --enforce` (the shared
 * decideShellCommand core), so the hook can never drift from the proxy.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);

function sessionFile() {
  return process.env.OCCASIO_SESSION_FILE || path.join(os.homedir(), '.occasio', 'session.json');
}

/**
 * Positive, unforgeable proxy detection. The env token is set by the proxy into
 * Claude Code's process at spawn (the agent's Bash subprocess cannot change it);
 * the matching token in session.json is agent-unreadable (deny_paths ~/.occasio).
 * Any absence / mismatch / read error → false → enforce (fail-closed).
 */
function proxyVerified() {
  const envTok = process.env.OCCASIO_PROXY_SESSION;
  if (!envTok || typeof envTok !== 'string') return false;
  try {
    const s = JSON.parse(fs.readFileSync(sessionFile(), 'utf8'));
    return typeof s.proxy_session === 'string' && s.proxy_session.length > 0 && s.proxy_session === envTok;
  } catch { return false; }
}

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

/**
 * @returns {number} process exit code: 0 (proceed) or 2 (block).
 */
function run(args) {
  args = args || [];
  if (args.includes('--install') || args.includes('install')) {
    return require('./hook-install').run(args);
  }
  // FAIL-CLOSED: any error denies. A non-2 exit (incl. a crash → 1) would let the
  // tool run, so the catch returns 2.
  try {
    let input;
    try { input = JSON.parse(readStdin()); } catch { input = {}; }

    const toolName = input.tool_name;
    if (!SHELL_TOOLS.has(toolName)) return 0;       // not a shell tool → not ours
    if (proxyVerified()) return 0;                  // proxy is enforcing → defer

    const command = input.tool_input && input.tool_input.command;
    if (typeof command !== 'string' || !command.trim()) return 0; // nothing to gate

    // Delegate to the shared decision (consume + audit + stderr message), in-process.
    const code = require('./gate').run([command, '--enforce']);
    return code === 0 ? 0 : 2;                       // 2 or 3 → block (exit 2)
  } catch (e) {
    try { process.stderr.write('Occasio: hook error — denying for safety: ' + (e && e.message) + '\n'); } catch { /* ignore */ }
    return 2;
  }
}

module.exports = { run, proxyVerified, SHELL_TOOLS };
