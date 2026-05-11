'use strict';

/**
 * classifier.js — Semantic routing for Bash tool_use calls.
 *
 * Replaces the simple LOCAL_BASH_CMDS whitelist with structured class data
 * from embeddings.json. Key improvements over the whitelist:
 *
 *   1. Git subcommand awareness — "git push" is rejected, "git log" is accepted.
 *   2. Dangerous flag detection — "--force", "--hard" block interception.
 *   3. Extensible via embeddings.json without code changes.
 *   4. Routing feedback log for future ML training.
 *
 * routeLocally() is the public interface.
 * isInterceptable() in interceptor.js delegates here.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const DATA         = require('./embeddings.json');
const ALWAYS_LOCAL = new Set(DATA.always_local);
const NEVER_LOCAL  = new Set(DATA.never_local);
const GIT_SAFE     = new Set(DATA.git_safe_subcommands);
const GIT_UNSAFE   = new Set(DATA.git_unsafe_subcommands);
const DANGER_FLAGS = new Set(DATA.dangerous_flags);
const SHELL_META   = /[;&|`$<>\\]/;

const FEEDBACK_LOG = path.join(os.homedir(), '.localfirst', 'routing-feedback.jsonl');

/**
 * Decide whether a tool call should be executed locally.
 *
 * @param {string} toolName   e.g. "Bash"
 * @param {string} command    the command string
 * @param {string} [context]  reserved for future ML use
 * @returns {{ local: boolean, confidence: number, reason: string }}
 */
function routeLocally(toolName, command, context = '') {
  if (toolName !== 'Bash') {
    return { local: false, confidence: 1.0, reason: 'non-bash tool' };
  }

  const cmd = (command || '').trim();
  if (!cmd) {
    return { local: false, confidence: 1.0, reason: 'empty command' };
  }
  if (SHELL_META.test(cmd)) {
    return { local: false, confidence: 1.0, reason: 'shell metacharacter' };
  }

  const parts     = cmd.split(/\s+/);
  const firstWord = parts[0].toLowerCase();

  // Dangerous flags anywhere in the command override everything.
  // Check exact case (git -D is uppercase, distinct from -d) then also lowercase
  // so --Force and similar variants are still caught.
  const hasDangerFlag = parts.slice(1).some(p => DANGER_FLAGS.has(p) || DANGER_FLAGS.has(p.toLowerCase()));
  if (hasDangerFlag) {
    return { local: false, confidence: 0.95, reason: 'dangerous flag' };
  }

  // Hard block
  if (NEVER_LOCAL.has(firstWord)) {
    return { local: false, confidence: 0.95, reason: `${firstWord}: write/execute command` };
  }

  // Git requires subcommand-level inspection
  if (firstWord === 'git') {
    const sub = (parts[1] || '').toLowerCase();
    if (GIT_SAFE.has(sub)) {
      return { local: true, confidence: 0.95, reason: `git ${sub}: read-only` };
    }
    if (GIT_UNSAFE.has(sub) || sub === '') {
      return { local: false, confidence: 0.92, reason: `git ${sub || '(bare)'}: write/network operation` };
    }
    // Unknown git subcommand — conservative
    return { local: false, confidence: 0.65, reason: `git ${sub}: unknown subcommand` };
  }

  // Safe read commands
  if (ALWAYS_LOCAL.has(firstWord)) {
    return { local: true, confidence: 0.95, reason: `${firstWord}: safe read command` };
  }

  // Unknown — default to cloud
  return { local: false, confidence: 0.6, reason: `${firstWord}: unknown command` };
}

/**
 * Append a routing decision to the feedback log for future training.
 *
 * @param {string} command
 * @param {{ local: boolean, confidence: number, reason: string }} decision
 * @param {number} latency_ms
 * @param {'success'|'error'|'timeout'} outcome
 */
function logRoutingDecision(command, decision, latency_ms, outcome) {
  try {
    const entry = JSON.stringify({
      ts:         new Date().toISOString(),
      command:    (command || '').slice(0, 200),
      local:      decision.local,
      confidence: decision.confidence,
      reason:     decision.reason,
      latency_ms,
      outcome,
    }) + '\n';
    fs.mkdirSync(path.dirname(FEEDBACK_LOG), { recursive: true });
    fs.appendFileSync(FEEDBACK_LOG, entry);
  } catch { /* feedback is best-effort */ }
}

module.exports = { routeLocally, logRoutingDecision };
