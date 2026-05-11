'use strict';

/**
 * Built-in classifier registry — names that policy.yml entries can reference
 * via `classifier: <name>`. Each classifier takes a BoundaryEvent and returns
 * { handled: boolean, reason: string }.
 *
 * Stage 3: classifiers wrap the existing JS validators. The user-facing
 * surface is the *name* in policy.yml (e.g. `bash-allowlist`); the
 * implementation stays in code where its accumulated correctness lives.
 *
 * Reason codes are preserved exactly (matching FALLBACK_REASONS) so that
 * status / dashboard / debug-log surfaces don't change.
 */

const {
  isReadHandleable,
  isGlobHandleable,
  isGrepHandleable,
  isTodoHandleable,
} = require('../runtime');

// classifyBlock owns the Bash/PowerShell allowlist + shell-meta + classifier
// gates. We delegate to it so reason codes match exactly. classifyBlock still
// uses Claude protocol names internally, so each shell classifier hardcodes
// the protocol name it represents (independent of the event's canonical name).
const lazyClassifyBlock = () => require('../interceptor').classifyBlock;

const CLASSIFIERS = Object.freeze({
  'read-input-validator': (event) => ({
    handled: !!isReadHandleable(event.toolInput),
    reason:  isReadHandleable(event.toolInput) ? 'ok' : 'read_unsupported_type',
  }),

  'glob-input-validator': (event) => ({
    handled: !!isGlobHandleable(event.toolInput),
    reason:  isGlobHandleable(event.toolInput) ? 'ok' : 'glob_injection_or_invalid',
  }),

  'grep-input-validator': (event) => {
    const ok = !!isGrepHandleable(event.toolInput);
    return {
      handled: ok,
      reason:  ok ? 'ok'
              : event.toolInput?.multiline === true ? 'grep_multiline'
              : 'grep_invalid_input',
    };
  },

  'todo-write-validator': (event) => ({
    handled: !!isTodoHandleable(event.toolInput, 'TodoWrite'),
    reason:  isTodoHandleable(event.toolInput, 'TodoWrite') ? 'ok' : 'tool_not_handled',
  }),

  'todo-read-validator': (event) => ({
    handled: !!isTodoHandleable(event.toolInput, 'TodoRead'),
    reason:  isTodoHandleable(event.toolInput, 'TodoRead') ? 'ok' : 'tool_not_handled',
  }),

  // Bash / PowerShell delegate fully to classifyBlock so the
  // SHELL_META / shell-composition / route-locally / native-handleable
  // accumulated correctness flows through unchanged. Reason codes match
  // FALLBACK_REASONS exactly.
  'bash-allowlist': (event) => {
    const cb = lazyClassifyBlock();
    return cb({ type: 'tool_use', id: event.id, name: 'Bash', input: event.toolInput });
  },
  'powershell-allowlist': (event) => {
    const cb = lazyClassifyBlock();
    return cb({ type: 'tool_use', id: event.id, name: 'PowerShell', input: event.toolInput });
  },
});

function lookup(name) {
  return CLASSIFIERS[name] || null;
}

module.exports = { CLASSIFIERS, lookup };
