'use strict';

/**
 * Canonical tool-name registry — the vocabulary of tools the boundary layer
 * recognizes, independent of any specific AI agent's protocol naming.
 *
 * Each adapter (claude-code, future cline, future cursor) maps its own
 * agent-specific tool names to canonical names. Inside the pipeline —
 * BoundaryEvent.toolName, dispatcher.NATIVE_HANDLERS, policy.tools — only
 * canonical names appear. Agent-specific names live in the adapter and in
 * the BoundaryEvent.raw payload.
 *
 * Stage 3 canonical names mirror MCP / common-sense conventions where
 * applicable (read_file, find_files, grep). Stage 4+ may add more.
 */

const CANONICAL = Object.freeze({
  READ_FILE:        'read_file',
  FIND_FILES:       'find_files',
  GREP:             'grep',
  TODO_WRITE:       'todo_write',
  TODO_READ:        'todo_read',
  SHELL_BASH:       'shell_bash',
  SHELL_POWERSHELL: 'shell_powershell',
});

const CANONICAL_NAMES = new Set(Object.values(CANONICAL));

// agentId → { agentToolName: canonicalName, ... }
const _agentMaps = {};

/**
 * Register an agent's name map. Called at adapter module load.
 * @param {string} agentId   e.g., 'claude-code'
 * @param {object} nameMap   keys = agent's tool names, values = canonical names
 */
function register(agentId, nameMap) {
  if (typeof agentId !== 'string' || !agentId)        throw new Error('register: agentId required');
  if (!nameMap || typeof nameMap !== 'object')        throw new Error('register: nameMap object required');
  const entry = {};
  for (const k of Object.keys(nameMap)) {
    const canonical = nameMap[k];
    if (!CANONICAL_NAMES.has(canonical)) {
      throw new Error(`register: ${agentId}.${k} maps to unknown canonical "${canonical}"`);
    }
    entry[k] = canonical;
  }
  _agentMaps[agentId] = entry;
}

/**
 * Translate one agent's tool name to its canonical name, if registered.
 * Returns null if the agent or name is unknown.
 */
function toCanonical(agentId, agentName) {
  const map = _agentMaps[agentId];
  return (map && map[agentName]) || null;
}

/**
 * Reverse: translate a canonical name back to a given agent's tool name.
 * Returns null if the agent or canonical is unknown to that agent.
 */
function toAgentName(agentId, canonicalName) {
  const map = _agentMaps[agentId];
  if (!map) return null;
  for (const k of Object.keys(map)) {
    if (map[k] === canonicalName) return k;
  }
  return null;
}

/**
 * Look up the canonical name across ALL registered agents. First match wins.
 * Used at policy-load time to translate `Read:` (Claude name) → `read_file`
 * so users who paste agent-native names in policy.yml still resolve correctly.
 *
 * Returns null if no agent has the name in its map.
 */
function firstCanonicalFor(name) {
  for (const agentId of Object.keys(_agentMaps)) {
    if (_agentMaps[agentId][name]) return _agentMaps[agentId][name];
  }
  return null;
}

function isCanonical(name) {
  return CANONICAL_NAMES.has(name);
}

/** Test helper: clear all registered agents. */
function _resetForTests() {
  for (const k of Object.keys(_agentMaps)) delete _agentMaps[k];
}

module.exports = {
  CANONICAL,
  CANONICAL_NAMES,
  register,
  toCanonical,
  toAgentName,
  firstCanonicalFor,
  isCanonical,
  _resetForTests,
};
