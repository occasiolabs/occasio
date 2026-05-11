'use strict';

/**
 * Policy loader — reads ~/.localfirst/policy.yml and returns a typed policy
 * object. Falls back to DEFAULT_POLICY when the file is missing or malformed.
 *
 * Stage 2 schema (intentionally minimal; Stage 3 will widen to rule lists):
 *
 *   version: 1
 *   block_secrets_in_tool_results: true   # BLOCK when scanner finds a secret
 *   block_requests_over_budget:    true   # BLOCK requests when session.cost ≥ budget
 *
 * Comments (#) and blank lines are ignored. No nesting, no lists, no flow
 * style — just `key: value` lines. Adding more keys does not change the
 * schema; unknown keys are silently ignored (forward-compatible).
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

/** Expand ~ and resolve to absolute path for policy file entries. */
function resolveConfigPath(p) {
  const expanded = p.startsWith('~') ? os.homedir() + p.slice(1) : p;
  return path.resolve(expanded);
}

// Default path can be overridden via LOCALFIRST_POLICY_FILE — used by the
// harness/redteam commands to point the proxy at a scratch policy.yml so
// the user's real ~/.localfirst/policy.yml is never read.
const DEFAULT_PATH = process.env.LOCALFIRST_POLICY_FILE
  || path.join(os.homedir(), '.localfirst', 'policy.yml');

// Default tool routing matches the pre-Stage-3 hardcoded behavior.
// Stage 3: keys are CANONICAL tool names (agent-agnostic). Adapters map
// their agent-specific names (Claude's "Read") to these canonical keys
// (`read_file`) when they emit BoundaryEvents.
const DEFAULT_TOOLS = Object.freeze({
  read_file:        Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'read-input-validator'  }),
  find_files:       Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'glob-input-validator'  }),
  grep:             Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'grep-input-validator'  }),
  todo_write:       Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'todo-write-validator' }),
  todo_read:        Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'todo-read-validator'  }),
  shell_bash:       Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'bash-allowlist'       }),
  shell_powershell: Object.freeze({ action: 'LOCAL', executor: 'native', classifier: 'powershell-allowlist' }),
});

const DEFAULT_POLICY = Object.freeze({
  version: 1,
  block_secrets_in_tool_results:  true,
  redact_secrets_in_tool_results: false,
  distill_tool_results:           false,
  block_requests_over_budget:     true,
  tools:                          DEFAULT_TOOLS,
  deny_paths:    Object.freeze([]),
  allow_paths:   Object.freeze([]),
  deny_patterns: Object.freeze([]),
});

/**
 * Parse a YAML subset string into an object.
 *
 * Supports:
 *   - Top-level `key: value` scalars (true/false/null/int/float/quoted/bare string)
 *   - One level of block-style nesting:
 *       parent:
 *         child: value
 *   - A second level of block-style nesting (used for `tools.<Name>.<field>`):
 *       parent:
 *         child:
 *           grandchild: value
 *   - Comments (`#`) and blank lines
 *
 * Not supported (reject silently): inline flow `{ ... }`, lists `- ...`,
 * tabs, multiline strings, anchors, aliases. Stage 3+ may extend.
 */
function parseValue(val) {
  if (val === '')               return true;       // bare key
  if (val === 'true')           return true;
  if (val === 'false')          return false;
  if (val === 'null')           return null;
  if (/^-?\d+$/.test(val))      return parseInt(val, 10);
  if (/^-?\d+\.\d+$/.test(val)) return parseFloat(val);
  const m = /^(['"])(.*)\1$/.exec(val);
  return m ? m[2] : val;
}

function parse(text) {
  const out = {};
  if (typeof text !== 'string') return out;

  // State: when we see a key with empty value at indent N, the next lines at
  // indent > N belong to that key as nested children. We track up to two
  // levels of block-nesting (L1 = direct child object, L2 = grandchild object).
  //
  // List support (ARCH-27): a sequence of `- item` lines under a top-level key
  // causes that key's value to become an array rather than a nested object.
  // l1Container / l1ContKey track the outer object and key so we can replace
  // the initially-created empty object with an array on the first `- item` line.
  let l1Parent    = null;   // the L1 nested object (or null)
  let l1Indent    = -1;     // indent of L1 entries (set on first child)
  let l1Container = null;   // outer object whose key holds l1Parent (for list replacement)
  let l1ContKey   = null;   // key in l1Container pointing to l1Parent
  let l2Parent    = null;   // the L2 nested object (or null)
  let l2Indent    = -1;     // indent of L2 entries (set on first grandchild)

  for (const rawLine of text.split('\n')) {
    let line = rawLine;
    const hash = line.indexOf('#');
    if (hash >= 0) line = line.slice(0, hash);
    if (!line.trim()) continue;

    const indent = (line.match(/^( *)/) || ['', ''])[1].length;
    const trimmed = line.trim();

    // List item: `- value` at the L1 indent level under a parent that declared
    // an empty value. Handled before the colon check because list values (e.g.
    // paths) may not contain a colon, or the colon may be inside the value.
    if (trimmed.startsWith('- ') && l1Container !== null && l1ContKey !== null) {
      if (l1Indent === -1) l1Indent = indent;
      if (indent === l1Indent) {
        const item = trimmed.slice(2).trim();
        if (item) {
          if (!Array.isArray(l1Container[l1ContKey])) {
            l1Container[l1ContKey] = [];
          }
          l1Container[l1ContKey].push(parseValue(item));
        }
        continue;
      }
    }

    const colon = trimmed.indexOf(':');
    if (colon < 0) continue;
    const key = trimmed.slice(0, colon).trim();
    const val = trimmed.slice(colon + 1).trim();
    if (!key) continue;

    if (indent === 0) {
      // Top-level
      if (val === '') {
        out[key]    = {};
        l1Container = out;
        l1ContKey   = key;
        l1Parent    = out[key];
        l1Indent    = -1;
        l2Parent    = null;
        l2Indent    = -1;
      } else {
        out[key]    = parseValue(val);
        l1Parent    = null;
        l1Container = null;
        l1ContKey   = null;
        l2Parent    = null;
      }
    } else if (l1Parent !== null) {
      if (l1Indent === -1) l1Indent = indent;

      if (indent === l1Indent) {
        // L1 entry
        if (val === '') {
          l1Parent[key] = {};
          l2Parent  = l1Parent[key];
          l2Indent  = -1;
        } else {
          l1Parent[key] = parseValue(val);
          l2Parent = null;
        }
      } else if (indent > l1Indent && l2Parent !== null) {
        if (l2Indent === -1) l2Indent = indent;
        if (indent === l2Indent) {
          l2Parent[key] = parseValue(val);
        }
        // Deeper levels ignored.
      }
    }
  }
  return out;
}

// Per-tool entry validation. `action` must be PASS, LOCAL, or TRANSFORM.
// For TRANSFORM, `transform` (a non-empty string) names the operation and is
// required — entries missing it are silently dropped. Returns null for any
// invalid entry so callers can safely skip it.
const VALID_ACTIONS = new Set(['PASS', 'LOCAL', 'TRANSFORM']);
function normalizeToolEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const action = raw.action;
  if (!VALID_ACTIONS.has(action)) return null;
  // max_output_tokens: per-tool context budget. Positive integer or null.
  // Applied AFTER any transform/distill as a final clip before the tool result
  // re-enters the model's next request. Same field on every action so a LOCAL
  // tool with no transform can still carry a budget.
  let maxOutputTokens = null;
  if (raw.max_output_tokens !== undefined && raw.max_output_tokens !== null) {
    const n = Number(raw.max_output_tokens);
    if (Number.isFinite(n) && Number.isInteger(n) && n > 0) maxOutputTokens = n;
  }
  if (action === 'TRANSFORM') {
    if (typeof raw.transform !== 'string' || !raw.transform.trim()) return null;
    const out = { action, transform: raw.transform };
    if (typeof raw.reason === 'string') out.reason = raw.reason;
    if (maxOutputTokens !== null) out.max_output_tokens = maxOutputTokens;
    return Object.freeze(out);
  }
  const out = { action };
  if (typeof raw.executor   === 'string') out.executor   = raw.executor;
  if (typeof raw.classifier === 'string') out.classifier = raw.classifier;
  if (typeof raw.reason     === 'string') out.reason     = raw.reason;
  if (maxOutputTokens !== null) out.max_output_tokens = maxOutputTokens;
  return Object.freeze(out);
}

/**
 * Merge a parsed policy onto the defaults, validating types. Anything missing
 * or wrong-type falls back to the default. Returns a frozen object.
 *
 * Tools merge semantics: if the parsed policy has a `tools:` block, it
 * REPLACES the defaults entirely (no per-key fallback). This is the simplest
 * mental model: the user's tools block is authoritative when present.
 * Stage 4+ can introduce per-tool override semantics if needed.
 */
function normalize(parsed) {
  const merged = { ...DEFAULT_POLICY };
  if (typeof parsed.version === 'number') merged.version = parsed.version;
  if (typeof parsed.block_secrets_in_tool_results === 'boolean') {
    merged.block_secrets_in_tool_results = parsed.block_secrets_in_tool_results;
  }
  if (typeof parsed.redact_secrets_in_tool_results === 'boolean') {
    merged.redact_secrets_in_tool_results = parsed.redact_secrets_in_tool_results;
  }
  if (typeof parsed.distill_tool_results === 'boolean') {
    merged.distill_tool_results = parsed.distill_tool_results;
  }
  if (typeof parsed.block_requests_over_budget === 'boolean') {
    merged.block_requests_over_budget = parsed.block_requests_over_budget;
  }
  // deny_paths / allow_paths: arrays of pre-resolved absolute path strings.
  // Invalid entries emit a stderr warning and are skipped — silent drops of
  // governance entries are a security gap, not a minor inconvenience.
  for (const listKey of ['deny_paths', 'allow_paths']) {
    if (Array.isArray(parsed[listKey])) {
      const resolved = [];
      parsed[listKey].forEach((entry, i) => {
        if (typeof entry !== 'string' || !entry.trim()) {
          process.stderr.write(`[LocalFirst] policy.yml: ${listKey}[${i}] — not a string, entry skipped\n`);
          return;
        }
        resolved.push(resolveConfigPath(entry.trim()));
      });
      merged[listKey] = Object.freeze(resolved);
    }
  }

  // deny_patterns: object of label → regex string, compiled at load time.
  if (parsed.deny_patterns && typeof parsed.deny_patterns === 'object' && !Array.isArray(parsed.deny_patterns)) {
    const patterns = [];
    for (const [label, rawPattern] of Object.entries(parsed.deny_patterns)) {
      if (typeof rawPattern !== 'string') {
        process.stderr.write(`[LocalFirst] policy.yml: deny_patterns.${label} — value must be a string, entry skipped\n`);
        continue;
      }
      try {
        const regex = new RegExp(rawPattern);
        patterns.push(Object.freeze({ label, regex }));
      } catch (e) {
        process.stderr.write(`[LocalFirst] policy.yml: deny_patterns.${label} — invalid RegExp "${rawPattern}", entry skipped\n`);
      }
    }
    merged.deny_patterns = Object.freeze(patterns);
  }

  if (parsed.tools && typeof parsed.tools === 'object') {
    // Lazy-require the registry to avoid an unconditional dependency at
    // module load (loader.js is imported by other code paths that don't
    // need the registry).
    let toolNames;
    try { toolNames = require('../core/tool-names'); } catch {}
    const tools = {};
    for (const name of Object.keys(parsed.tools)) {
      const entry = normalizeToolEntry(parsed.tools[name]);
      if (!entry) continue;
      // Stage 3: keys are canonical. If the user wrote an agent-specific
      // alias (e.g., 'Read'), translate to canonical. Unknown names are
      // kept as-is (no agent claims them; lookup will miss safely).
      let key = name;
      if (toolNames && !toolNames.isCanonical(name)) {
        const canonical = toolNames.firstCanonicalFor(name);
        if (canonical) key = canonical;
      }
      tools[key] = entry;
    }
    merged.tools = Object.freeze(tools);
  }
  return Object.freeze(merged);
}

let _cached     = null;
let _cachedPath = null;
let _cachedMtime = null;  // mtimeMs when the file was last read (null = file was absent)
let _override   = null;   // tests-only: forces load() to return this regardless of path

// v0.6.6: policy hash + change-callback. The hash is a SHA-256 of the
// raw policy file bytes (or an empty string when absent), recomputed on
// every cache miss. It is what lands in the audit log's policy_loaded row.
//
// Hashing the file bytes (not the normalized object) keeps the contract
// predictable: byte-identical files produce identical hashes; comments
// and whitespace count, just like they do for the YAML editor. The
// audit row is therefore directly traceable to a specific file content
// the corp can keep under source control.
let _cachedHash    = null;
let _changeListeners = [];

function computePolicyHash(filePath) {
  try {
    const bytes = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(bytes).digest('hex');
  } catch {
    // Absent/unreadable file → all-zeros sentinel so the listener still
    // fires once on first load, distinguishing "no file" from "no listener".
    return '0'.repeat(64);
  }
}

/**
 * Register a callback that fires whenever load() observes a transition
 * to a new policy hash. Fires once on first load (cold cache), and once
 * per subsequent edit (mtime change → re-read → new hash).
 *
 * The callback receives:
 *   { hash, path, version, source }
 * where `source` is 'user' if the file existed, 'default' otherwise.
 *
 * Used by the proxy and the MCP server to emit a `policy_loaded` audit
 * row exactly when a change is observed (not on every load() call).
 */
function onPolicyChange(cb) {
  if (typeof cb === 'function') _changeListeners.push(cb);
}

function _firePolicyChange(filePath, policy, hash, fileWasPresent) {
  for (const cb of _changeListeners) {
    try {
      cb({
        hash,
        path:    filePath,
        version: policy && typeof policy.version === 'number' ? policy.version : 1,
        source:  fileWasPresent ? 'user' : 'default',
      });
    } catch (e) {
      // Listener crash must not break the proxy — surface to stderr only.
      try { process.stderr.write(`[localfirst] policy-change listener threw: ${e.message}\n`); } catch {}
    }
  }
}

/**
 * Load ~/.localfirst/policy.yml (or another path), with mtime-based reload.
 *
 * On every call we do one `statSync` to read the file's modification time.
 * If the mtime matches the last read — or the file was absent then and is
 * still absent now — the cached policy is returned immediately without any
 * file I/O.  If the mtime changed, the file appeared, or the file was
 * deleted, we re-read and re-normalize.  Deleted/unreadable files fall back
 * to DEFAULT_POLICY exactly as before.
 *
 * Choosing statSync over fs.watch:
 *   - No persistent watcher to clean up; no background thread keeping the
 *     process alive after the proxy stops.
 *   - Deterministic: the reload happens on the very next load() call after
 *     the file changes, not asynchronously via an event queue.
 *   - The stat syscall is sub-millisecond; load() is called once per tool
 *     call (not in a hot loop), so the overhead is negligible.
 *
 * @param {string} [filePath] override path (used in tests)
 * @returns {object} frozen policy object
 */
function load(filePath = DEFAULT_PATH) {
  if (_override) return _override;

  // Read the current mtime. null means the file is absent or unreadable.
  let currentMtime = null;
  try { currentMtime = fs.statSync(filePath).mtimeMs; } catch { /* absent */ }

  // Cache hit: same path and mtime unchanged (covers absent→absent as null===null).
  if (_cached && _cachedPath === filePath && _cachedMtime === currentMtime) {
    return _cached;
  }

  // Cache miss: file changed, appeared, or disappeared — re-read.
  let parsed = {};
  let fileWasPresent = false;
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    parsed = parse(text);
    fileWasPresent = true;
  } catch { /* file missing or unreadable → defaults */ }
  _cached      = normalize(parsed);
  _cachedPath  = filePath;
  _cachedMtime = currentMtime;

  // v0.6.6: compute the file-bytes hash and fire the change callback iff
  // the hash transitioned. This is the only place that observes policy
  // changes, so it is also the only place that triggers policy_loaded
  // audit rows. Idempotent by construction.
  const newHash = computePolicyHash(filePath);
  if (newHash !== _cachedHash) {
    _cachedHash = newHash;
    _firePolicyChange(filePath, _cached, newHash, fileWasPresent);
  }

  return _cached;
}

/**
 * Test helper: set an override that load() returns regardless of path.
 * Pass null to clear. Production code never calls this.
 */
function _setOverrideForTests(policyObj) {
  _override = policyObj ? normalize(policyObj) : null;
}

/**
 * Reset the cached policy. Used by tests; not normally called by production.
 */
function _resetCache() {
  _cached            = null;
  _cachedPath        = null;
  _cachedMtime       = null;
  _override          = null;
  _cachedHash        = null;
  _changeListeners   = [];
}

module.exports = {
  DEFAULT_PATH,
  DEFAULT_POLICY,
  parse,
  normalize,
  normalizeToolEntry,
  load,
  computePolicyHash,
  onPolicyChange,
  _resetCache,
  _setOverrideForTests,
};
