'use strict';

/**
 * JsonlAuditor — appends one tamper-evident record per (event, decision, result)
 * tuple to a JSONL file.
 *
 * Each row carries:
 *   prev_hash  — SHA-256 hex of the previous row (GENESIS sentinel for first row)
 *   hash       — SHA-256 hex of JSON.stringify(rowWithoutHash)
 *
 * The chain is continuous across process restarts: on startup the auditor reads
 * the last hash from the existing file. Legacy rows (pre-hash-chain, no hash
 * field) are preserved as-is; the chain starts at GENESIS from the first
 * hash-bearing row.
 *
 * Verification: see src/audit/verifier.js / `occasio audit verify`.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const { normalizeToolInputsForAudit } = require('./input-normalizer');
const { gitStateDigest } = require('../git/state');

const DEFAULT_LOG = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');

// Sentinel prev_hash for the first row in a chain (64 zero hex digits).
const GENESIS = '0'.repeat(64);

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// Hash a row object that already contains prev_hash but not hash.
// Field order must be stable (guaranteed by the explicit object literal in record()).
function computeHash(rowWithoutHash) {
  return sha256hex(JSON.stringify(rowWithoutHash));
}

// Default tail-read window size (bytes). Large enough to contain several full
// audit rows on any plausible workload; small enough that bootstrap on a
// 100k-event log stays sub-50ms.
const TAIL_READ_BYTES = 64 * 1024;

// Read the trailing window of a file. Returns the decoded string (utf8) along
// with a flag indicating whether the read started mid-file (i.e. the first
// line in the returned buffer may be truncated).
function readTail(filePath, bytes = TAIL_READ_BYTES) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const { size } = fs.fstatSync(fd);
    const start = Math.max(0, size - bytes);
    const len   = size - start;
    const buf   = Buffer.alloc(len);
    if (len > 0) fs.readSync(fd, buf, 0, len, start);
    return { content: buf.toString('utf8'), truncated: start > 0 };
  } finally {
    fs.closeSync(fd);
  }
}

// Outcome codes for scanning the tail. A [code, value] tuple is used rather
// than an object literal so that field-name tokens used by the audit row
// schema (see test-interceptor.js §32) cannot appear earlier in this file
// than the row builder in record() below.
//   ['hash',    hexString]         found a valid hash-bearing row
//   ['genesis']                    file empty / legacy-only / missing
//   ['corrupt', detailString]      last line invalid JSON, no fallback row
function scanTailForPrevHash(filePath, bytes = TAIL_READ_BYTES) {
  let content, truncated;
  try {
    ({ content, truncated } = readTail(filePath, bytes));
  } catch {
    return ['genesis'];
  }
  if (!content) return ['genesis'];

  // Split into raw lines (no filter) so we can detect a partial trailing line
  // separately from intentionally-empty lines. A well-formed JSONL ends in
  // '\n'; if the last element after split is non-empty, the file was cut
  // mid-write.
  const raw = content.split('\n');
  const lastFragment = raw[raw.length - 1];
  const lines = raw.filter(Boolean);
  if (lines.length === 0) return ['genesis'];

  // If we read from offset 0, the first line is authoritative. If we read
  // from mid-file, the first line in the window may be a fragment of a row
  // truncated by the window — drop it so we never treat a fragment as legacy.
  const startIdx = truncated && raw[0] === lines[0] ? 1 : 0;
  const lastNonEmptyIdx = lines.length - 1;

  // Detect a partial trailing line: file does not end in '\n' AND the last
  // line fails to JSON.parse. A complete row that *happens* to be the final
  // entry is fine — its trailing newline guarantees lastFragment === ''.
  const trailingPartial = lastFragment !== '' && (() => {
    try { JSON.parse(lines[lastNonEmptyIdx]); return false; } catch { return true; }
  })();

  // Walk lines in reverse to find the most recent valid hash-bearing row.
  // Skip the partial trailing line if present.
  const scanFrom = trailingPartial ? lastNonEmptyIdx - 1 : lastNonEmptyIdx;
  for (let i = scanFrom; i >= startIdx; i--) {
    try {
      const row = JSON.parse(lines[i]);
      if (typeof row.hash === 'string' && row.hash.length === 64) {
        return ['hash', row.hash];
      }
    } catch {
      // Mid-window JSON.parse failure: a truly corrupt earlier row. We do not
      // attempt to recover past it here — if no valid hash row exists in the
      // remaining window, fall through to the corrupt/genesis decision below.
    }
  }

  // No hash row found in the window. If we observed a partial trailing line
  // AND the window contains no complete hash row, the chain is in an
  // ambiguous state — caller must decide whether to fail hard or fall back
  // to GENESIS (only safe if the file truly contains zero prior chain rows).
  if (trailingPartial) {
    return ['corrupt', 'partial trailing line, no recoverable prev_hash in tail window'];
  }
  return ['genesis'];
}

// Public: returns the most recent hash to chain from, or GENESIS.
// Throws AuditCorruptError when the file's last line is JSON-broken and no
// earlier hash-bearing row exists in the tail window — this prevents the
// silent tamper gap where a partial write would otherwise restart the chain.
function loadPrevHash(filePath, opts = {}) {
  const { tailBytes = TAIL_READ_BYTES, failHard = true } = opts;
  // Missing file → genesis (initial bootstrap).
  if (!fs.existsSync(filePath)) return GENESIS;
  const [code, detail] = scanTailForPrevHash(filePath, tailBytes);
  if (code === 'hash')    return detail;
  if (code === 'genesis') return GENESIS;
  // code === 'corrupt'
  if (!failHard) {
    process.stderr.write(`[occasio audit] WARNING: ${filePath}: ${detail}\n`);
    return GENESIS;
  }
  const err = new Error(
    `Audit log corrupt at ${filePath}: ${detail}. ` +
    `Run \`occasio audit repair --file ${filePath}\` to truncate the partial trailing line.`
  );
  err.code = 'AUDIT_CORRUPT';
  throw err;
}

/**
 * Build an auditor that writes to the given file (default: pipeline-events.jsonl).
 * Returns { record(event, decision, result), file }.
 *
 * v0.6.4 contract change: record() returns { ok: true } on a successful append,
 * or { ok: false, error, droppedRow } if the append throws. Callers (pipeline)
 * promote ok=false into AuditWriteError so the proxy can fail-closed for
 * governance — a missing audit row must not coexist with a successful cloud
 * call. prevHash is only advanced on a successful append, keeping the
 * in-memory chain consistent with what is on disk if the proxy is restarted.
 */
function createAuditor(filePath = DEFAULT_LOG, opts = {}) {
  // lock=true wraps each append in a proper-lockfile lockSync/unlockSync pair
  // and re-reads prev_hash from disk inside the lock. Default ON: Occasio's
  // own architecture spawns concurrent writers against the default chain file
  // (HTTP proxy in bin/occasio.js + MCP server in bin/occasio-mcp.js), so a
  // no-lock default produces silent race-condition chain breaks on real user
  // workloads. The single-digit-ms I/O cost is mandatory for the tamper-
  // evidence guarantee to hold. Opt out only for tight-loop unit tests that
  // genuinely have no concurrent writer.
  const { lock = true } = opts;
  let lockfile = null;
  if (lock) {
    // proper-lockfile is a regular dependency (see package.json); the
    // try/catch here is belt-and-braces for unusual install states.
    try { lockfile = require('proper-lockfile'); }
    catch (e) {
      throw new Error(`createAuditor requires proper-lockfile: ${e.message}`);
    }
    // The lockfile target must exist before lockSync can create its companion
    // directory marker. Touch it.
    if (!fs.existsSync(filePath)) {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, '');
    }
  }

  try { fs.mkdirSync(path.dirname(filePath), { recursive: true }); }
  catch { /* directory already exists, or unwritable — surface on first append */ }

  let prevHash = loadPrevHash(filePath);

  function withLock(fn) {
    if (!lock) return fn();
    // proper-lockfile uses mkdir(2) for atomicity; staleness keeps the lock
    // self-healing across crashes. realpath:false avoids extra syscalls for
    // a path we already control.
    // proper-lockfile's sync API forbids `retries` — it must busy-loop on
     // EEXIST itself. Keep stale-cleanup so a crashed writer cannot freeze
     // siblings forever.
    let release = null;
    const start = Date.now();
    while (release === null) {
      try {
        release = lockfile.lockSync(filePath, { stale: 10000, realpath: false });
      } catch (e) {
        if (e.code !== 'ELOCKED') throw e;
        if (Date.now() - start > 10000) throw e;
        // tight spin — node has no sleepSync; a microtask burst is fine for
        // contention durations expected here (single-digit ms per writer)
        const until = Date.now() + 2;
        while (Date.now() < until) { /* spin */ }
      }
    }
    // Inside the lock we MUST re-read prev_hash — another process may have
    // appended since we last advanced it. Without this, two concurrent
    // writers would produce two rows with the same prev_hash → chain break.
    prevHash = loadPrevHash(filePath, { failHard: false });
    try { return fn(); }
    finally { try { release(); } catch { /* lock already released by stale-timeout reaper */ } }
  }

  function record(event, decision, result) {
    if (!event || !decision) return { ok: true };
    return withLock(() => recordInner(event, decision, result));
  }

  function recordInner(event, decision, result) {
    // Field order is explicit and must remain stable — computeHash depends on it.
    // The Python walker in docs/audit_walker.py mirrors this order; any change
    // here without updating that walker breaks independent verifiability.
    const row = {
      audit_schema: 1,
      ts:            event.timestamp,
      event_id:      event.id,
      session_id:    event.sessionId,
      run_id:        event.runId,
      agent:         event.agent,
      protocol:      event.protocol,
      direction:     event.direction,
      kind:          event.kind,
      tool_name:     event.toolName,
      tool_inputs:   normalizeToolInputsForAudit(event.toolName, event.toolInput),
      action:        decision.action,
      reason:        decision.reason,
      policy_source: decision.policySource,
      executor:      decision.executor,
      transform:     decision.transform,
      result_kind:   result?.passThrough ? 'pass' :
                     result?.blocked     ? 'block' :
                     result?.transformed ? 'transform' :
                     result?.exitCode !== undefined ? 'local' : 'unknown',
      exit_code:          typeof result?.exitCode === 'number' ? result.exitCode : undefined,
      secrets_redacted:   result?.secretsRedacted?.length || undefined,
      distilled:          result?.distilled || undefined,
      tokens_saved:       result?.savedTokens || undefined,
      // Identity-gate enrichment (v2): present only for identity decisions
      // (decision.identity tagged by the engine); {} otherwise, so non-identity
      // rows are byte-for-byte unchanged. Additive + walker-safe (hash stays last).
      ...identityAuditFields(event, decision, result),
      // Secret-redaction enrichment: present only for redaction rows (best-effort
      // backstop). Mutually exclusive with identity fields (a redaction is a
      // TRANSFORM, not a BLOCK). Records labels + count, never the secret value.
      ...secretRedactionFields(decision, result),
      prev_hash:     prevHash,
    };
    row.hash = computeHash(row);
    try {
      fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    } catch (e) {
      // Do NOT advance prevHash — a dropped row must not poison the chain.
      // The dropped row is returned so the caller can surface it to stderr
      // before aborting the proxy.
      return { ok: false, error: e, droppedRow: row };
    }
    prevHash = row.hash;
    return { ok: true };
  }

  /**
   * v0.6.6: write a synthetic `policy_loaded` row.
   *
   * The row uses the same field order as record() so the canonical
   * serialization (and therefore the Python independent walker) does not
   * change. Field semantics for this row kind:
   *
   *   kind:        'policy_loaded'
   *   tool_name:   'policy_loaded'        (placeholder; not a real tool)
   *   tool_inputs: { policy_hash, policy_path, version }
   *   action:      'INFO'                 (not a Decision action)
   *   reason:      'policy-loaded'
   *   policy_source: 'user' | 'default'
   *   result_kind: omitted                (no Result, per v0.6.6 design note)
   *
   * Returns { ok: true } on success; { ok: false, error, droppedRow } on
   * append failure, mirroring record()'s contract so the caller can
   * propagate AuditWriteError uniformly.
   */
  function recordPolicyLoaded(args) {
    return withLock(() => recordPolicyLoadedInner(args));
  }

  /**
   * Write a synthetic `git_state` row binding a run to the concrete repository
   * state at a lifecycle phase ('run_start' | 'run_end').
   *
   * Like recordPolicyLoaded, this uses record()'s field order so the canonical
   * serialization (and the Python independent walker) needs no change — the
   * git facts live inside tool_inputs. Semantics for this row kind:
   *
   *   kind:        'git_state'
   *   tool_name:   'git_state'
   *   tool_inputs: { phase, cwd, digest, ...capturedState }
   *   action:      'INFO'              (not a Decision action)
   *   reason:      'git-state'
   *
   * Returns { ok: true } on success; { ok: false, error, droppedRow } on append
   * failure, mirroring record()'s contract.
   */
  function recordGitState(args) {
    return withLock(() => recordGitStateInner(args));
  }

  /**
   * Write a synthetic `limit_exceeded` row when a per-round volume cap
   * (policy.limits) is hit and the run is halted. Mirrors recordGitState's
   * field order / append+hash contract so the canonical serialization (and the
   * Python walker) need no change. Semantics for this row kind:
   *
   *   kind:        'limit_exceeded'
   *   tool_name:   'limit_exceeded'
   *   tool_inputs: { limit, max, actual, round, decision: 'block' }
   *   action:      'BLOCK'      (it IS an enforcement decision)
   *   reason:      'limit-exceeded'
   *
   * Returns { ok: true } / { ok: false, error, droppedRow } like record().
   */
  function recordLimitExceeded(args) {
    return withLock(() => recordLimitExceededInner(args));
  }

  /**
   * Record a per-request accounting row (kind:"request").
   *
   * Phase-2 of the truth-source unification: every cloud-bound or
   * intercepted request writes ONE slim row into the hash chain alongside
   * the existing logs/*.jsonl write, so the chain becomes the authoritative
   * source for cost/tokens — not just behavior. The row deliberately omits
   * the request body, files-touched list, and per-tool detail: tool-level
   * facts are already attested as separate kind:"tool_call" rows and can
   * be re-joined by run_id.
   *
   * Field order below is the canonical serialization contract and MUST
   * remain stable. Adding new fields is only allowed at the END (before
   * prev_hash), and only with a new audit_schema bump.
   *
   * Accepts the same `entry` shape used by writeLog/updateSession.
   * Returns { ok: true } on success; { ok: false, error, droppedRow } on
   * append failure, mirroring record()'s contract.
   */
  function recordRequest(entry) {
    if (!entry) return { ok: true };
    return withLock(() => recordRequestInner(entry));
  }

  function recordRequestInner(entry) {
    const row = {
      audit_schema:         1,
      ts:                   entry.iso || new Date().toISOString(),
      event_id:             crypto.randomUUID(),
      session_id:           entry.run_id,
      run_id:               entry.run_id,
      agent:                'occasio',
      protocol:             'anthropic-http',
      direction:            'outbound',
      kind:                 'request',
      event_type:           entry.event_type || (entry.intercepted ? 'local_only' : 'cloud_sent'),
      model:                entry.model,
      cwd:                  entry.cwd,
      input_tokens:         entry.input_tokens         || 0,
      output_tokens:        entry.output_tokens        || 0,
      cache_read_tokens:    entry.cache_read_tokens    || 0,
      cache_write_tokens:   entry.cache_write_tokens   || 0,
      cost:                 entry.cost                 || 0,
      cache_savings:        entry.cache_savings        || 0,
      lao_tokens_saved:     entry.lao_tokens_saved     || 0,
      lao_cost_saved:       entry.lao_cost_saved       || 0,
      distill_tokens_saved: entry.distill_tokens_saved || 0,
      distill_cost_saved:   entry.distill_cost_saved   || 0,
      tools_attempted:      entry.tools_attempted      || 0,
      tools_local_count:    entry.tools_local_count    || 0,
      tools_mcp_count:      entry.tools_mcp_count      || 0,
      prev_hash:            prevHash,
    };
    row.hash = computeHash(row);
    try {
      fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    } catch (e) {
      return { ok: false, error: e, droppedRow: row };
    }
    prevHash = row.hash;
    return { ok: true };
  }

  function recordPolicyLoadedInner({ hash, path: policyPath, version, source }) {
    const row = {
      audit_schema: 1,
      ts:            new Date().toISOString(),
      event_id:      crypto.randomUUID(),
      session_id:    undefined,
      run_id:        undefined,
      agent:         'occasio',
      protocol:      'internal',
      direction:     'inbound',
      kind:          'policy_loaded',
      tool_name:     'policy_loaded',
      tool_inputs:   {
        policy_hash: hash,
        policy_path: policyPath,
        version:     typeof version === 'number' ? version : 1,
      },
      action:        'INFO',
      reason:        'policy-loaded',
      policy_source: source === 'user' ? 'user' : 'default',
      executor:      undefined,
      transform:     undefined,
      // result_kind intentionally omitted: a policy_loaded event has no
      // dispatcher Result. Confirmed by the v0.6.6 design note in
      // docs/AUDIT.md §1 — the row format spec marks result_kind absent
      // for kind=policy_loaded rows.
      exit_code:        undefined,
      secrets_redacted: undefined,
      distilled:        undefined,
      tokens_saved:     undefined,
      prev_hash:        prevHash,
    };
    row.hash = computeHash(row);
    try {
      fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    } catch (e) {
      return { ok: false, error: e, droppedRow: row };
    }
    prevHash = row.hash;
    return { ok: true };
  }

  function recordGitStateInner({ phase, runId, sessionId, cwd, state } = {}) {
    const s = state || {};
    const row = {
      audit_schema: 1,
      ts:            new Date().toISOString(),
      event_id:      crypto.randomUUID(),
      session_id:    sessionId,
      run_id:        runId,
      agent:         'occasio',
      protocol:      'internal',
      direction:     'inbound',
      kind:          'git_state',
      tool_name:     'git_state',
      tool_inputs:   {
        phase:           phase === 'run_end' ? 'run_end' : 'run_start',
        cwd:             cwd,
        is_repo:         !!s.is_repo,
        head:            s.head || null,
        branch:          s.branch || null,
        dirty:           !!s.dirty,
        changed_files:   Array.isArray(s.changed_files) ? s.changed_files : [],
        untracked_files: Array.isArray(s.untracked_files) ? s.untracked_files : [],
        diff_hash:       s.diff_hash || null,
        digest:          gitStateDigest(s),
      },
      action:        'INFO',
      reason:        'git-state',
      policy_source: undefined,
      executor:      undefined,
      transform:     undefined,
      exit_code:        undefined,
      secrets_redacted: undefined,
      distilled:        undefined,
      tokens_saved:     undefined,
      prev_hash:        prevHash,
    };
    row.hash = computeHash(row);
    try {
      fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    } catch (e) {
      return { ok: false, error: e, droppedRow: row };
    }
    prevHash = row.hash;
    return { ok: true };
  }

  function recordLimitExceededInner({ runId, sessionId, kind, max, actual, round } = {}) {
    const row = {
      audit_schema: 1,
      ts:            new Date().toISOString(),
      event_id:      crypto.randomUUID(),
      session_id:    sessionId,
      run_id:        runId,
      agent:         'occasio',
      protocol:      'internal',
      direction:     'inbound',
      kind:          'limit_exceeded',
      tool_name:     'limit_exceeded',
      tool_inputs:   {
        limit:    kind,
        max:      typeof max === 'number' ? max : null,
        actual:   typeof actual === 'number' ? actual : null,
        round:    typeof round === 'number' ? round : null,
        decision: 'block',
      },
      action:        'BLOCK',
      reason:        'limit-exceeded',
      policy_source: undefined,
      executor:      undefined,
      transform:     undefined,
      exit_code:        undefined,
      secrets_redacted: undefined,
      distilled:        undefined,
      tokens_saved:     undefined,
      prev_hash:        prevHash,
    };
    row.hash = computeHash(row);
    try {
      fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    } catch (e) {
      return { ok: false, error: e, droppedRow: row };
    }
    prevHash = row.hash;
    return { ok: true };
  }

  return { record, recordPolicyLoaded, recordRequest, recordGitState, recordLimitExceeded, file: filePath };
}

// ── Identity-gate audit enrichment (v2) ─────────────────────────────────────
// Defined below createAuditor (function declarations are hoisted) so the
// field-name strings inside these helpers do not shadow recordInner's row
// literal in the AUDIT.md field-order drift guard.
//
// Resolve the human the AI agent acts on behalf of. Read once from
// ~/.occasio/identity.json ({ id } | { delegator } | { user }); fall back to
// the OS username. Cached so the identity path adds no per-event file I/O.
let _delegatorCache;
function resolveDelegator() {
  if (_delegatorCache !== undefined) return _delegatorCache;
  let delegatorId = null;
  try {
    const raw = fs.readFileSync(path.join(os.homedir(), '.occasio', 'identity.json'), 'utf8');
    const j = JSON.parse(raw);
    delegatorId = j.id || j.delegator || j.user || null;
  } catch { /* no identity file → fall back to OS user */ }
  if (!delegatorId) {
    try { delegatorId = os.userInfo().username; } catch { delegatorId = 'unknown'; }
  }
  _delegatorCache = { type: 'human', id: delegatorId };
  return _delegatorCache;
}

/**
 * Build the additive identity-gate fields for an audit row, or {} when the
 * decision is not an identity-gate decision (tagged by the engine via
 * `decision.identity`). All field names are in-toto-predicate compatible so a
 * future predicate export is a projection, not a migration.
 *
 * enforcement_point is always 'proxy' here: this row is written from the
 * proxy's in-loop BLOCK. coverage is 'enforced' because the BLOCK kept the
 * tool_use inside Occasio's loop (the command never reached the agent). A
 * future hook enforcement point would set these differently.
 */
function identityAuditFields(event, decision, result) {
  const idy = decision && decision.identity;
  if (!idy) return {};
  const command = (event.toolInput && typeof event.toolInput.command === 'string')
    ? event.toolInput.command : '';
  const approvalRequired = !!(decision.approval_required || (result && result.approval_required));
  return {
    event_type: idy.event_type,
    // High-signal: an enforced deny / approval gate. Separates these from the
    // chatty best-effort secret_redacted rows when scanning the chain by eye.
    severity: 'high',
    actor: {
      type:        event.actorType || 'ai_agent',
      id:          event.agent || null,
      session_id:  event.sessionId || null,
      trust_level: event.trustLevel || 'untrusted',
    },
    delegator: event.delegator || resolveDelegator(),
    tool: {
      type:         'shell',
      name:         event.toolName,
      raw_command:  command,
      // Same canonical hash the approval store keys on, so a reviewer can join
      // an audit row to its approval token.
      command_hash: command ? require('../policy/command-normalize').commandHash(command) : null,
    },
    identity_requested: {
      type:         idy.identity_type || null,
      target_class: idy.target_class || 'unknown',
      risk:         idy.risk || null,
    },
    classification: {
      action:       idy.classification || null,
      reason:       idy.classify_reason || null,
      matched_rule: idy.matched_rule || null,
    },
    policy_decision: {
      decision:    decision.action,
      reason:      decision.reason,
      policy_name: 'identity-gate',
    },
    approval:          approvalRequired ? { state: 'pending', scope: null } : null,
    enforcement_point: 'proxy',
    coverage:          'enforced',
  };
}

/**
 * Build the additive secret-redaction fields, or {} when the row is not a
 * secret redaction. Fires for both redaction streams: path-1 (the dispatcher's
 * redact-secrets TRANSFORM on a tool result) and path-2 (outbound redaction of
 * an agent-injected tool_result). A redaction is a best-effort DETECTOR, not an
 * enforced gate — so coverage is 'best-effort' and severity 'low', keeping it
 * machine- and eye-separable from the high-signal enforced deny/approval rows.
 *
 * NEVER records the secret value — only labels (which detector matched) and a
 * count. The redacted bytes live in the tool_result, not the audit row.
 */
function secretRedactionFields(decision, result) {
  const isRedact = (decision && typeof decision.transform === 'string' && /redact-secrets/.test(decision.transform)) ||
                   (result && Array.isArray(result.secretsRedacted) && result.secretsRedacted.length > 0);
  if (!isRedact) return {};
  const count = (result && Array.isArray(result.secretsRedacted)) ? result.secretsRedacted.length : 0;
  if (count === 0) return {};
  const labels = (result && Array.isArray(result.secretLabels)) ? result.secretLabels : undefined;
  return {
    event_type:          'secret_redacted',
    severity:            'low',
    secret_redacted_count: count,
    ...(labels && labels.length ? { secret_labels: labels } : {}),
    enforcement_point:   'proxy',
    coverage:            'best-effort',
  };
}

module.exports = {
  createAuditor,
  DEFAULT_LOG,
  GENESIS,
  computeHash,
  loadPrevHash,
  scanTailForPrevHash,
  TAIL_READ_BYTES,
};
