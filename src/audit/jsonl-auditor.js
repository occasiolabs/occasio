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
 * Verification: see src/audit/verifier.js / `localfirst audit verify`.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const { normalizeToolInputsForAudit } = require('./input-normalizer');

const DEFAULT_LOG = path.join(os.homedir(), '.localfirst', 'pipeline-events.jsonl');

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

// Scan an existing file in reverse for the most recent hash value.
// Returns GENESIS when the file is empty, missing, or contains only legacy rows.
function loadPrevHash(filePath) {
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return GENESIS; }
  const lines = content.split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const row = JSON.parse(lines[i]);
      if (typeof row.hash === 'string' && row.hash.length === 64) return row.hash;
    } catch {}
  }
  return GENESIS;
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
function createAuditor(filePath = DEFAULT_LOG) {
  try { fs.mkdirSync(path.dirname(filePath), { recursive: true }); } catch {}

  let prevHash = loadPrevHash(filePath);

  function record(event, decision, result) {
    if (!event || !decision) return { ok: true };
    // Field order is explicit and must remain stable — computeHash depends on it.
    // The Python walker in docs/audit_walker.py mirrors this order; any change
    // here without updating that walker breaks independent verifiability.
    const row = {
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
  function recordPolicyLoaded({ hash, path: policyPath, version, source }) {
    const row = {
      ts:            new Date().toISOString(),
      event_id:      crypto.randomUUID(),
      session_id:    undefined,
      run_id:        undefined,
      agent:         'localfirst',
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

  return { record, recordPolicyLoaded, file: filePath };
}

module.exports = { createAuditor, DEFAULT_LOG, GENESIS, computeHash };
