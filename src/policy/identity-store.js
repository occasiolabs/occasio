'use strict';

/**
 * identity-store.js — the approval store behind the identity gate.
 *
 * An identity *borrow* (ssh/az/sudo) is fail-closed BLOCKed until a human
 * authorizes it. This store records that handshake in ~/.occasio/approvals.jsonl:
 *
 *   request  (proxy)  → pending      a borrow was attempted and blocked
 *   approve  (human)  → approved     the human authorized it, single-use + TTL
 *   consume  (proxy)  → consumed     the agent's re-attempt was let through once
 *   deny / expire     → denied / expired
 *
 * Scope is per `command_hash` (the exact normalized command, incl. the remote
 * part) so "ssh hostA approved once" never means "ssh anywhere". Duration is
 * --once + a short TTL, never forever.
 *
 * Forgery resistance: each approved record is HMAC-signed (key at
 * ~/.occasio/approval-key, 0600). `lookup` verifies the signature, so a
 * hand-written approvals.jsonl entry fails verification → fail-closed deny. This
 * closes the naive direct-write forge; an obfuscated-interpreter write that also
 * steals the key is the documented residual (see docs/identity-gate.md), whose
 * real fix is OS-level store isolation.
 *
 * Read/write split (mirrors the gate's design): `lookup` is READ-ONLY (no lock,
 * does not persist) so the engine can call it idempotently; every mutation
 * (requestApproval / consume / approve / deny / sweep) takes the proper-lockfile
 * lock and rewrites the file, exactly like src/audit/jsonl-auditor.js.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { commandHash } = require('./command-normalize');

const DEFAULT_TTL     = 300;     // seconds — approval lifetime
const MAX_TTL         = 3600;    // seconds — hard cap on --ttl overrides
const DEFAULT_MAX_USES = 1;      // --once
const PENDING_TTL     = 86400;   // seconds — a pending request auto-expires after a day

function defaultPaths() {
  const dir = path.join(os.homedir(), '.occasio');
  return {
    file:    process.env.OCCASIO_APPROVALS_FILE || path.join(dir, 'approvals.jsonl'),
    keyFile: process.env.OCCASIO_APPROVAL_KEY_FILE || path.join(dir, 'approval-key'),
  };
}

function nowSec() { return Math.floor(Date.now() / 1000); }
function newId()  { return 'apr_' + crypto.randomBytes(8).toString('hex'); }

/**
 * @param {object} [opts] { file, keyFile } — injectable for tests.
 */
function createIdentityStore(opts = {}) {
  const file    = opts.file    || defaultPaths().file;
  const keyFile = opts.keyFile || defaultPaths().keyFile;

  let lockfile = null;
  try { lockfile = require('proper-lockfile'); } catch { lockfile = null; }

  function ensureDir() {
    try { fs.mkdirSync(path.dirname(file), { recursive: true }); } catch { /* exists */ }
  }

  // ── HMAC key ───────────────────────────────────────────────────────────────
  function getOrCreateKey() {
    try {
      return fs.readFileSync(keyFile);
    } catch { /* create below */ }
    ensureDir();
    const key = crypto.randomBytes(32);
    try { fs.writeFileSync(keyFile, key, { mode: 0o600 }); } catch { /* best effort */ }
    return key;
  }
  function signRecord(rec) {
    const key = getOrCreateKey();
    const payload = `${rec.id}|${rec.command_hash}|${rec.actor || ''}|${rec.approved_by || ''}|${rec.expires_at || ''}|${rec.max_uses || ''}`;
    return crypto.createHmac('sha256', key).update(payload, 'utf8').digest('hex');
  }
  function verifySig(rec) {
    if (typeof rec.sig !== 'string' || rec.sig.length !== 64) return false;
    let expected;
    try { expected = signRecord(rec); } catch { return false; }
    const a = Buffer.from(rec.sig, 'hex');
    const b = Buffer.from(expected, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  // ── file I/O ─────────────────────────────────────────────────────────────
  function readAll() {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
    const rows = [];
    for (const line of text.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try { rows.push(JSON.parse(t)); } catch { /* skip corrupt line */ }
    }
    return rows;
  }
  function writeAll(rows) {
    ensureDir();
    fs.writeFileSync(file, rows.map(r => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));
  }

  function withLock(fn) {
    if (!lockfile) return fn(readAll());
    ensureDir();
    if (!fs.existsSync(file)) fs.writeFileSync(file, '');
    let release = null;
    const start = Date.now();
    while (release === null) {
      try { release = lockfile.lockSync(file, { stale: 10000, realpath: false }); }
      catch (e) {
        if (e.code !== 'ELOCKED') throw e;
        if (Date.now() - start > 10000) throw e;
        const until = Date.now() + 2; while (Date.now() < until) { /* spin */ }
      }
    }
    try { return fn(readAll()); }
    finally { try { release(); } catch { /* released by stale reaper */ } }
  }

  // ── validity (read-side, no persistence) ───────────────────────────────────
  function isLiveApproved(rec) {
    return rec && rec.state === 'approved' &&
      typeof rec.expires_at === 'number' && nowSec() < rec.expires_at &&
      typeof rec.uses === 'number' && typeof rec.max_uses === 'number' && rec.uses < rec.max_uses &&
      verifySig(rec);
  }

  // ── public API ─────────────────────────────────────────────────────────────

  /** READ-ONLY: the valid approved+signed+unexpired+unused token, or null. Fail-closed. */
  function lookup({ command_hash, actor } = {}) {
    if (!command_hash) return null;
    let rows;
    try { rows = readAll(); } catch { return null; }   // unreadable → deny
    for (const rec of rows) {
      if (rec.command_hash !== command_hash) continue;
      if (actor && rec.actor && rec.actor !== actor) continue;
      if (isLiveApproved(rec)) return rec;
    }
    return null;
  }

  /** Idempotent upsert of a pending request keyed by (command_hash, actor). */
  function requestApproval({ command_hash, normalized_command, actor, identity_type, target_class, risk } = {}) {
    if (!command_hash) return { id: null, state: 'error' };
    return withLock(rows => {
      const existing = rows.find(r => r.command_hash === command_hash &&
        (r.actor || '') === (actor || '') && r.state === 'pending' &&
        (typeof r.pending_expires_at !== 'number' || nowSec() < r.pending_expires_at));
      if (existing) return { id: existing.id, state: 'pending' };
      const rec = {
        id: newId(), command_hash, normalized_command: normalized_command || null,
        actor: actor || null, identity_type: identity_type || null,
        target_class: target_class || null, risk: risk || null,
        state: 'pending', requested_at: nowSec(), pending_expires_at: nowSec() + PENDING_TTL,
        approved_at: null, approved_by: null, identity_source: null,
        ttl_seconds: null, max_uses: null, uses: 0, expires_at: null,
        decided_by: null, sig: null,
      };
      rows.push(rec);
      writeAll(rows);
      return { id: rec.id, state: 'pending' };
    });
  }

  /** Human authorizes. Caps ttl, defaults --once. Signs the record. */
  function approve(id, { ttl_seconds, max_uses, approved_by, identity_source } = {}) {
    return withLock(rows => {
      const rec = rows.find(r => r.id === id);
      if (!rec) return { ok: false, error: 'not_found' };
      let ttl = typeof ttl_seconds === 'number' && ttl_seconds > 0 ? Math.floor(ttl_seconds) : DEFAULT_TTL;
      if (ttl > MAX_TTL) ttl = MAX_TTL;
      rec.state          = 'approved';
      rec.approved_at    = nowSec();
      rec.approved_by    = approved_by || null;
      rec.identity_source = identity_source || null;
      rec.ttl_seconds    = ttl;
      rec.max_uses       = typeof max_uses === 'number' && max_uses > 0 ? Math.floor(max_uses) : DEFAULT_MAX_USES;
      rec.uses           = 0;
      rec.expires_at     = nowSec() + ttl;
      rec.decided_by     = 'human';
      rec.sig            = signRecord(rec);
      writeAll(rows);
      return { ok: true, record: rec };
    });
  }

  function deny(id, { decided_by } = {}) {
    return withLock(rows => {
      const rec = rows.find(r => r.id === id);
      if (!rec) return { ok: false, error: 'not_found' };
      rec.state = 'denied';
      rec.decided_by = decided_by || 'human';
      rec.sig = null;
      writeAll(rows);
      return { ok: true, record: rec };
    });
  }

  /** Atomic single consume of a valid token. Re-checks under lock (defends a concurrent deny). */
  function consume(id) {
    return withLock(rows => {
      const rec = rows.find(r => r.id === id);
      if (!rec || !isLiveApproved(rec)) return { ok: false };
      rec.uses += 1;
      if (rec.uses >= rec.max_uses) rec.state = 'consumed';
      writeAll(rows);
      return { ok: true, record: rec };
    });
  }

  /** Transition stale records; returns those that just expired (for the auditor). */
  function sweep() {
    return withLock(rows => {
      const expired = [];
      let changed = false;
      for (const rec of rows) {
        if (rec.state === 'pending' && typeof rec.pending_expires_at === 'number' && nowSec() >= rec.pending_expires_at) {
          rec.state = 'expired'; changed = true;
          expired.push({ ...rec, _kind: 'pending' });
        } else if (rec.state === 'approved' && typeof rec.expires_at === 'number' && nowSec() >= rec.expires_at && rec.uses < rec.max_uses) {
          rec.state = 'expired'; changed = true;
          expired.push({ ...rec, _kind: 'approved_unused' });
        }
      }
      if (changed) writeAll(rows);
      return { expired };
    });
  }

  function list({ state } = {}) {
    const rows = readAll();
    return state ? rows.filter(r => r.state === state) : rows;
  }
  function get(id) { return readAll().find(r => r.id === id) || null; }

  return {
    requestApproval, lookup, approve, deny, consume, sweep, list, get,
    file, keyFile, DEFAULT_TTL, MAX_TTL, DEFAULT_MAX_USES, PENDING_TTL,
  };
}

/** Shared default-paths store for the engine + CLIs (reads env fresh each call). */
function getStore() { return createIdentityStore(defaultPaths()); }

module.exports = {
  createIdentityStore, getStore, defaultPaths, commandHash,
  DEFAULT_TTL, MAX_TTL, DEFAULT_MAX_USES, PENDING_TTL,
};
