'use strict';

/**
 * eyes/content-store.js — content-addressed blob store under
 * ~/.occasio/eyes/content/. Used to keep heavy bytes out of the per-exchange
 * JSON payloads while preserving full fidelity for the Eyes UI.
 *
 *   const { store, read, gc } = require('./content-store');
 *   const ref = store(Buffer.from('hello'));  // → 'sha256-2cf24…'
 *   const bytes = read(ref);
 *
 * Properties:
 *   - Dedup: identical bytes → same ref → same on-disk file (1 copy).
 *   - Cheap: pure SHA-256 + writeFileSync. No locks because writes are
 *     idempotent (same content, same hash, same file).
 *   - Bounded: gc() trims by total-size or age, never touches reffed blobs
 *     when an `inUse` callback is provided.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const DEFAULT_DIR = path.join(os.homedir(), '.occasio', 'eyes', 'content');

function ensureDir(dir) {
  try { fs.mkdirSync(dir, { recursive: true }); } catch { /* ignore */ }
}

function hashOf(buf) {
  const h = crypto.createHash('sha256');
  h.update(buf);
  return 'sha256-' + h.digest('hex');
}

function refToPath(ref, dir) {
  // sha256-abcd1234… → <dir>/ab/cd1234…
  if (typeof ref !== 'string' || !ref.startsWith('sha256-')) return null;
  const hex = ref.slice('sha256-'.length);
  if (hex.length < 4 || !/^[0-9a-f]+$/.test(hex)) return null;
  return path.join(dir, hex.slice(0, 2), hex.slice(2));
}

/**
 * Persist `content` (string|Buffer) to the store. Returns `sha256-…` ref.
 * Idempotent: writing the same bytes twice is a no-op (same path).
 * Returns null if `content` is null/empty or write fails.
 */
function store(content, opts) {
  opts = opts || {};
  const dir = opts.dir || DEFAULT_DIR;
  if (content == null) return null;
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
  if (buf.length === 0) return null;
  const ref = hashOf(buf);
  const p = refToPath(ref, dir);
  if (!p) return null;
  try {
    ensureDir(path.dirname(p));
    if (!fs.existsSync(p)) fs.writeFileSync(p, buf);
    return ref;
  } catch { return null; }
}

/**
 * Read a blob by ref. Returns Buffer or null.
 */
function read(ref, opts) {
  opts = opts || {};
  const dir = opts.dir || DEFAULT_DIR;
  const p = refToPath(ref, dir);
  if (!p) return null;
  try { return fs.readFileSync(p); } catch { return null; }
}

/**
 * Return { bytes, mtimeMs } for a ref, without reading the content. null if
 * missing.
 */
function stat(ref, opts) {
  opts = opts || {};
  const dir = opts.dir || DEFAULT_DIR;
  const p = refToPath(ref, dir);
  if (!p) return null;
  try {
    const s = fs.statSync(p);
    return { bytes: s.size, mtimeMs: s.mtimeMs };
  } catch { return null; }
}

/**
 * Garbage-collect the store. Pass an `inUse(ref) → bool` callback so we never
 * delete blobs that are still referenced. Without `inUse`, deletes everything
 * older than `maxAgeMs` OR (oldest-first) until total store size ≤ maxBytes.
 */
function gc(opts) {
  opts = opts || {};
  const dir = opts.dir || DEFAULT_DIR;
  const maxAgeMs = typeof opts.maxAgeMs === 'number' ? opts.maxAgeMs : Infinity;
  const maxBytes = typeof opts.maxBytes === 'number' ? opts.maxBytes : Infinity;
  const inUse   = typeof opts.inUse === 'function' ? opts.inUse : null;

  if (!fs.existsSync(dir)) return { removed: 0, kept: 0, bytes: 0 };

  // walk shards
  const entries = [];
  for (const shard of fs.readdirSync(dir)) {
    const shardDir = path.join(dir, shard);
    let names;
    try { names = fs.readdirSync(shardDir); } catch { continue; }
    for (const n of names) {
      const full = path.join(shardDir, n);
      try {
        const st = fs.statSync(full);
        entries.push({ path: full, ref: 'sha256-' + shard + n, mtimeMs: st.mtimeMs, size: st.size });
      } catch { /* ignore */ }
    }
  }
  entries.sort((a, b) => a.mtimeMs - b.mtimeMs);

  const now = Date.now();
  let totalBytes = entries.reduce((s, e) => s + e.size, 0);
  let removed = 0, kept = 0, keptBytes = 0;

  for (const e of entries) {
    const reffed = inUse ? inUse(e.ref) : false;
    const tooOld = (now - e.mtimeMs) > maxAgeMs;
    const overBudget = totalBytes > maxBytes;
    if (!reffed && (tooOld || overBudget)) {
      try { fs.unlinkSync(e.path); totalBytes -= e.size; removed++; }
      catch { /* leave */ }
    } else {
      kept++; keptBytes += e.size;
    }
  }
  return { removed, kept, bytes: keptBytes };
}

module.exports = { store, read, stat, gc, hashOf, refToPath, DEFAULT_DIR };
