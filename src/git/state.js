'use strict';

/**
 * git/state.js — read-only capture of a repository's git state at a point in
 * time, for binding an Occasio run to the concrete code it ran against.
 *
 * Everything here is best-effort and NEVER throws: a non-git directory, a repo
 * with no commits, or a machine without git installed all resolve to a
 * well-formed object with `is_repo:false` (or null fields) rather than an
 * error. The proxy's audit-write path treats git evidence as additive — it
 * must not be able to abort a run.
 *
 * All git invocations use spawnSync with an argv array and NO shell, so paths
 * with spaces are safe on Windows and there is no command-injection surface.
 *
 * captureGitState(cwd) →
 *   {
 *     is_repo:         boolean,
 *     head:            string|null,   // 40-hex commit SHA at HEAD
 *     branch:          string|null,   // abbrev ref (e.g. "main"), or "HEAD" detached
 *     dirty:           boolean,       // any tracked change or untracked file
 *     changed_files:   string[],      // tracked paths with a working-tree/index change (sorted)
 *     untracked_files: string[],      // paths git reports as untracked '??' (sorted)
 *     diff_hash:       string|null,   // sha256 of `git diff HEAD` output (null if no diff)
 *   }
 *
 * gitStateDigest(state) → sha256 hex over a canonical subset — a single stable
 * fingerprint of the repo state suitable for commitment.
 */

const crypto = require('crypto');
const { spawnSync } = require('child_process');

function sha256hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Run a git subcommand read-only. Returns { ok, out } where out is trimmed
// stdout on success. Any spawn error / non-zero exit → { ok:false, out:'' }.
function git(args, cwd) {
  let r;
  try {
    r = spawnSync('git', args, {
      cwd,
      encoding: 'utf8',
      timeout: 5000,
      windowsHide: true,
      // No shell: argv is passed directly to git, so spaces/specials in cwd or
      // args are not re-interpreted. maxBuffer generous for large diffs.
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch {
    return { ok: false, out: '' };
  }
  if (!r || r.error || typeof r.status !== 'number' || r.status !== 0) {
    return { ok: false, out: '' };
  }
  return { ok: true, out: (r.stdout || '').replace(/\r\n/g, '\n') };
}

// Parse `git status --porcelain` (v1 format) into tracked-changed + untracked.
// Porcelain v1 line shape: "XY <path>" or for renames "XY <old> -> <new>".
function parsePorcelain(out) {
  const changed = [];
  const untracked = [];
  for (const line of out.split('\n')) {
    if (!line) continue;
    const xy = line.slice(0, 2);
    let p = line.slice(3);
    if (xy === '??') {
      untracked.push(p);
      continue;
    }
    // Rename/copy: "old -> new" — record the destination path.
    const arrow = p.indexOf(' -> ');
    if (arrow !== -1) p = p.slice(arrow + 4);
    changed.push(p);
  }
  changed.sort();
  untracked.sort();
  return { changed, untracked };
}

function captureGitState(cwd) {
  const dir = cwd || process.cwd();

  const empty = {
    is_repo: false,
    head: null,
    branch: null,
    dirty: false,
    changed_files: [],
    untracked_files: [],
    diff_hash: null,
  };

  // Gate on a real work tree. `--is-inside-work-tree` prints "true" only inside
  // a checkout (not a bare repo, not a plain directory).
  const inside = git(['rev-parse', '--is-inside-work-tree'], dir);
  if (!inside.ok || inside.out.trim() !== 'true') return empty;

  const headR = git(['rev-parse', 'HEAD'], dir);
  const head = headR.ok && /^[0-9a-f]{40}$/.test(headR.out.trim())
    ? headR.out.trim() : null;

  const branchR = git(['rev-parse', '--abbrev-ref', 'HEAD'], dir);
  const branch = branchR.ok && branchR.out.trim() ? branchR.out.trim() : null;

  const statusR = git(['status', '--porcelain'], dir);
  const { changed, untracked } = statusR.ok
    ? parsePorcelain(statusR.out)
    : { changed: [], untracked: [] };

  // Diff vs HEAD captures staged + unstaged tracked changes. Pre-first-commit
  // repos have no HEAD, so fall back to the plain working-tree diff.
  const diffR = head
    ? git(['diff', 'HEAD'], dir)
    : git(['diff'], dir);
  const diffText = diffR.ok ? diffR.out : '';
  const diff_hash = diffText.length ? sha256hex(diffText) : null;

  return {
    is_repo: true,
    head,
    branch,
    dirty: changed.length > 0 || untracked.length > 0,
    changed_files: changed,
    untracked_files: untracked,
    diff_hash,
  };
}

// Stable single-value fingerprint of a captured state. Field order is fixed so
// the digest is reproducible across machines/runtimes (mirrors the canonical
// serialization used by the audit chain).
function gitStateDigest(state) {
  const s = state || {};
  const canonical = JSON.stringify({
    is_repo: !!s.is_repo,
    head: s.head || null,
    branch: s.branch || null,
    dirty: !!s.dirty,
    changed_files: Array.isArray(s.changed_files) ? s.changed_files.slice().sort() : [],
    untracked_files: Array.isArray(s.untracked_files) ? s.untracked_files.slice().sort() : [],
    diff_hash: s.diff_hash || null,
  });
  return sha256hex(canonical);
}

module.exports = { captureGitState, gitStateDigest, _parsePorcelain: parsePorcelain };
