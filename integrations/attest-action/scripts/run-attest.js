#!/usr/bin/env node
'use strict';

/**
 * run-attest.js — invoked by action.yml step `attest`.
 *
 * Resolves inputs, locates the run_id (input → ~/.occasio/session.json
 * fallback), invokes `occasio attest --sign ...` and emits Action outputs
 * for the next step.
 *
 * Pure Node, no npm deps beyond Node 20's stdlib.
 */

const { spawnSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

function out(key, val) {
  // GitHub Actions newer output protocol via GITHUB_OUTPUT.
  const file = process.env.GITHUB_OUTPUT;
  const line = `${key}=${String(val).replace(/\r?\n/g, ' ')}\n`;
  if (file) fs.appendFileSync(file, line, 'utf8');
  else      process.stdout.write(`::set-output name=${key}::${val}\n`);
}

function die(msg) {
  process.stderr.write(`[attest-action] ${msg}\n`);
  process.exit(1);
}

const LF_HOME = path.join(os.homedir(), '.occasio');

// ── Input validators ────────────────────────────────────────────────────────
// Any string that flows into `spawnSync('occasio', [..., value, ...])` must
// be whitelisted. spawnSync with an array argv is shell-safe — but a value
// that begins with `--` is still treated as a flag by the child, and a value
// that contains a comma corrupts our --files-changed encoding. Validate at
// the boundary, fail closed.

const UUID_RE        = /^[0-9a-fA-F-]{36}$/;
const GIT_COMMIT_RE  = /^[0-9a-fA-F]{7,64}$/;
// Conservative path policy for inputs that come from the workflow file:
// no NUL, no newlines, no leading dash (would be parsed as a flag).
const PATH_RE        = /^[^\0\r\n][^\0\r\n]{0,1023}$/;

function validRunId(s)     { return typeof s === 'string' && UUID_RE.test(s); }
function validCommitSha(s) { return typeof s === 'string' && GIT_COMMIT_RE.test(s); }
function validPath(s)      { return typeof s === 'string' && PATH_RE.test(s) && !s.startsWith('-'); }
// Workflow filenames go through git's --name-only output; reject anything
// containing characters that would corrupt our comma-joined encoding or be
// interpreted as a flag. Comma-bearing filenames exist on POSIX but are rare;
// we drop them with a warning rather than silently misencoding.
function validFilePath(s)  { return typeof s === 'string' && s.length > 0 && !s.startsWith('-') && !s.includes(',') && !/[\0\r\n]/.test(s); }

// ── Resolve run_id ──────────────────────────────────────────────────────────
function resolveRunId() {
  const explicit = (process.env.OCC_INPUT_RUN_ID || '').trim();
  if (explicit) {
    if (!validRunId(explicit)) die(`Invalid run-id input: must be a UUID. Got: ${explicit}`);
    return explicit;
  }
  const sess = path.join(LF_HOME, 'session.json');
  try {
    const j = JSON.parse(fs.readFileSync(sess, 'utf8'));
    if (j && typeof j.run_id === 'string') {
      if (!validRunId(j.run_id)) die(`session.json has invalid run_id: ${j.run_id}`);
      return j.run_id;
    }
  } catch { /* fall through */ }
  die(`No run-id input and ${sess} not readable. Pass run-id explicitly, or run a Occasio session before this action.`);
}

// ── Resolve files-changed from the PR (best effort) ─────────────────────────
function resolveFilesChanged() {
  // Use git diff against the base ref if available. The checkout action's
  // default fetch-depth=1 is fine — diff against HEAD~1 covers the head commit.
  const headSha = (process.env.OCC_GITHUB_SHA || '').trim();
  if (!validCommitSha(headSha)) return [];
  const args = ['diff', '--name-only', `${headSha}^..${headSha}`];
  const r = spawnSync('git', args, { encoding: 'utf8' });
  if (r.status !== 0) return [];
  const all = r.stdout.split('\n').map(s => s.trim()).filter(Boolean);
  const kept = all.filter(validFilePath);
  if (kept.length !== all.length) {
    const dropped = all.length - kept.length;
    process.stderr.write(`[attest-action] dropped ${dropped} file path(s) with invalid characters (comma, NUL, newline, leading dash)\n`);
  }
  return kept;
}

// ── Main ────────────────────────────────────────────────────────────────────
function main() {
  const runId        = resolveRunId();
  const chainFile    = (process.env.OCC_INPUT_CHAIN  || '').trim();
  const policyFile   = (process.env.OCC_INPUT_POLICY || '').trim();
  const sign         = (process.env.OCC_INPUT_SIGN   || 'true').trim().toLowerCase() === 'true';
  const gitCommit    = (process.env.OCC_GITHUB_SHA   || '').trim();

  if (chainFile  && !validPath(chainFile))      die(`Invalid chain-file input: ${chainFile}`);
  if (policyFile && !validPath(policyFile))     die(`Invalid policy-file input: ${policyFile}`);
  if (gitCommit  && !validCommitSha(gitCommit)) die(`Invalid github SHA: ${gitCommit}`);

  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const outPath   = path.join(workspace, 'run.occasio.json');

  // One artifact, one command: `occasio bundle` packs the attestation, the
  // run's chain slice, the policy snapshot and (with --sign) the Sigstore
  // bundle into a single self-contained file. git_state is chain-sourced
  // inside the bundle, so there is no --git-commit/--files-changed injection
  // here — the embedded git_state is exactly what `occasio verify --strict`
  // cross-checks against the chain.
  const args = ['bundle', '--run', runId, '--out', outPath];
  if (chainFile)  args.push('--log',    chainFile);
  if (policyFile) args.push('--policy', policyFile);
  if (sign)       args.push('--sign');

  process.stdout.write(`[attest-action] occasio ${args.join(' ')}\n`);
  const r = spawnSync('occasio', args, { encoding: 'utf8', stdio: 'inherit' });
  if (r.status !== 0) die(`occasio bundle failed (exit ${r.status})`);

  out('bundle-path',      outPath);
  out('attestation-path', outPath);  // back-compat alias: same single file

  // Extract rekor entry from the bundle's embedded attestation, if signed.
  let rekor = '';
  try {
    const b = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    rekor = (b && b.attestation && b.attestation.signature && b.attestation.signature.rekor_entry) || '';
  } catch { /* ignore */ }
  out('rekor-entry', rekor);
}

// Only execute when invoked as a script; allow tests to require() this file
// and exercise the validators / helpers without spawning anything.
if (require.main === module) main();

module.exports = {
  validRunId, validCommitSha, validPath, validFilePath,
  UUID_RE, GIT_COMMIT_RE, PATH_RE,
  resolveRunId, resolveFilesChanged, main,
};
