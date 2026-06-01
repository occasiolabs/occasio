'use strict';

/**
 * occasio policy diff — structured, human-readable diff between two policies.
 *
 * Default: the active policy.yml vs ./policy.lock.json (drift from the approved
 * baseline). Also: `policy diff <a.yml> <b.yml>` for two files, or
 * `--since <lock>` / `--file <policy>` overrides.
 *
 * Exit code (via the caller): 0 when identical, 1 when they differ — a drop-in
 * CI pin ("fail if policy drifted from the lock").
 *
 * The comparison is semantic (over loader.parse → summarize), so comment and
 * whitespace churn is ignored; the raw byte-hash match/mismatch is reported
 * separately as the authoritative drift signal.
 */

const fs   = require('fs');
const path = require('path');

const { summarize, LOCK_SCHEMA } = require('./lock');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function fmtVal(v) {
  if (v && typeof v === 'object') {
    if (typeof v.action === 'string') return v.transform ? `${v.action}→${v.transform}` : v.action;
    return JSON.stringify(v);
  }
  return String(v);
}

// Diff two label→value maps. Returns [{mark, key, detail}] with marks +/-/~.
function mapDiff(a, b) {
  const out = [];
  const keys = [...new Set([...Object.keys(a || {}), ...Object.keys(b || {})])].sort();
  for (const k of keys) {
    const inA = a && k in a, inB = b && k in b;
    if (inA && !inB)      out.push({ mark: '-', key: k, detail: fmtVal(a[k]) });
    else if (!inA && inB) out.push({ mark: '+', key: k, detail: fmtVal(b[k]) });
    else if (JSON.stringify(a[k]) !== JSON.stringify(b[k]))
      out.push({ mark: '~', key: k, detail: `${fmtVal(a[k])} → ${fmtVal(b[k])}` });
  }
  return out;
}

// Diff two string lists. Returns [{mark, key}] with +/-.
function listDiff(a, b) {
  const sa = new Set(a || []), sb = new Set(b || []);
  const out = [];
  for (const x of (a || [])) if (!sb.has(x)) out.push({ mark: '-', key: x });
  for (const x of (b || [])) if (!sa.has(x)) out.push({ mark: '+', key: x });
  return out;
}

/**
 * @param {object} a  baseline summary (e.g. the lock)
 * @param {object} b  current summary (e.g. the active policy)
 * @returns {{ changed: boolean, sections: Array<{name, rows}> }}
 */
function diffSummaries(a, b) {
  const sections = [];
  const add = (name, rows) => { if (rows.length) sections.push({ name, rows }); };
  add('flags',         mapDiff(a.flags, b.flags));
  add('deny_paths',    listDiff(a.deny_paths, b.deny_paths));
  add('allow_paths',   listDiff(a.allow_paths, b.allow_paths));
  add('deny_patterns', mapDiff(a.deny_patterns, b.deny_patterns));
  add('tools',         mapDiff(a.tools, b.tools));
  add('limits',        mapDiff(a.limits, b.limits));
  return { changed: sections.length > 0, sections };
}

// ── CLI ────────────────────────────────────────────────────────────────────

function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }

function readParsed(p) {
  const loader = require('./loader');
  const text = fs.readFileSync(p, 'utf8');   // throws → caller handles
  return { summary: summarize(loader.parse(text)), hash: loader.computePolicyHash(p), label: p };
}

/**
 * @returns {{ changed: boolean }}  caller exits 1 when changed.
 */
function runDiffCli(args) {
  args = args || [];
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      'occasio policy diff — show what changed between two policies\n\n' +
      'usage: occasio policy diff                       (active policy.yml vs ./policy.lock.json)\n' +
      '       occasio policy diff --file <p> --since <lock>\n' +
      '       occasio policy diff <a.yml> <b.yml>\n'
    );
    return { changed: false };
  }

  const loader = require('./loader');
  // Positional file args (anything not a flag or a flag's value).
  const flagVals = new Set();
  for (const f of ['--file', '--since']) { const i = args.indexOf(f); if (i >= 0) flagVals.add(i + 1); }
  const positionals = args.filter((a, i) => !a.startsWith('--') && !flagVals.has(i));

  let baseline, current;   // { summary, hash, label }
  try {
    if (positionals.length >= 2) {
      baseline = readParsed(path.resolve(positionals[0]));
      current  = readParsed(path.resolve(positionals[1]));
    } else {
      const policyPath = path.resolve(flag(args, '--file') || loader.DEFAULT_PATH);
      const lockPath   = path.resolve(flag(args, '--since') || path.join(process.cwd(), 'policy.lock.json'));
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      if (lock.schema !== LOCK_SCHEMA) throw new Error(`${lockPath} is not an ${LOCK_SCHEMA} file`);
      baseline = { summary: lock.summary, hash: lock.policy_hash, label: `${lockPath} (lock)` };
      current  = readParsed(policyPath);
    }
  } catch (e) {
    process.stderr.write(`${col.r('✗')} policy diff: ${e.message}\n`);
    // Treat an I/O/parse failure as "changed" so CI does not silently pass.
    return { changed: true };
  }

  const { changed, sections } = diffSummaries(baseline.summary, current.summary);
  const hashMatch = baseline.hash === current.hash;

  process.stdout.write(col.b('\n⚡ Occasio — Policy Diff\n\n'));
  process.stdout.write(`  baseline: ${col.d(baseline.label)}  ${col.d(baseline.hash.slice(0, 12) + '…')}\n`);
  process.stdout.write(`  current:  ${col.d(current.label)}  ${col.d(current.hash.slice(0, 12) + '…')}\n\n`);
  process.stdout.write(`  byte-hash: ${hashMatch ? col.g('match') : col.r('DRIFT')}\n`);

  if (!changed && hashMatch) {
    process.stdout.write(col.g('\n  ✓ policies are identical — no drift.\n\n'));
    return { changed: false };
  }
  if (!changed && !hashMatch) {
    // Same semantics, different bytes (comments/whitespace). Surface it but do
    // not fail the semantic diff — report as changed so CI drift-pins still trip.
    process.stdout.write(col.y('\n  ⚠ byte-hash differs but the semantic policy is unchanged (comments/whitespace).\n\n'));
    return { changed: true };
  }

  for (const sec of sections) {
    process.stdout.write(col.b(`\n  ${sec.name}:\n`));
    for (const row of sec.rows) {
      const c = row.mark === '+' ? col.g : row.mark === '-' ? col.r : col.y;
      process.stdout.write(`    ${c(row.mark)} ${row.key}${row.detail ? '  ' + col.d(row.detail) : ''}\n`);
    }
  }
  process.stdout.write(col.r('\n  ✗ policy drifted from the baseline.\n\n'));
  return { changed: true };
}

module.exports = { diffSummaries, runDiffCli };
