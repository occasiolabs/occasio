'use strict';

/**
 * verifier.js — hash-chain verification for pipeline-events.jsonl.
 *
 * verifyFile(filePath) → { ok, total, legacy, chained, errors, firstHash, lastHash }
 * runAuditCli(args)    — CLI entry point for `occasio audit [verify]`
 *
 * Chain rules:
 *   1. The first hash-chained row must have prev_hash === GENESIS.
 *   2. Each subsequent chained row's prev_hash must equal the previous row's hash.
 *   3. Every chained row's hash must equal sha256(JSON.stringify(rowWithoutHash)).
 *
 * Legacy rows (no hash field) are skipped and counted separately.
 * They are not verifiable; their presence does not break the chain.
 */

const fs   = require('fs');
const { DEFAULT_LOG, GENESIS, computeHash } = require('./jsonl-auditor');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

/**
 * Verify the hash chain in a pipeline-events.jsonl file.
 *
 * Returns:
 *   ok         — true iff no errors found in the chained segment
 *   total      — total non-empty lines in the file
 *   legacy     — rows without hash/prev_hash (not verifiable)
 *   chained    — rows with hash/prev_hash (verified)
 *   errors     — [{ line, detail }] for any broken links or hash mismatches
 *   firstHash  — prev_hash of the first chained row (should be GENESIS)
 *   lastHash   — hash of the last chained row (null if none)
 */
function verifyFile(filePath = DEFAULT_LOG) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false, total: 0, legacy: 0, chained: 0,
      errors: [{ line: 0, detail: `Cannot read file: ${e.message}` }],
      firstHash: null, lastHash: null,
    };
  }

  const lines = content.split('\n').filter(Boolean);
  const errors = [];
  let legacy = 0, chained = 0;
  let expectedPrevHash = null;  // null = no chained row seen yet
  let firstHash = null, lastHash = null;
  const seenSchemaVersions = new Set();
  const SUPPORTED_SCHEMA_VERSIONS = new Set([1]);

  for (let i = 0; i < lines.length; i++) {
    let row;
    try {
      row = JSON.parse(lines[i]);
    } catch {
      errors.push({ line: i + 1, detail: 'Invalid JSON — cannot parse row' });
      continue;
    }

    if (typeof row.hash !== 'string' || row.hash.length !== 64) {
      legacy++;
      continue;
    }

    chained++;

    // Schema-version policy:
    //   - rows with audit_schema=undefined are legacy (pre-versioning) and
    //     verify as before — they are valid.
    //   - rows with audit_schema=1 verify normally.
    //   - rows with audit_schema=N for unknown N record a non-fatal warning
    //     in errors with a `warning: true` marker; ok-state is unaffected.
    if (row.audit_schema !== undefined) {
      seenSchemaVersions.add(row.audit_schema);
      if (!SUPPORTED_SCHEMA_VERSIONS.has(row.audit_schema)) {
        errors.push({
          line: i + 1,
          detail: `unknown audit_schema version ${row.audit_schema} (this build supports: ${[...SUPPORTED_SCHEMA_VERSIONS].join(',')})`,
          warning: true,
        });
      }
    }

    if (expectedPrevHash === null) {
      // First chained row: prev_hash must be GENESIS.
      firstHash = row.prev_hash;
      if (row.prev_hash !== GENESIS) {
        errors.push({ line: i + 1, detail: `first chained row has unexpected prev_hash (expected GENESIS, got ${String(row.prev_hash).slice(0, 16)}…)` });
      }
      expectedPrevHash = GENESIS;
    }

    // Chain continuity: prev_hash must equal the previous row's hash.
    if (row.prev_hash !== expectedPrevHash) {
      errors.push({ line: i + 1, detail: `chain broken — prev_hash mismatch (expected ${expectedPrevHash.slice(0, 12)}…, got ${String(row.prev_hash).slice(0, 12)}…)` });
    }

    // Content integrity: stored hash must equal recomputed hash.
    const { hash: storedHash, ...rowWithoutHash } = row;
    const recomputed = computeHash(rowWithoutHash);
    if (recomputed !== storedHash) {
      errors.push({ line: i + 1, detail: `hash mismatch — row was modified (stored ${storedHash.slice(0, 12)}…, computed ${recomputed.slice(0, 12)}…)` });
    }

    // Advance chain using the recomputed hash so that a tampered row causes the
    // next row's prev_hash check to fail too — makes cascade breaks visible.
    expectedPrevHash = recomputed;
    lastHash = storedHash;
  }

  // Warnings (unknown schema versions) do not flip ok=false — they are
  // forward-compatibility hints, not chain breakage.
  const fatal = errors.filter(e => !e.warning);
  return {
    ok: fatal.length === 0,
    total: lines.length, legacy, chained,
    errors,
    firstHash, lastHash,
    schemaVersions: [...seenSchemaVersions],
  };
}

function runAuditCli(args) {
  const sub = args[0];

  // Dispatch sub-commands. `repair` is forwarded to src/audit/repair.js.
  if (sub === 'repair') {
    const { runRepairCli } = require('./repair');
    return runRepairCli(args.slice(1));
  }

  // Accept: `occasio audit`, `occasio audit verify`, `occasio audit verify --file <path>`
  if (sub && sub !== 'verify' && !sub.startsWith('-')) {
    console.error(`Unknown audit subcommand: ${sub}\nUsage: occasio audit [verify|repair] [--file <path>]`);
    process.exit(1);
  }

  const rest   = sub === 'verify' ? args.slice(1) : args;
  const fileIdx = rest.indexOf('--file');
  const filePath = fileIdx !== -1 && rest[fileIdx + 1] ? rest[fileIdx + 1] : DEFAULT_LOG;

  console.log(`\n${col.b('Occasio — audit log verification')}\n`);
  console.log(`  File:  ${col.d(filePath)}`);

  const r = verifyFile(filePath);

  console.log(`  Rows:  ${r.total} total  (${r.chained} chained, ${r.legacy} legacy/unverified)\n`);

  if (r.total === 0) {
    console.log(`  ${col.d('Log is empty — nothing to verify.')}`);
    return;
  }

  if (r.chained === 0) {
    console.log(`  ${col.y('⚠  No hash-chained rows found.')}`);
    console.log(col.d('  All rows pre-date hash-chain support and are not verifiable.'));
    console.log(col.d('  New sessions will start a fresh chain from the GENESIS sentinel.'));
    return;
  }

  if (r.ok) {
    console.log(`  ${col.g('✓ Chain intact')}  (${r.chained} rows verified)`);
    if (r.lastHash) {
      console.log(`  ${col.d('Last:  ' + r.lastHash.slice(0, 32) + '…')}`);
    }
  } else {
    console.log(`  ${col.r('✗ Chain broken')}  (${r.errors.length} error(s) detected)`);
    for (const err of r.errors) {
      console.log(`    ${col.r('Line ' + err.line + ':')} ${err.detail}`);
    }
    console.log('');
    process.exit(1);
  }
}

module.exports = { verifyFile, runAuditCli };
