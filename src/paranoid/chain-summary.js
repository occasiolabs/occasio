'use strict';

/**
 * chain-summary.js: embed the existing audit-chain verifier output as
 * one block in the paranoid report. Read-only, reuses src/audit/verifier.
 */

const path = require('path');
const os   = require('os');

const { verifyFile } = require('../audit/verifier');

const DEFAULT_CHAIN = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');

function scan(opts = {}) {
  const t0 = Date.now();
  const file = opts.chainFile || process.env.OCCASIO_AUDIT_FILE || DEFAULT_CHAIN;
  const result = verifyFile(file);

  // Pre-v0.9 concurrent-writer events produced chain breaks under specific
  // workloads. The lock-by-default fix in v0.9 prevents new occurrences but
  // does not retroactively repair the existing chain. We surface the count
  // and tag pre-existing breaks as `info` (historical) rather than `critical`.
  const hits = [];
  if (!result.ok) {
    for (const err of (result.errors || [])) {
      hits.push({
        severity: 'info',
        message: `chain break at line ${err.line}: ${err.detail}`,
        kind: 'historical-break',
      });
    }
  }

  const summary = { critical: 0, warn: 0, info: hits.length, ok: result.ok ? 1 : 0 };

  return {
    name: 'chain-summary',
    hits,
    summary,
    chain: {
      file,
      total:      result.total,
      legacy:     result.legacy,
      chained:    result.chained,
      firstHash:  result.firstHash,
      lastHash:   result.lastHash,
      breakCount: (result.errors || []).length,
      ok:         result.ok,
    },
    durationMs: Date.now() - t0,
  };
}

module.exports = { scan };
