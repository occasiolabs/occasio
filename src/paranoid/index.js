'use strict';

/**
 * Paranoid doctor: scan this install for evidence of network calls,
 * telemetry SDKs, and chain-integrity status. The output is the proof
 * surface for the local-first claim on README.md and docs/WHY-LOCAL.md.
 *
 * Usage:
 *   occasio doctor --paranoid           human terminal view
 *   occasio doctor --paranoid --json    structured JSON
 *
 * Signing of the paranoid report (--sign) is staged for v0.10.1; the
 * required signAttestation path at src/attest/sign.js is reusable when
 * we land it.
 *
 * Exit code is 0 if no critical findings, 1 otherwise.
 */

const sourceScan       = require('./source-scan');
const selfAudit        = require('./self-audit');
const packageIntegrity = require('./package-integrity');
const chainSummary     = require('./chain-summary');
const { renderHuman, renderJson } = require('./render');

function runScanners(opts = {}) {
  const t0 = Date.now();
  const scanners = {
    'source-scan':       sourceScan.scan(opts),
    'self-audit':        selfAudit.scan(opts),
    'package-integrity': packageIntegrity.scan(opts),
    'chain-summary':     chainSummary.scan(opts),
  };

  const totals = { critical: 0, warn: 0, info: 0, ok: 0 };
  for (const k of Object.keys(scanners)) {
    const s = scanners[k].summary || {};
    totals.critical += s.critical || 0;
    totals.warn     += s.warn     || 0;
    totals.info     += s.info     || 0;
    totals.ok       += s.ok       || 0;
  }

  return {
    name: 'occasio-paranoid-doctor',
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    scanners,
    totals,
  };
}

/**
 * Optionally sign the report and write the Sigstore bundle next to it.
 * Returns { bundlePath, signatureBlock } on success, throws otherwise.
 * Caller decides whether to abort or continue on sign failure.
 */
async function signReportToDisk(report, opts) {
  const fs   = require('fs');
  const path = require('path');
  const { signParanoidReport } = require('./sign');

  const reportJson = JSON.stringify(report);
  const { bundle, signatureBlock } = await signParanoidReport(reportJson, {
    oidcToken: opts.oidcToken,
  });

  const outDir = opts.outDir || process.cwd();
  const stamp  = report.generatedAt.replace(/[:.]/g, '-');
  const reportPath = path.join(outDir, `paranoid-report-${stamp}.json`);
  const bundlePath = path.join(outDir, `paranoid-report-${stamp}.sigstore.json`);
  fs.writeFileSync(reportPath, reportJson);
  fs.writeFileSync(bundlePath, JSON.stringify(bundle));
  return { reportPath, bundlePath, signatureBlock };
}

async function runParanoid(opts = {}) {
  const report = runScanners(opts);

  if (opts.sign) {
    try {
      const { reportPath, bundlePath, signatureBlock } = await signReportToDisk(report, opts);
      report.signature = signatureBlock;
      report.artefacts = { reportPath, bundlePath };
      const out = opts.json ? renderJson(report) : renderHuman(report);
      process.stdout.write(out);
      if (!opts.json) {
        process.stdout.write(`\n  Signed report written to:\n    ${reportPath}\n    ${bundlePath}\n`);
        if (signatureBlock.rekor_entry) {
          process.stdout.write(`  Rekor: ${signatureBlock.rekor_entry}\n`);
        }
        process.stdout.write('\n');
      }
      return report.totals.critical === 0 ? 0 : 1;
    } catch (e) {
      process.stderr.write(`\n  Sign failed: ${e.message}\n`);
      process.stderr.write(`  The unsigned report follows.\n\n`);
    }
  }

  const out = opts.json ? renderJson(report) : renderHuman(report);
  process.stdout.write(out);
  if (!opts.json) process.stdout.write('\n');
  return report.totals.critical === 0 ? 0 : 1;
}

module.exports = { runParanoid, runScanners };
