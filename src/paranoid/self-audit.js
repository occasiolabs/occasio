'use strict';

/**
 * self-audit.js: search src/ and bin/ for known telemetry SDK signatures
 * and verify that package.json does not depend on any telemetry packages.
 *
 * The curated pattern list lives in patterns/telemetry-sdks.js. Both checks
 * report any match as `critical` since presence of a telemetry SDK in
 * Occasio (source or deps) breaks the no-phone-home promise on the README.
 */

const fs   = require('fs');
const path = require('path');

const { SOURCE_PATTERNS, PACKAGE_NAMES } = require('./patterns/telemetry-sdks');
const { listJsFiles } = require('./source-scan');

// listJsFiles already skips src/paranoid/patterns/, so the curated SDK
// strings in patterns/telemetry-sdks.js do not match themselves.
function scanSource(dirs) {
  const files = listJsFiles(dirs);
  const hits  = [];
  for (const f of files) {
    const text  = fs.readFileSync(f, 'utf8');
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const { re, label } of SOURCE_PATTERNS) {
        if (re.test(lines[i])) {
          hits.push({
            severity: 'critical',
            file: f,
            line: i + 1,
            snippet: lines[i].trim().slice(0, 120),
            pattern: label,
          });
          break;
        }
      }
    }
  }
  return { files: files.length, hits };
}

function scanDeps(packageJsonPath) {
  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')); }
  catch { return { runtimeDeps: 0, devDeps: 0, hits: [] }; }

  const runtime = Object.keys(pkg.dependencies    || {});
  const dev     = Object.keys(pkg.devDependencies || {});
  const hits    = [];

  for (const name of runtime) {
    if (PACKAGE_NAMES.has(name)) {
      hits.push({ severity: 'critical', package: name, scope: 'runtime' });
    }
  }
  for (const name of dev) {
    if (PACKAGE_NAMES.has(name)) {
      hits.push({ severity: 'critical', package: name, scope: 'dev' });
    }
  }
  return { runtimeDeps: runtime.length, devDeps: dev.length, hits };
}

/**
 * Run both source and dependency audits.
 * Returns the canonical scanner shape, with an additional `deps` block
 * carrying the dependency-side counts.
 */
function scan(opts = {}) {
  const t0   = Date.now();
  const dirs = opts.dirs || [
    path.join(__dirname, '..', '..', 'src'),
    path.join(__dirname, '..', '..', 'bin'),
  ];
  const pkgPath = opts.packageJsonPath ||
    path.join(__dirname, '..', '..', 'package.json');

  const src = scanSource(dirs);
  const dep = scanDeps(pkgPath);

  const allHits = src.hits.concat(dep.hits.map(h => ({ ...h, kind: 'dependency' })));
  const summary = { critical: 0, warn: 0, info: 0, ok: 0 };
  for (const h of allHits) summary[h.severity]++;

  return {
    name: 'self-audit',
    files: src.files,
    hits: allHits,
    deps: {
      runtime: dep.runtimeDeps,
      dev: dep.devDeps,
      hits: dep.hits,
    },
    patternCount: SOURCE_PATTERNS.length,
    summary,
    durationMs: Date.now() - t0,
  };
}

module.exports = { scan, scanSource, scanDeps };
