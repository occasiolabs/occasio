'use strict';

/**
 * package-integrity.js: report the installed version, install path, and
 * a reproducible-verify recipe. Deliberately performs no network call.
 *
 * Why no auto-verify: the paranoid doctor itself must uphold the
 * no-phone-home promise it is verifying. Calling the npm registry to
 * compare integrity hashes would contradict the very check. The recipe
 * is printed inline so the user (or a reviewer) can run it themselves.
 *
 * When npm-provenance is published for this package, a future revision of
 * this scanner will note the provenance bundle's location on disk and
 * the steps to verify it offline against the source commit.
 */

const fs   = require('fs');
const path = require('path');

function scan(opts = {}) {
  const t0   = Date.now();
  const pkgPath = opts.packageJsonPath ||
    path.join(__dirname, '..', '..', 'package.json');

  let version = null, name = null, installPath = null;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    version = pkg.version || null;
    name    = pkg.name    || null;
  } catch { /* leave nulls */ }

  try { installPath = path.dirname(pkgPath); } catch { /* ignore */ }

  const hits = [];
  if (!version) {
    hits.push({
      severity: 'warn',
      message: 'package.json version missing; cannot produce a verify recipe',
    });
  }

  const summary = { critical: 0, warn: hits.length, info: 1, ok: 0 };

  return {
    name: 'package-integrity',
    hits,
    summary,
    package: { name, version, installPath },
    recipe: version && name ? [
      `npm pack ${name}@${version}`,
      `sha256sum ${name.replace(/[@/]/g, '-').replace(/^-/, '')}-${version}.tgz`,
      `npm view ${name}@${version} dist.integrity`,
    ] : null,
    note: 'Manual verification only. The paranoid doctor never calls the registry itself.',
    durationMs: Date.now() - t0,
  };
}

module.exports = { scan };
