'use strict';

/**
 * path-match.js — the single source of truth for deny_paths / allow_paths
 * matching. Both the tool-call gate (src/policy/engine.js) and the outbound
 * auto-context gate (src/outbound-policy.js) import from here, so the two can
 * never drift. (They did: globs were added to the engine but not the outbound
 * matcher, silently re-opening the auto-context `.env` strip.)
 *
 * An entry containing * or ? is a path GLOB matched against the whole resolved
 * path; an entry without is a directory PREFIX. Matching normalises separators
 * to '/' and is case-insensitive on Windows.
 *
 *   **  → any run of characters, including '/'   (cross-segment)
 *   *   → any run of characters except '/'        (within one segment)
 *   ?   → a single character except '/'
 */

const path = require('path');

const normCase = process.platform === 'win32'
  ? (p) => p.toLowerCase()
  : (p) => p;

// Safe prefix match: prevents ~/.aws from matching ~/.awskeys.
function matchesPrefix(inputNorm, denyNorm) {
  return inputNorm === denyNorm || inputNorm.startsWith(denyNorm + path.sep);
}

function isGlobEntry(entry) {
  return typeof entry === 'string' && (entry.includes('*') || entry.includes('?'));
}

const _globCache = new Map();
function globToRegExp(glob) {
  if (_globCache.has(glob)) return _globCache.get(glob);
  const g = glob.replace(/\\/g, '/');
  let re = '^';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') {
      if (g[i + 1] === '*') { re += '.*'; i++; }   // ** (consume the pair)
      else                  { re += '[^/]*'; }      // *
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  re += '$';
  const rx = new RegExp(re, process.platform === 'win32' ? 'i' : '');
  _globCache.set(glob, rx);
  return rx;
}

/**
 * Does a resolved absolute input path match a single deny/allow entry?
 * Glob entries match the whole path; plain entries are directory prefixes.
 */
function pathMatchesEntry(resolvedAbsPath, entry) {
  if (isGlobEntry(entry)) {
    return globToRegExp(entry).test(resolvedAbsPath.replace(/\\/g, '/'));
  }
  return matchesPrefix(normCase(resolvedAbsPath), normCase(entry));
}

module.exports = { normCase, matchesPrefix, isGlobEntry, globToRegExp, pathMatchesEntry };
