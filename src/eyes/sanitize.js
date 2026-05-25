'use strict';

/**
 * eyes/sanitize.js — display-time identity scrubber for Eyes payloads.
 *
 * Goal: a user can record a screencast of `occasio eyes` against a real
 * session without leaking their home path, OS username, git identity,
 * hostname, or environment-derived secrets. Operates on the response
 * boundary in server.js and on the TUI render path in content-render.js.
 * Disk contents under ~/.occasio/eyes/ are NEVER modified — this is a
 * display filter, not a recording mode.
 *
 * Hard constraint: NO hardcoded personal strings live in this file.
 * Every needle is discovered at runtime from os/git/env. A meta-test in
 * test-eyes.js refuses to ship if a real-identity value appears in this
 * source — see "self-leak" assertion there.
 *
 * API:
 *   discoverIdentity(deps?)   → identity object, deps injectable for tests
 *   buildSanitizer({identity, salt}) → { text(s), payload(p), needles() }
 *   createSession({salt?})    → buildSanitizer with discovered identity
 */

const crypto = require('crypto');
const os     = require('os');

// Env vars known to carry the OS username on common platforms. The VALUES of
// these vars at runtime become substitution needles; the variable NAMES are
// generic POSIX/Windows constants, not personal data.
const IDENT_ENV_VARS = ['USER', 'USERNAME', 'LOGNAME', 'HOME', 'USERPROFILE'];

// Per-type prefixes for generated pseudonyms. Keep them plain ASCII, no
// special characters, so they survive markdown/HTML/terminal rendering.
const TYPE_PREFIX = {
  homedir:  'home',
  username: 'user',
  email:    'user',     // emailed pseudonym still uses `user-` for consistency
  realName: 'User',
  hostname: 'host',
  env:      'envval',
};

function runGitConfig(key) {
  try {
    const { execFileSync } = require('child_process');
    const out = execFileSync('git', ['config', '--get', key], {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
      timeout: 1500,
    });
    const v = (out || '').trim();
    return v || null;
  } catch { return null; }
}

/**
 * Discover identifying values from the local environment. All sources are
 * injectable so tests can construct a fake identity without touching the
 * machine. Missing sources simply drop from the result.
 */
function discoverIdentity(deps) {
  deps = deps || {};
  const env       = deps.env       || process.env;
  const homedir   = deps.homedir   || (() => { try { return os.homedir(); }   catch { return null; } })();
  const userInfo  = deps.userInfo  || (() => { try { return os.userInfo(); }  catch { return null; } })();
  const hostname  = deps.hostname  || (() => { try { return os.hostname(); }  catch { return null; } })();
  const gitConfig = deps.gitConfig || runGitConfig;

  const identity = {
    homedir:  homedir || null,
    username: (userInfo && userInfo.username) || null,
    email:    null,
    realName: null,
    hostname: hostname || null,
    envLeaks: {},
  };

  // git config values — only the user's own configured identity. We do NOT
  // do generic email-regex scanning of payload content (that would mangle
  // legitimate third-party email mentions in code).
  identity.email    = gitConfig('user.email') || null;
  identity.realName = gitConfig('user.name')  || null;

  // Env values that commonly carry the username verbatim. Each value is
  // captured and substituted independently so e.g. $USERPROFILE on Windows
  // (which is the full home path) is matched even if $USERNAME differs.
  for (const k of IDENT_ENV_VARS) {
    const v = env[k];
    if (typeof v === 'string' && v.length >= 2) identity.envLeaks[k] = v;
  }

  return identity;
}

function hmacShort(salt, type, value) {
  // 4 hex chars = 16 bits. Birthday collision within a single session's
  // unique needle set (~10 strings) is astronomically unlikely; on the
  // off-chance of a collision the buildSanitizer dedup-loop appends -2/-3.
  const h = crypto.createHmac('sha256', salt);
  h.update(`${type}:${value}`);
  return h.digest('hex').slice(0, 4);
}

function pseudonymFor(salt, type, value, taken) {
  const prefix = TYPE_PREFIX[type] || 'tok';
  const stem   = hmacShort(salt, type, value);
  let candidate;
  if (type === 'email') {
    candidate = `${prefix}-${stem}@example.invalid`;
  } else if (type === 'homedir') {
    // POSIX-form pseudonym regardless of input platform → screenshots look
    // platform-agnostic and don't accidentally reveal "this was Windows".
    candidate = `/home/${TYPE_PREFIX.username}-${stem}`;
  } else if (type === 'realName') {
    candidate = `${prefix} ${stem.toUpperCase()}`;
  } else {
    candidate = `${prefix}-${stem}`;
  }
  if (!taken.has(candidate)) { taken.add(candidate); return candidate; }
  // Collision (extremely rare). Suffix until unique.
  for (let i = 2; i < 1000; i++) {
    const c = `${candidate}-${i}`;
    if (!taken.has(c)) { taken.add(c); return c; }
  }
  return candidate; // give up; identical to a prior, harmless
}

/**
 * Build a sanitizer closure over a specific identity + salt.
 * Substitution rule: longest needle first, plain string replace (no regex).
 * Homedir gets a special pre-pass so paths starting with it become
 * /home/user-XX/<rest with forward slashes>.
 */
function buildSanitizer({ identity, salt }) {
  if (!identity) identity = {};
  if (!salt) salt = crypto.randomBytes(16);

  const taken = new Set();
  // pairs: [needle, replacement, isHomePrefix?]
  const pairs = [];

  function addPair(type, value, isHomePrefix) {
    if (!value || typeof value !== 'string') return;
    if (value.length < 2) return;
    const repl = pseudonymFor(salt, type, value, taken);
    pairs.push([value, repl, !!isHomePrefix]);
  }

  // Order of `add` calls does NOT matter for correctness — we sort by
  // needle length descending below. But we want stable pseudonyms keyed by
  // the actual value, so each addPair generates its own HMAC.
  addPair('homedir',  identity.homedir, true);
  addPair('email',    identity.email);
  addPair('realName', identity.realName);
  addPair('hostname', identity.hostname);
  addPair('username', identity.username);
  for (const v of Object.values(identity.envLeaks || {})) {
    // Skip if already covered by a prior identical needle (homedir/username
    // commonly equals $HOME/$USER).
    if (pairs.find(p => p[0] === v)) continue;
    addPair('env', v);
  }

  // Longest-first to prevent shorter substrings from chewing through
  // longer ones (e.g. username "bob" must not eat the homedir prefix
  // before homedir's own rule runs).
  pairs.sort((a, b) => b[0].length - a[0].length);

  // Pre-compute home-prefix needle variants. On Windows the homedir uses
  // backslashes; the same path appears with forward slashes in JSON / tool
  // inputs. We substitute both forms.
  const homePair = pairs.find(p => p[2]);
  const homeBackslash  = homePair ? homePair[0] : null;
  const homeForward    = homeBackslash ? homeBackslash.replace(/\\/g, '/') : null;
  const homePseudonym  = homePair ? homePair[1] : null;

  function text(s) {
    if (typeof s !== 'string' || !s) return s;
    let out = s;
    // Home-prefix special-case: any path that begins with the homedir (in
    // either slash form) → /home/user-XX/<rest>. Doing this before the
    // generic length-sorted loop avoids the case where the bare username
    // inside the home path gets pseudonymized first and breaks the prefix
    // match.
    if (homeBackslash && homePseudonym) {
      if (out.includes(homeBackslash)) {
        out = out.split(homeBackslash).join(homePseudonym);
      }
      if (homeForward && homeForward !== homeBackslash && out.includes(homeForward)) {
        out = out.split(homeForward).join(homePseudonym);
      }
      // Cosmetic slash-normalize: when the pseudonym (POSIX-form) is
      // followed by Windows-style backslashes (`/home/user-XX\Desktop\foo`),
      // convert the path-tail to forward slashes so screenshots look clean.
      // Bounded — only consumes a contiguous path-like run after the
      // pseudonym, stops at whitespace or quote/bracket/paren chars so we
      // don't mangle prose.
      if (out.indexOf(homePseudonym + '\\') !== -1) {
        const esc = homePseudonym.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const rx = new RegExp(esc + '([\\\\/][^\\s"\'`<>(){}\\[\\],;]*)', 'g');
        out = out.replace(rx, (_m, tail) => homePseudonym + tail.replace(/\\/g, '/'));
      }
    }
    for (const [needle, repl, isHome] of pairs) {
      if (isHome) continue; // handled above
      if (!needle) continue;
      if (out.indexOf(needle) === -1) continue;
      out = out.split(needle).join(repl);
    }
    return out;
  }

  function walkValue(v) {
    if (v == null) return v;
    if (typeof v === 'string') return text(v);
    if (typeof v === 'number' || typeof v === 'boolean') return v;
    if (Array.isArray(v)) {
      const out = new Array(v.length);
      for (let i = 0; i < v.length; i++) out[i] = walkValue(v[i]);
      return out;
    }
    if (typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v)) out[k] = walkValue(v[k]);
      return out;
    }
    return v;
  }

  function payload(p) {
    if (!p || typeof p !== 'object') return p;
    return walkValue(p);
  }

  function needles() {
    return pairs.map(p => ({ needle: p[0], replacement: p[1] }));
  }

  return { text, payload, needles };
}

function createSession(opts) {
  opts = opts || {};
  const identity = opts.identity || discoverIdentity();
  const salt     = opts.salt     || crypto.randomBytes(16);
  return buildSanitizer({ identity, salt });
}

module.exports = {
  discoverIdentity,
  buildSanitizer,
  createSession,
  IDENT_ENV_VARS,
};
