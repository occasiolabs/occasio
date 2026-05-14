'use strict';
/**
 * restart-check.js — Detect stale proxy (interceptor.js modified after proxy started).
 *
 * The Occasio proxy caches interceptor.js in memory on startup via Node's
 * module require() cache.  If interceptor.js is edited while the proxy is
 * running, the new code is NOT used until the proxy process is restarted.
 *
 * This script compares interceptor.js mtime with the proxy session start time
 * and prints a clear warning if the proxy is carrying stale code.
 *
 * Usage:
 *   node scripts/restart-check.js
 *
 * Run before any live validation session to confirm the proxy has loaded the
 * current interceptor.js.
 */

'use strict';
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const SESSION_FILE   = path.join(os.homedir(), '.occasio', 'session.json');
const INTERCEPTOR_JS = path.join(__dirname, '..', 'src', 'interceptor.js');

// Parse "DD.MM.YYYY HH:MM:SS" (German locale) or ISO strings from session.json.
function parseSessionDate(str) {
  if (!str) return null;
  // ISO first
  const iso = new Date(str);
  if (!isNaN(iso.getTime())) return iso;
  // DD.MM.YYYY HH:MM:SS
  const m = /^(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(str.trim());
  if (m) {
    return new Date(
      parseInt(m[3]),
      parseInt(m[2]) - 1,
      parseInt(m[1]),
      parseInt(m[4]),
      parseInt(m[5]),
      parseInt(m[6])
    );
  }
  // MM/DD/YYYY HH:MM:SS
  const us = /^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(str.trim());
  if (us) {
    return new Date(
      parseInt(us[3]),
      parseInt(us[1]) - 1,
      parseInt(us[2]),
      parseInt(us[4]),
      parseInt(us[5]),
      parseInt(us[6])
    );
  }
  return null;
}

function fmt(d) {
  if (!d) return '(unknown)';
  return d.toLocaleString();
}

// ── main ──────────────────────────────────────────────────────────────────────

let interceptorMtime;
try {
  interceptorMtime = fs.statSync(INTERCEPTOR_JS).mtime;
} catch {
  console.error(`✗ Cannot read interceptor.js: ${INTERCEPTOR_JS}`);
  process.exit(1);
}

if (!fs.existsSync(SESSION_FILE)) {
  console.log('ℹ  No session.json found — proxy has not been started yet.');
  console.log(`   interceptor.js last modified: ${fmt(interceptorMtime)}`);
  process.exit(0);
}

let session;
try {
  session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
} catch {
  console.error(`✗ Cannot parse session.json: ${SESSION_FILE}`);
  process.exit(1);
}

const sessionStart = parseSessionDate(session.start);

console.log('Occasio proxy staleness check');
console.log('─'.repeat(40));
console.log(`interceptor.js modified : ${fmt(interceptorMtime)}`);
console.log(`proxy session started   : ${sessionStart ? fmt(sessionStart) : `"${session.start}" (unparsed)`}`);

if (!sessionStart) {
  console.log('\n⚠  Could not parse session start time — cannot determine staleness.');
  console.log('   If you recently edited interceptor.js, restart the proxy to be safe.');
  process.exit(0);
}

const stale = interceptorMtime > sessionStart;

if (stale) {
  const diffMs  = interceptorMtime - sessionStart;
  const diffMin = Math.round(diffMs / 60000);
  console.log(`\n✗  STALE — interceptor.js is ${diffMin} minute(s) newer than the running proxy.`);
  console.log('   The proxy is running OLD code.');
  console.log('   Restart required: stop the proxy and run `occasio claude` again.');
  process.exit(1);
} else {
  console.log('\n✓  OK — proxy session started after the last interceptor.js edit.');
  console.log('   The proxy is running current code.');
  process.exit(0);
}
