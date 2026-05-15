// `occasio clear` — reset session + today's log.
// `occasio clear --history` — wipe ALL historical logs + blocked-secret records.
//
// Destructive but bounded to ~/.occasio/. session.json is unconditionally
// removed; logs are removed file-by-file (no rmdir) so an exotic
// permission error on one file does not abort the rest.

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const LOG_DIR      = path.join(os.homedir(), '.occasio');
const SESSION_FILE = path.join(LOG_DIR, 'session.json');

const col = {
  g: s => `\x1b[32m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
};

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function getLogFile() { return path.join(LOG_DIR, 'logs', `${todayStr()}.jsonl`); }

function ensureDirs() {
  for (const sub of ['', 'logs', 'reports', 'blocked', 'distilled']) {
    const d = path.join(LOG_DIR, sub);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }
}

function run(args) {
  ensureDirs();
  const clearAll = (args || []).includes('--history');
  if (clearAll) {
    const logsDir = path.join(LOG_DIR, 'logs');
    const blockedDir = path.join(LOG_DIR, 'blocked');
    let n = 0;
    for (const dir of [logsDir, blockedDir]) {
      try { for (const f of fs.readdirSync(dir)) { fs.unlinkSync(path.join(dir, f)); n++; } } catch { /* ignore */ }
    }
    try { fs.unlinkSync(SESSION_FILE); } catch { /* ignore */ }
    console.log(col.g(`✓ Cleared all history (${n} log files) and session data`));
  } else {
    try { fs.unlinkSync(getLogFile()); } catch { /* ignore */ }
    try { fs.unlinkSync(SESSION_FILE); } catch { /* ignore */ }
    console.log(col.g("✓ Cleared today's log and session data"));
    console.log(col.d('  Use --history to wipe all historical logs'));
  }
}

module.exports = { run };
