'use strict';

/**
 * occasio identity set|show
 *
 * The authorizing human's identity, written explicitly to
 * ~/.occasio/identity.json. This is the `approved_by` recorded when a human
 * authorizes an identity borrow (occasio approvals approve). Precedence:
 * explicit identity.json > OS username fallback. NOT git config (per-repo
 * editable, no auth signal).
 *
 *   occasio identity set --id alice
 *   occasio identity show
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};
function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }

function identityFile() {
  return process.env.OCCASIO_IDENTITY_FILE || path.join(os.homedir(), '.occasio', 'identity.json');
}

/** Read the explicit identity file (or null). */
function readIdentity() {
  try { return JSON.parse(fs.readFileSync(identityFile(), 'utf8')); } catch { return null; }
}

/**
 * Resolve the current authorizing identity: explicit if set, else the OS user.
 * @returns {{ id: string, source: 'explicit'|'os_fallback' }}
 */
function currentIdentity() {
  const j = readIdentity();
  const explicit = j && (j.id || j.delegator || j.user);
  if (explicit) return { id: String(explicit), source: 'explicit' };
  let u; try { u = os.userInfo().username; } catch { u = 'unknown'; }
  return { id: u, source: 'os_fallback' };
}

function usage() {
  return [
    'occasio identity — the authorizing human identity (approved_by)',
    '',
    'usage: occasio identity set --id <name>   |   occasio identity show',
    '',
  ].join('\n');
}

function run(args) {
  args = args || [];
  if (has(args, '--help') || has(args, '-h')) { process.stdout.write(usage()); return 0; }
  const sub = args[0];

  if (!sub || sub === 'show') {
    const id = currentIdentity();
    process.stdout.write(col.b('\n⚡ Occasio — Identity\n\n'));
    process.stdout.write(`  id:     ${col.c(id.id)}\n`);
    process.stdout.write(`  source: ${id.source === 'explicit' ? col.g('explicit') : col.y('os_fallback')}\n`);
    if (id.source === 'os_fallback') {
      process.stdout.write('\n' + col.d('  Set an explicit identity for attributable approvals:\n    occasio identity set --id <name>\n'));
    }
    process.stdout.write('\n');
    return 0;
  }

  if (sub === 'set') {
    const id = flag(args, '--id');
    if (!id || !String(id).trim()) {
      process.stderr.write('[Occasio] identity set: --id <name> is required\n\n' + usage());
      return 1;
    }
    const file = identityFile();
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify({ id: String(id).trim(), set_at: new Date().toISOString(), source: 'explicit' }, null, 2) + '\n', { mode: 0o600 });
    } catch (e) {
      process.stderr.write(`[Occasio] identity set: cannot write ${file}: ${e.message}\n`);
      return 1;
    }
    process.stdout.write(col.b('\n⚡ Occasio — Identity\n\n'));
    process.stdout.write(`  ${col.g('✓')} explicit identity set: ${col.c(String(id).trim())}\n`);
    process.stdout.write(col.d(`    ${file}\n\n`));
    return 0;
  }

  process.stderr.write(`[Occasio] identity: unknown subcommand "${sub}"\n\n` + usage());
  return 1;
}

module.exports = { run, usage, currentIdentity, identityFile };
