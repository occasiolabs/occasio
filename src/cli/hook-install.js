'use strict';

/**
 * occasio hook --install — register the PreToolUse hook in Claude Code's settings.
 *
 * Merges (never clobbers) a `hooks.PreToolUse` entry into ~/.claude/settings.json
 * that runs `occasio hook` for Bash/PowerShell tool calls. Idempotent. The hook is
 * a SECOND enforcement point for execution that does not flow through the proxy;
 * it no-ops when the proxy is verified active (see src/cli/hook.js).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const col = {
  g: s => `\x1b[32m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m`,
};

const MATCHER  = 'Bash|PowerShell';
const HOOK_CMD = 'occasio hook';

function settingsFile() {
  return process.env.OCCASIO_CLAUDE_SETTINGS || path.join(os.homedir(), '.claude', 'settings.json');
}
function readSettings(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}
/** Is an Occasio PreToolUse hook already present (any matcher)? */
function hasOccasioHook(settings) {
  const pre = settings && settings.hooks && settings.hooks.PreToolUse;
  if (!Array.isArray(pre)) return false;
  return pre.some(g => Array.isArray(g.hooks) && g.hooks.some(h => h && h.command === HOOK_CMD));
}

function run() {
  const file = settingsFile();
  const settings = readSettings(file);

  if (hasOccasioHook(settings)) {
    process.stdout.write(col.b('\n⚡ Occasio — Hook install\n\n'));
    process.stdout.write(`  ${col.g('✓')} already installed in ${col.c(file)}\n\n`);
    return 0;
  }

  settings.hooks = settings.hooks || {};
  if (!Array.isArray(settings.hooks.PreToolUse)) settings.hooks.PreToolUse = [];
  settings.hooks.PreToolUse.push({ matcher: MATCHER, hooks: [{ type: 'command', command: HOOK_CMD }] });

  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
  } catch (e) {
    process.stderr.write(`[Occasio] hook --install: cannot write ${file}: ${e.message}\n`);
    return 1;
  }

  process.stdout.write(col.b('\n⚡ Occasio — Hook install\n\n'));
  process.stdout.write(`  ${col.g('✓')} PreToolUse hook registered in ${col.c(file)}\n`);
  process.stdout.write(col.d('     matcher Bash|PowerShell → occasio hook. It no-ops when the proxy is\n'));
  process.stdout.write(col.d('     active, and enforces (gate --enforce) when it is not.\n'));
  process.stdout.write(col.d('     Requires `occasio` on PATH (occasio register installs the alias).\n\n'));
  return 0;
}

module.exports = { run, settingsFile, readSettings, hasOccasioHook, MATCHER, HOOK_CMD };
