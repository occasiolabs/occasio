// `occasio register` — installs a `claude()` shell function so the user
// can keep typing `claude` and silently get routed through the proxy.
//
// Idempotent: detects the canonical marker and exits; auto-upgrades the
// legacy `--intercept` snippet to `claude` if found. Best-effort on
// failure — prints a manual instruction rather than crashing.

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`,
};

function registerWindows() {
  const profileDir  = path.join(os.homedir(), 'Documents', 'PowerShell');
  const profileFile = path.join(profileDir, 'Microsoft.PowerShell_profile.ps1');
  const snippet = `\n# Occasio — intercept Claude Code traffic\nfunction claude { occasio claude @args }\n`;
  const alreadyMarker = 'occasio claude @args';
  const legacyMarker  = 'occasio --intercept @args';
  try {
    if (!fs.existsSync(profileDir)) fs.mkdirSync(profileDir, { recursive: true });
    const existing = fs.existsSync(profileFile) ? fs.readFileSync(profileFile, 'utf8') : '';
    if (existing.includes(alreadyMarker)) {
      console.log(col.g('✓ Already registered (PowerShell)'));
      console.log(col.d('  Type: claude'));
    } else if (existing.includes(legacyMarker)) {
      const updated = existing.replace(
        /function claude \{ occasio --intercept @args \}/g,
        'function claude { occasio claude @args }'
      );
      fs.writeFileSync(profileFile, updated);
      console.log(col.g('✓ Updated to canonical form (occasio claude)'));
      console.log('');
      console.log(col.y(`  ⚠  Restart PowerShell — the 'claude' alias is not active yet.`));
      console.log(col.d(`     Open a new terminal, or run:  . $PROFILE`));
      console.log('');
    } else {
      fs.appendFileSync(profileFile, snippet);
      console.log(col.g(`✓ Registered in ${profileFile}`));
      console.log('');
      console.log(col.y(`  ⚠  Restart PowerShell — the 'claude' alias is not active yet.`));
      console.log(col.d(`     Open a new terminal, or run:  . $PROFILE`));
      console.log('');
    }
  } catch (e) {
    console.log(col.r(`✗ Could not write profile: ${e.message}`));
    console.log(col.d(`  Add manually to your PowerShell profile:\n  function claude { occasio claude @args }`));
  }
}

function registerPosix() {
  const rcFile = (process.env.SHELL || '').includes('zsh')
    ? path.join(os.homedir(), '.zshrc')
    : path.join(os.homedir(), '.bashrc');
  const snippet = `\n# Occasio — intercept Claude Code traffic\nclaude() { occasio claude "$@"; }\n`;
  const alreadyMarker = 'occasio claude "$@"';
  const legacyMarker  = 'occasio --intercept "$@"';
  try {
    const existing = fs.existsSync(rcFile) ? fs.readFileSync(rcFile, 'utf8') : '';
    if (existing.includes(alreadyMarker)) {
      console.log(col.g(`✓ Already registered (${rcFile})`));
    } else if (existing.includes(legacyMarker)) {
      const updated = existing.replace(
        /claude\(\) \{ occasio --intercept "\$@"; \}/g,
        'claude() { occasio claude "$@"; }'
      );
      fs.writeFileSync(rcFile, updated);
      console.log(col.g(`✓ Updated to canonical form in ${rcFile}`));
    } else {
      fs.appendFileSync(rcFile, snippet);
      console.log(col.g(`✓ Registered in ${rcFile}`));
    }
    console.log(col.d('  Run: source ' + rcFile + '  — then type: claude'));
  } catch (e) {
    console.log(col.r(`✗ Could not write ${rcFile}: ${e.message}`));
    console.log(col.d(`  Add manually:\n  claude() { occasio claude "$@"; }`));
  }
}

function run() {
  if (process.platform === 'win32') registerWindows();
  else registerPosix();
}

module.exports = { run };
