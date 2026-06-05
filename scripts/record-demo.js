#!/usr/bin/env node
'use strict';

/**
 * record-demo.js — one-take driver for the launch demo video.
 *
 * Runs the REAL Occasio demo commands in the storyboard order from
 * docs/launch/demo-script.md, with a caption before each beat. Nothing here
 * is faked — it shells out to the actual CLI so the recording shows real
 * product output.
 *
 * Usage (record this):
 *   occasio  must be installed:  npm install -g @occasiolabs/occasio
 *   node scripts/record-demo.js
 *
 * By default each beat waits for you to press Enter, so YOU control the pace
 * while screen-recording. Flags / env:
 *   DEMO_AUTO=1        advance automatically (no Enter), ~3s per beat
 *   DEMO_PAUSE=4       seconds per beat in auto mode (default 3)
 *   OCCASIO_BIN="..."  override the CLI command (default: occasio)
 *
 * Recording tips: terminal font >= 18pt, dark theme, fill the frame. Do a
 * dry run first so the timing feels natural. Pair with `occasio eyes --demo`
 * (the browser UI from the landing page) for the hero shot.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');

const OC    = process.env.OCCASIO_BIN || 'occasio';
const AUTO  = process.env.DEMO_AUTO === '1';
const PAUSE = (parseFloat(process.env.DEMO_PAUSE || '3') || 3) * 1000;

const c = {
  cyan:  s => `\x1b[36m${s}\x1b[0m`,
  dim:   s => `\x1b[2m${s}\x1b[0m`,
  bold:  s => `\x1b[1m${s}\x1b[0m`,
};

function sleep(ms) {
  // Blocking sleep without busy-waiting.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function gate(msg) {
  if (AUTO) { sleep(PAUSE); return; }
  process.stdout.write(c.dim(`\n  ${msg || '[Enter for next beat]'} `));
  try { fs.readSync(0, Buffer.alloc(8), 0, 8); } catch { /* non-tty: just continue */ }
  process.stdout.write('\n');
}

function caption(n, total, text) {
  console.log('\n' + c.cyan(`▶ ${n}/${total}  `) + c.bold(text) + '\n');
}

function run(args) {
  const r = spawnSync(OC, args, { stdio: 'inherit', shell: true });
  if (r.error) {
    console.error(`\n[record-demo] could not run "${OC} ${args.join(' ')}": ${r.error.message}`);
    console.error('[record-demo] is Occasio installed?  npm install -g @occasiolabs/occasio');
    process.exit(1);
  }
}

// ── The take ────────────────────────────────────────────────────────────────

console.clear();
console.log(c.bold('\n  Occasio — demo take') + c.dim('   (real CLI output, nothing faked)\n'));
gate('[Enter to start recording the first beat]');

caption(1, 3, 'Your AI agent reads your files. Occasio strips the secrets before they reach the cloud.');
run(['demo']);
gate();

caption(2, 3, 'Every action is hash-chained and Sigstore-signed. Here is the proof, verified two independent ways.');
run(['demo', 'audit']);
gate();

caption(3, 3, 'See it live yourself, no setup:');
console.log('   ' + c.cyan('occasio eyes --demo') + c.dim('        # the browser UI from the landing page'));
console.log('   ' + c.cyan('npm install -g @occasiolabs/occasio'));
console.log('\n   ' + c.dim('useoccasio.com  ·  github.com/occasiolabs/occasio') + '\n');
