#!/usr/bin/env node
'use strict';

/**
 * test-doctor-ansi.js: regression for the doctor color-reset bleed.
 *
 * Verifies that every line emitted by `occasio policy doctor` ends with the
 * ANSI reset sequence so Windows Terminal (and other emulators that carry
 * state across line breaks) cannot bleed a colour attribute into the next
 * console.log call. See src/policy/doctor.js (`safe(...)` helper).
 *
 * Strategy: capture console.log output while invoking runDoctorCli with a
 * synthetic logsDir containing one entry, then assert each non-empty emitted
 * line ends with \x1b[0m.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-doctor-ansi-'));
const logsDir = path.join(tmpRoot, 'logs');
fs.mkdirSync(logsDir, { recursive: true });

// One minimal session log entry: aggregate() walks tools[] only so a single
// entry with a representative tools array is enough to exercise the summary +
// at least one suggestion path.
const today = new Date().toISOString().slice(0, 10);
const logFile = path.join(logsDir, `${today}.jsonl`);
const entry = {
  iso: new Date().toISOString(),
  run_id: 'doctor-ansi-test',
  model: 'claude-haiku-4-5',
  tools_attempted: 3,
  tools_local_count: 2,
  tools: [
    { tool: 'Read',  bytes: 1024, kept_bytes: 1024, intercepted: true,  prevention_reason: 'native' },
    { tool: 'Grep',  bytes:  512, kept_bytes:  512, intercepted: true,  prevention_reason: 'native' },
    { tool: 'Bash',  bytes: 2048, kept_bytes: 2048, intercepted: false, prevention_reason: null     },
  ],
};
fs.writeFileSync(logFile, JSON.stringify(entry) + '\n');

const { runDoctorCli } = require('./src/policy/doctor');

// One captured entry per console.log call. The bleed bug we are guarding
// against is "the next console.log inherits residual colour state", so each
// entry is treated as one logical write and must end with an ANSI reset if it
// opened a colour anywhere inside.
const captured = [];
const realLog = console.log;
console.log = (...args) => {
  captured.push(args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
};

try {
  runDoctorCli([], { logsDir });
} finally {
  console.log = realLog;
}

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { realLog(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
}

realLog('\nDoctor ANSI reset coverage');

const ESC   = '\x1b[';
const RESET = '\x1b[0m';

let coloured = 0;
const offenders = [];

for (const entry of captured) {
  if (!entry.includes(ESC)) continue;
  coloured++;
  // After the last newline (if any), what does the entry end with? If the
  // tail of the write has an open colour without a closing reset, the NEXT
  // console.log inherits that state on terminals that buffer at the write
  // boundary. The reset can land anywhere after the last newline.
  const lastNl = entry.lastIndexOf('\n');
  const tail   = lastNl >= 0 ? entry.slice(lastNl + 1) : entry;
  // Either the tail is empty (entry ends with \n, terminal flushes cleanly)
  // or the tail must contain a reset sequence.
  if (tail.length > 0 && !tail.includes(RESET)) {
    offenders.push(entry);
  }
}

assert('at least one coloured emission', coloured > 0,
       `captured ${captured.length} console.log calls`);
assert('every coloured emission closes with ANSI reset', offenders.length === 0,
       offenders.length ? offenders[0].replace(/\x1b\[/g, '\\x1b[').slice(0, 120) : '');

realLog(`\n  ${passed} passed, ${failed} failed`);

try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }

if (failed > 0) process.exit(1);
process.exit(0);
