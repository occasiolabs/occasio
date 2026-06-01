'use strict';

/**
 * occasio scan [--file <path> | --stdin] [--json]
 *
 * Run the explainable secret detectors (src/scanner/detectors.js) over a file
 * or stdin and print findings: detector · label · confidence · reason · line,
 * with a masked snippet. The matched value is never printed in plaintext.
 *
 * Exit code: 1 when any finding exists (CI-usable), 0 when clean.
 */

const fs = require('fs');
const { detectSecrets } = require('../scanner/detectors');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function flag(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function has(args, name)  { return args.indexOf(name) >= 0; }

function usage() {
  return [
    'occasio scan — detect secrets with explainable findings (prefix / jwt / env-key / entropy)',
    '',
    'usage: occasio scan --file <path>   |   occasio scan --stdin   [--json]',
    '',
    'exit 1 when findings exist (CI gate), 0 when clean. Values are never printed in plaintext.',
    '',
  ].join('\n');
}

function confColor(c) { return c >= 0.9 ? col.r : c >= 0.7 ? col.y : col.d; }

function run(args) {
  args = args || [];
  if (has(args, '--help') || has(args, '-h')) { process.stdout.write(usage()); return 0; }

  const file = flag(args, '--file');
  let text, source;
  try {
    if (file) { text = fs.readFileSync(file, 'utf8'); source = file; }
    else      { text = fs.readFileSync(0, 'utf8');    source = '(stdin)'; }
  } catch (e) {
    process.stderr.write(`[Occasio] scan: cannot read input: ${e.message}\n`);
    return 2;
  }

  const findings = detectSecrets(text);

  if (has(args, '--json')) {
    process.stdout.write(JSON.stringify({ source, findings }, null, 2) + '\n');
    return findings.length ? 1 : 0;
  }

  process.stdout.write(col.b(`\n⚡ Occasio scan`) + col.d(`  ${source}\n\n`));
  if (!findings.length) {
    process.stdout.write(col.g('  ✓ no secrets detected\n\n'));
    return 0;
  }
  for (const f of findings) {
    const conf = `${Math.round(f.confidence * 100)}%`;
    process.stdout.write(
      `  ${col.r('●')} ${col.b(f.detector)} ${col.d('·')} ${f.label} ${col.d('·')} ${confColor(f.confidence)(conf)} ` +
      `${col.d('·')} ${source}:${f.line}\n`
    );
    process.stdout.write(`      ${col.d(f.reason)}\n`);
    process.stdout.write(`      ${col.d('snippet ')} ${f.snippet}\n`);
    process.stdout.write(`      ${col.d('sha256  ')} ${f.value_sha256.slice(0, 16)}…\n`);
  }
  process.stdout.write(col.r(`\n  ✗ ${findings.length} finding(s)\n\n`));
  return 1;
}

module.exports = { run, usage };
