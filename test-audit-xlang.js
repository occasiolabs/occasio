#!/usr/bin/env node
'use strict';

/**
 * test-audit-xlang.js — the Node↔Python canonical-serialization guarantee.
 *
 * The audit row hash is SHA-256(JSON.stringify(rowWithoutHash)) (V8). The
 * independent Python walker (docs/audit_walker.py) MUST reproduce V8 byte-for-
 * byte — including ECMAScript number formatting, where V8 and Python's json.dumps
 * diverge for small floats (V8 "0.00003" vs json.dumps "3e-05"). This pins that:
 * a chain full of adversarial floats/strings must verify under the walker, and a
 * tampered value must be caught.
 */

const fs = require('fs'), os = require('os'), path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const GENESIS = '0'.repeat(64);
const sha = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
// EXACT auditor contract: hash = sha256(JSON.stringify(rowWithoutHash)).
const computeHash = row => sha(JSON.stringify(row));

// The battery: the values that broke it + ECMAScript notation edge cases + the
// realistic per-request cost shape (tiny token×price floats) + string escapes.
const VALUES = [
  0, -0, 30, 1000, 999999,                            // integers
  0.1, 0.2, 0.1 + 0.2, 1.5, 123.456, 100.5,           // ordinary floats
  0.00003, 0.000045, 0.0000012, 9e-5, 0.0001, 0.00012,// the divergence zone
  1e-6, 1e-7, 1e-21, 5e-324,                           // exponential zone
  1e20, 1e21, 1.7976931348623157e308,                 // large / exponential
  -0.00003, -1.5, -1e-7,                               // negatives
  3 / 1e6 * 10, 15 * 0.000003, 1234 * 3.5e-6,          // realistic costs
  'plain', 'a"b\\c/d', 'tab\there', 'new\nline\r\n',   // string escapes
  'unicode é ☃ 🚀', 'ctrlx',               // non-ASCII + control
  { cost: 0.00003, cache_savings: 9e-5, nested: [1, 1e-7, { x: 0.000045 }] }, // nested row-like
  [0.00003, 'x\ny', 1e-7, -0.0],
  'c0-controls:' + String.fromCharCode(1) + String.fromCharCode(31) + String.fromCharCode(8) + ':end', //   \b escaping
];

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'xlang-'));
const file = path.join(TMP, 'chain.jsonl');

// Build a real hash chain, one row per battery value.
let prev = GENESIS;
const lines = [];
VALUES.forEach((v, i) => {
  const rowWithoutHash = { audit_schema: 1, event_type: 'xlang', i, v, prev_hash: prev };
  const hash = computeHash(rowWithoutHash);
  lines.push(JSON.stringify({ ...rowWithoutHash, hash }));
  prev = hash;
});
fs.writeFileSync(file, lines.join('\n') + '\n');

let pass = 0, fail = 0;
const ok = (l, c) => { if (c) { console.log('  ✓ ' + l); pass++; } else { console.error('  ✗ ' + l); fail++; } };

// 1. the walker must verify the whole adversarial chain
const r = spawnSync('python', ['docs/audit_walker.py', file], { encoding: 'utf8' });
ok('Python walker verifies the adversarial chain (' + VALUES.length + ' rows)', r.status === 0 && /OK: \d+ rows verified/.test(r.stdout));
if (r.status !== 0) console.error('    walker said: ' + (r.stdout + r.stderr).trim());

// 2. negative control: tamper one value (leave its hash) → walker must catch it
const tampered = lines.slice();
const obj = JSON.parse(tampered[12]); obj.v = (typeof obj.v === 'number' ? obj.v + 0.000001 : 'X'); tampered[12] = JSON.stringify(obj);
const tfile = path.join(TMP, 'tampered.jsonl');
fs.writeFileSync(tfile, tampered.join('\n') + '\n');
const rt = spawnSync('python', ['docs/audit_walker.py', tfile], { encoding: 'utf8' });
ok('Python walker CATCHES a tampered value (negative control)', rt.status === 1 && /MISMATCH/.test(rt.stderr));

// 3. per-value spot check: walker's recomputed hash == Node's for each value
//    (a single bad value would already fail #1, but this localises a failure)
const py = `
import sys, json, hashlib
sys.path.insert(0, 'docs')
import audit_walker as w
ok=0; bad=0
for line in open(sys.argv[1], encoding='utf-8'):
    line=line.strip()
    if not line: continue
    row=json.loads(line); h=row.pop('hash')
    rec=hashlib.sha256(w.canonical_serialize(row)).hexdigest()
    if rec==h: ok+=1
    else: bad+=1; print('BADROW', row.get('i'), file=sys.stderr)
print(ok, bad)
`;
const rp = spawnSync('python', ['-c', py, file], { encoding: 'utf8' });
ok('every row hash matches (Node≡Python per row)', /(\d+) 0\s*$/.test(rp.stdout.trim()));
if (!/\d+ 0\s*$/.test(rp.stdout.trim())) console.error('    ' + (rp.stdout + rp.stderr).trim());

fs.rmSync(TMP, { recursive: true, force: true });
console.log('\n' + '─'.repeat(40));
if (fail === 0) console.log(`✓ All ${pass} audit xlang tests passed`);
else console.error(`✗ ${fail}/${pass + fail} audit xlang tests failed`);
process.exit(fail === 0 ? 0 : 1);
