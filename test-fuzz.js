#!/usr/bin/env node
'use strict';

/**
 * test-fuzz.js — adversarial-input fuzzer for the occasio classifier and
 * native handlers.
 *
 * Mutates valid tool-use inputs along the four high-impact axes from the
 * threat model (B1, B4):
 *   1. Shell metacharacter injection
 *   2. Quote / escape splicing
 *   3. Path traversal (`..`, encoded, null bytes)
 *   4. Length / structural DoS (long strings, deep nesting in valid shape)
 *
 * For every mutated input we assert four invariants:
 *
 *   I-1  No function throws an uncaught exception.
 *   I-2  Every call returns within FAST_BUDGET_MS (default 100 ms).
 *   I-3  classifyBlock is deterministic — calling twice returns the same
 *        reason and handled flag for the same input.
 *   I-4  Containment: when isInterceptable returns true for a Bash block,
 *        either isNativeHandleable accepts the command, or the cmd has no
 *        SHELL_META outside a compound-handleable structure. (If both fail
 *        but isInterceptable still said true, that is a routing bug.)
 *
 * Seed via OCCASIO_FUZZ_SEED env var for reproducible runs; default seed
 * rotates on each invocation. Iteration count via OCCASIO_FUZZ_ITERS
 * (default 5000 — small enough to fit in `npm test`, large enough that the
 * known mutations actually fire).
 *
 * This is not in the default `npm test` because it walks the local
 * filesystem and may be slow on cold caches. Invoke via `npm run fuzz`.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const {
  classifyBlock,
  isInterceptable,
  isNativeHandleable,
  isReadHandleable,
  isGlobHandleable,
  isGrepHandleable,
  isTodoHandleable,
  handleReadTool,
  handleGlobTool,
  handleGrepTool,
  nativeHandle,
} = require('./src/interceptor');

const SEED = Number(process.env.OCCASIO_FUZZ_SEED) || (Date.now() & 0xffffffff);
const ITERS = Number(process.env.OCCASIO_FUZZ_ITERS) || 5000;
// 2500 ms budget: 500 ms slack above the Glob/Grep wall-clock cap
// (OCCASIO_GLOB_MAX_MS, default 2000 ms). Any call exceeding this is either
// a bug or a regression that defeated the handler-internal deadline — both
// are findings we want to surface.
const FAST_BUDGET_MS = Number(process.env.OCCASIO_FUZZ_BUDGET_MS) || 2500;

console.log(`occasio fuzz: seed=${SEED} iters=${ITERS} budget=${FAST_BUDGET_MS}ms`);

// ── Deterministic PRNG (mulberry32) ───────────────────────────────────────
function mulberry32(s) {
  return function () {
    s = (s + 0x6d2b79f5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(SEED);
const rint = (n) => Math.floor(rng() * n);
const pick = (arr) => arr[rint(arr.length)];

// ── Corpora ────────────────────────────────────────────────────────────────

const SHELL_INJECTIONS = [
  ';', '|', '||', '&&', '`', '$(', '${', '>', '>>', '<', '\\',
  '\n', '\r\n', '\x00', ';rm -rf /', '`whoami`', '$(id)',
  '"; cat /etc/passwd #', "'; cat /etc/passwd #",
];

const PATH_TRAVERSALS = [
  '../', '..\\', '../../', '..%2f', '..%5c',
  '/../', '\\..\\',  // mid-string
  '%2e%2e%2f', '....//',  // double-encoding / over-collapse
  '/etc/passwd', 'C:\\Windows\\System32\\config\\SAM',
  '\\\\?\\C:\\', '/dev/null', '/dev/tcp/evil.example.com/9999',
];

const QUOTE_BREAKS = [
  '"', "'", '\\"', "\\'", '"""', "'''",
  '"; echo pwned "', "'; echo pwned '",
];

const SAFE_BASES = [
  'cat package.json',
  'head -n 5 README.md',
  'git status',
  'git log --oneline -5',
  'git -C src status',
  'find . -name "*.js"',
  'test -f package.json',
  'ls -la',
  'echo hello',
  'cd src && git status',
  'Get-Content README.md',
  'Get-ChildItem -Path src',
  'Test-Path package.json',
  'Select-String -Pattern foo -Path README.md',
];

const READ_PATH_BASES = [
  'README.md', 'src/index.js', './package.json',
  '/etc/hosts', 'C:\\Windows\\System32\\drivers\\etc\\hosts',
];

const GLOB_PATTERN_BASES = [
  '**/*.js', '*.md', 'src/**/*.{ts,tsx}', '?oo.js', '[abc]*.json',
];

const GREP_PATTERN_BASES = [
  'function', 'TODO', '^const\\s+', '\\bclass\\b', 'foo|bar',
];

// ── Mutators ───────────────────────────────────────────────────────────────

function mutateString(s) {
  const mutations = [
    () => s + pick(SHELL_INJECTIONS),
    () => pick(SHELL_INJECTIONS) + s,
    () => s.replace(/\s/, pick(SHELL_INJECTIONS) + ' '),
    () => s + pick(QUOTE_BREAKS),
    () => s.repeat(1 + rint(5)),                            // length
    () => s + 'A'.repeat(rint(4096)),                       // long pad
    () => s + '\0',                                         // null byte
    () => s.split('').reverse().join(''),                   // reverse (often invalid → good)
    () => '',                                               // empty
    () => null,                                             // null input
    () => 42,                                               // wrong type
    () => ({ unexpected: 'object' }),                       // wrong shape
    () => s,                                                // identity
  ];
  return pick(mutations)();
}

function mutatePath(p) {
  if (typeof p !== 'string') return p;
  const mutations = [
    () => pick(PATH_TRAVERSALS) + p,
    () => p + pick(PATH_TRAVERSALS),
    () => p.replace('/', '/' + pick(PATH_TRAVERSALS)),
    () => pick(PATH_TRAVERSALS),
    () => p + '\0' + pick(PATH_TRAVERSALS),
    () => p,
  ];
  return pick(mutations)();
}

// ── Invariant checks ───────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function safeCall(label, fn, input) {
  const start = Date.now();
  let result, err;
  try { result = fn(); } catch (e) { err = e; }
  const elapsed = Date.now() - start;
  if (err) {
    failures.push({ label, input, kind: 'crash', err: err.message });
    failed++;
    return null;
  }
  if (elapsed > FAST_BUDGET_MS) {
    failures.push({ label, input, kind: 'slow', elapsed });
    failed++;
    return null;
  }
  passed++;
  return result;
}

function fuzzOnce(i) {
  // Pick a tool to target this iteration.
  const target = pick(['Read', 'Glob', 'Grep', 'Bash', 'PowerShell', 'TodoWrite', 'TodoRead']);

  let block;
  let cmdForBash = null;

  if (target === 'Read') {
    block = { name: 'Read', input: { file_path: mutatePath(pick(READ_PATH_BASES)) } };
    if (rng() < 0.3) block.input.offset = rint(1000);
    if (rng() < 0.3) block.input.limit  = rint(1000);
    if (rng() < 0.2) block.input.pages  = '1-3';
  } else if (target === 'Glob') {
    block = { name: 'Glob', input: { pattern: mutateString(pick(GLOB_PATTERN_BASES)) } };
    if (rng() < 0.4) block.input.path = mutatePath('src');
  } else if (target === 'Grep') {
    block = { name: 'Grep', input: { pattern: mutateString(pick(GREP_PATTERN_BASES)) } };
    if (rng() < 0.3) block.input.path        = mutatePath('src');
    if (rng() < 0.3) block.input.glob        = mutateString('*.js');
    if (rng() < 0.3) block.input.output_mode = pick(['content', 'count', 'files_with_matches', 'xml']);
    if (rng() < 0.2) block.input.multiline   = rng() < 0.5;
  } else if (target === 'Bash' || target === 'PowerShell') {
    cmdForBash = mutateString(pick(SAFE_BASES));
    block = { name: target, input: { command: cmdForBash } };
  } else {
    // TodoWrite / TodoRead
    const todos = rng() < 0.5
      ? [{ id: '1', content: mutateString('do x'), status: 'pending', priority: 'high' }]
      : pick([null, 'bad', 42, [{}], undefined]);
    block = { name: target, input: { todos } };
  }

  // I-1, I-2: no crash, no slow.
  const handled = safeCall('classifyBlock', () => classifyBlock(block), block);
  const inter   = safeCall('isInterceptable', () => isInterceptable(block), block);

  // I-3: determinism.
  if (handled !== null) {
    const second = safeCall('classifyBlock-determinism', () => classifyBlock(block), block);
    if (second && (second.handled !== handled.handled || second.reason !== handled.reason)) {
      failures.push({ label: 'determinism', input: block, kind: 'nondeterministic',
        first: handled, second });
      failed++;
    } else if (second) {
      passed++;
    }
  }

  // Tool-specific deep calls (the handler must also be crash-safe).
  if (target === 'Read') {
    safeCall('isReadHandleable', () => isReadHandleable(block.input), block.input);
    if (isReadHandleable(block.input)) {
      safeCall('handleReadTool', () => handleReadTool(block.input),   block.input);
    }
  } else if (target === 'Glob') {
    safeCall('isGlobHandleable', () => isGlobHandleable(block.input), block.input);
    if (isGlobHandleable(block.input)) {
      safeCall('handleGlobTool', () => handleGlobTool(block.input),   block.input);
    }
  } else if (target === 'Grep') {
    safeCall('isGrepHandleable', () => isGrepHandleable(block.input), block.input);
    if (isGrepHandleable(block.input)) {
      safeCall('handleGrepTool', () => handleGrepTool(block.input),   block.input);
    }
  } else if (target === 'Bash' && cmdForBash != null && typeof cmdForBash === 'string') {
    safeCall('isNativeHandleable', () => isNativeHandleable(cmdForBash), cmdForBash);
    safeCall('nativeHandle',       () => nativeHandle(cmdForBash),       cmdForBash);

    // I-4: containment. If interceptable, the cmd must not be a raw shell-meta
    // string that nativeHandle declined. This catches whitelist regressions.
    if (inter === true) {
      const nr = (() => { try { return nativeHandle(cmdForBash); } catch { return null; } })();
      if (nr === null && /[;&|`$<>\\]/.test(cmdForBash)) {
        // Allowed exception: `&&` and `;` compound chains that nativeHandle
        // does accept under isCompoundHandleable. If nativeHandle still says
        // no, the routing claimed interceptable for something it can't run
        // natively — that is the bug class we are hunting.
        failures.push({
          label: 'containment',
          input: { cmd: cmdForBash, block },
          kind: 'isInterceptable=true but nativeHandle=null with SHELL_META',
        });
        failed++;
      }
    }
  } else if (target === 'TodoWrite' || target === 'TodoRead') {
    safeCall('isTodoHandleable', () => isTodoHandleable(block.input, target), block.input);
  }
}

// ── Run ────────────────────────────────────────────────────────────────────

const start = Date.now();
for (let i = 0; i < ITERS; i++) {
  fuzzOnce(i);
  if (i % 1000 === 0 && i > 0) {
    process.stdout.write(`  ${i}/${ITERS} (p=${passed} f=${failed})\r`);
  }
}
const elapsed = Date.now() - start;

console.log(`\nfuzz done in ${elapsed} ms — calls passed: ${passed}, failed: ${failed}`);

if (failed > 0) {
  console.error('\nFAILURES (first 20):');
  for (const f of failures.slice(0, 20)) {
    console.error(`  • [${f.kind}] ${f.label}`);
    console.error('     input: ' + JSON.stringify(f.input).slice(0, 200));
    if (f.err)     console.error('     error: ' + f.err);
    if (f.elapsed) console.error('     elapsed: ' + f.elapsed + ' ms');
    if (f.first)   console.error('     first/second: ' +
      JSON.stringify(f.first) + ' vs ' + JSON.stringify(f.second));
  }
  console.error(`\nreproduce: OCCASIO_FUZZ_SEED=${SEED} OCCASIO_FUZZ_ITERS=${ITERS} node test-fuzz.js`);
  process.exit(1);
}

console.log('✓ fuzz clean: no crashes, no slow calls, classifier deterministic, containment held.');
process.exit(0);
