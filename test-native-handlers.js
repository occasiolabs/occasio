#!/usr/bin/env node
'use strict';

/**
 * test-native-handlers.js — unit tests for handlers under
 * src/executor/native-handlers/.
 *
 * Extracted from test-interceptor.js section "23. Todo tool" as the first
 * step of the test-file split outlined in docs/ADAPTER-STAGE-2-MIGRATION.md.
 * As each subsequent native handler (Read, Glob, Grep, Shell) moves to its
 * own module under src/executor/native-handlers/, the corresponding tests
 * should relocate here too — keeping test-interceptor.js focused on
 * dispatch/routing concerns.
 *
 * The imports are deliberately routed through src/interceptor so any
 * future loss of the re-export surface fails this test loudly.
 */

const fs   = require('fs');
const path = require('path');

const {
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
  isReadHandleable,
  handleReadTool,
  readFileNative,
  READ_SKIP_EXTENSIONS,
  isGlobHandleable,
  handleGlobTool,
  globToRegex,
  isGrepHandleable,
  handleGrepTool,
} = require('./src/interceptor');

let passed = 0, failed = 0;
function assert(label, condition, detail = '') {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`);
    failed++;
  }
}

// ── 1. Todo tool — isTodoHandleable, handleTodoWriteTool, handleTodoReadTool ─
console.log('\n1. Todo tool — isTodoHandleable, handleTodoWriteTool, handleTodoReadTool');

assert('isTodoHandleable TodoRead null → true',
  isTodoHandleable(null, 'TodoRead'));
assert('isTodoHandleable TodoRead {} → true',
  isTodoHandleable({}, 'TodoRead'));
assert('isTodoHandleable TodoRead no input → true',
  isTodoHandleable(undefined, 'TodoRead'));

assert('isTodoHandleable TodoWrite null → false',
  !isTodoHandleable(null, 'TodoWrite'));
assert('isTodoHandleable TodoWrite non-object → false',
  !isTodoHandleable('hello', 'TodoWrite'));
assert('isTodoHandleable TodoWrite no todos → false',
  !isTodoHandleable({}, 'TodoWrite'));
assert('isTodoHandleable TodoWrite todos not array → false',
  !isTodoHandleable({ todos: 'bad' }, 'TodoWrite'));
assert('isTodoHandleable TodoWrite todos null → false',
  !isTodoHandleable({ todos: null }, 'TodoWrite'));
assert('isTodoHandleable TodoWrite todos empty array → true',
  isTodoHandleable({ todos: [] }, 'TodoWrite'));
assert('isTodoHandleable TodoWrite valid todos array → true',
  isTodoHandleable({ todos: [{ id: '1', content: 'Do thing', status: 'pending', priority: 'high' }] }, 'TodoWrite'));

assert('isTodoHandleable unknown tool → false',
  !isTodoHandleable({}, 'Write'));

// ── handleTodoWriteTool ────────────────────────────────────────────────────
{
  const store = [];
  const r1 = handleTodoWriteTool(null, store);
  assert('TodoWrite null input → exitCode 1',     r1.exitCode === 1);
  assert('TodoWrite null input → error output',   r1.output.includes('todos'));

  const r2 = handleTodoWriteTool({ todos: 'bad' }, store);
  assert('TodoWrite non-array todos → exitCode 1', r2.exitCode === 1);

  const todos = [
    { id: '1', content: 'First task',  status: 'in_progress', priority: 'high'   },
    { id: '2', content: 'Second task', status: 'pending',     priority: 'medium' },
  ];
  const r3 = handleTodoWriteTool({ todos }, store);
  assert('TodoWrite valid → exitCode 0',        r3.exitCode === 0);
  assert('TodoWrite valid → empty output',      r3.output === '');
  assert('TodoWrite valid → taskCount 2',       r3.taskCount === 2);
  assert('TodoWrite updates store length',      store.length === 2);
  assert('TodoWrite store first id correct',    store[0].id === '1');
  assert('TodoWrite store second id correct',   store[1].id === '2');

  const r4 = handleTodoWriteTool({ todos: [{ id: '3', content: 'Only task', status: 'pending', priority: 'low' }] }, store);
  assert('TodoWrite overwrite → taskCount 1',     r4.taskCount === 1);
  assert('TodoWrite overwrite → store length 1',  store.length === 1);
  assert('TodoWrite overwrite → store has new id', store[0].id === '3');

  const r5 = handleTodoWriteTool({ todos: [] }, store);
  assert('TodoWrite empty todos → exitCode 0',  r5.exitCode === 0);
  assert('TodoWrite empty todos → store empty', store.length === 0);
  assert('TodoWrite empty todos → taskCount 0', r5.taskCount === 0);
}

// ── handleTodoReadTool ─────────────────────────────────────────────────────
{
  const store = [];
  const r1 = handleTodoReadTool(store);
  assert('TodoRead empty store → exitCode 0',     r1.exitCode === 0);
  assert('TodoRead empty store → taskCount 0',    r1.taskCount === 0);
  assert('TodoRead empty store → valid JSON []',  JSON.parse(r1.output) !== undefined && Array.isArray(JSON.parse(r1.output)));
  assert('TodoRead empty store → empty array',    JSON.parse(r1.output).length === 0);

  const todos = [{ id: 'a', content: 'A task', status: 'pending', priority: 'high' }];
  handleTodoWriteTool({ todos }, store);
  const r2 = handleTodoReadTool(store);
  assert('TodoRead after write → taskCount 1',    r2.taskCount === 1);
  const parsed = JSON.parse(r2.output);
  assert('TodoRead after write → correct id',     parsed[0].id === 'a');
  assert('TodoRead after write → correct content', parsed[0].content === 'A task');
}

// ── Session consistency: write/read across rounds ──────────────────────────
{
  const store = [];
  const todos1 = [{ id: '1', content: 'Task one', status: 'pending', priority: 'high' }];
  const todos2 = [
    { id: '2', content: 'Task two',   status: 'in_progress', priority: 'high'   },
    { id: '3', content: 'Task three', status: 'pending',     priority: 'medium' },
  ];

  handleTodoWriteTool({ todos: todos1 }, store);
  assert('Session: first write → 1 task',     store.length === 1);

  handleTodoWriteTool({ todos: todos2 }, store);
  assert('Session: second write → 2 tasks',   store.length === 2);

  const r = handleTodoReadTool(store);
  const parsed = JSON.parse(r.output);
  assert('Session: read after overwrite → 2', parsed.length === 2);
  assert('Session: read reflects last write',  parsed[0].id === '2');
}

// ── 2. Read tool — isReadHandleable, handleReadTool ────────────────────────
console.log('\n2. Read tool — isReadHandleable, handleReadTool');

// Re-export shape: any future loss of the re-export surface should fail loudly.
assert('interceptor re-exports isReadHandleable',  typeof isReadHandleable  === 'function');
assert('interceptor re-exports handleReadTool',    typeof handleReadTool    === 'function');
assert('interceptor re-exports readFileNative',    typeof readFileNative    === 'function');
assert('interceptor re-exports READ_SKIP_EXTENSIONS', READ_SKIP_EXTENSIONS instanceof Set);

const tmpRead  = path.join(require('os').tmpdir(), 'lf-read-test.txt');
const tmpLines = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
fs.writeFileSync(tmpRead, tmpLines.join('\n') + '\n', 'utf8');

try {
  // isReadHandleable — routing decisions
  assert('isReadHandleable: valid text path',        isReadHandleable({ file_path: '/src/index.js' }));
  assert('isReadHandleable: relative path',          isReadHandleable({ file_path: 'src/index.js' }));
  assert('isReadHandleable: null input → false',     !isReadHandleable(null));
  assert('isReadHandleable: missing file_path',      !isReadHandleable({}));
  assert('isReadHandleable: empty string path',      !isReadHandleable({ file_path: '' }));
  assert('isReadHandleable: .pdf → false',           !isReadHandleable({ file_path: 'guide.pdf' }));
  assert('isReadHandleable: .PDF uppercase → false', !isReadHandleable({ file_path: 'GUIDE.PDF' }));
  assert('isReadHandleable: .ipynb → false',         !isReadHandleable({ file_path: 'nb.ipynb' }));
  assert('isReadHandleable: .png → false',           !isReadHandleable({ file_path: 'img.png' }));
  assert('isReadHandleable: pages param → false',    !isReadHandleable({ file_path: 'doc.txt', pages: '1-3' }));
  assert('isReadHandleable: .ts file → true',        isReadHandleable({ file_path: 'src/foo.ts' }));
  assert('isReadHandleable: Windows backslash path accepted',
    isReadHandleable({ file_path: 'C:\\Users\\example\\src\\index.js' }));

  // handleReadTool — output correctness
  {
    const r = handleReadTool({ file_path: tmpRead });
    assert('handleReadTool: exitCode 0',              r.exitCode === 0);
    assert('handleReadTool: output contains alpha',   r.output.includes('alpha'));
    assert('handleReadTool: line numbers present',    r.output.includes('     1\t'));
    assert('handleReadTool: line 3 labeled correctly', r.output.includes('     3\tgamma'));
  }

  // offset and limit
  {
    const r = handleReadTool({ file_path: tmpRead, offset: 1, limit: 2 });
    assert('handleReadTool offset/limit: exitCode 0',  r.exitCode === 0);
    assert('handleReadTool offset/limit: starts at line 2', r.output.startsWith('     2\tbeta'));
    assert('handleReadTool offset/limit: only 2 lines',
      r.output.trim().split('\n').length === 2);
    assert('handleReadTool offset/limit: line numbering reflects file pos',
      r.output.includes('     3\tgamma'));
  }

  // offset=0 explicit (same as default)
  {
    const r = handleReadTool({ file_path: tmpRead, offset: 0, limit: 1 });
    assert('handleReadTool offset=0: starts at line 1', r.output.startsWith('     1\talpha'));
  }

  // missing file
  {
    const r = handleReadTool({ file_path: '/nonexistent-path-xyz-123/file.txt' });
    assert('handleReadTool missing file: exitCode 1',   r.exitCode === 1);
    assert('handleReadTool missing file: error message', r.output.includes('No such file'));
  }

  // empty file_path
  {
    const r = handleReadTool({ file_path: '' });
    assert('handleReadTool empty path: exitCode 1', r.exitCode === 1);
  }

  // null input
  {
    const r = handleReadTool(null);
    assert('handleReadTool null input: exitCode 1', r.exitCode === 1);
  }

} finally {
  try { fs.unlinkSync(tmpRead); } catch { /* tmp cleanup best-effort */ }
}

// ── 3. Glob tool — isGlobHandleable, globToRegex, handleGlobTool ───────────
console.log('\n3. Glob tool — isGlobHandleable, globToRegex, handleGlobTool');

// Re-export shape
assert('interceptor re-exports isGlobHandleable', typeof isGlobHandleable === 'function');
assert('interceptor re-exports handleGlobTool',   typeof handleGlobTool   === 'function');
assert('interceptor re-exports globToRegex',      typeof globToRegex      === 'function');

// isGlobHandleable
assert('isGlobHandleable: null → false',            !isGlobHandleable(null));
assert('isGlobHandleable: empty object → false',    !isGlobHandleable({}));
assert('isGlobHandleable: empty pattern → false',   !isGlobHandleable({ pattern: '' }));
assert('isGlobHandleable: valid pattern → true',    isGlobHandleable({ pattern: '**/*.js' }));
assert('isGlobHandleable: with path → true',        isGlobHandleable({ pattern: '*.ts', path: 'src' }));
assert('isGlobHandleable: semicolon injection → false',  !isGlobHandleable({ pattern: '*.js;rm -rf' }));
assert('isGlobHandleable: pipe injection → false',       !isGlobHandleable({ pattern: '*.js|cat' }));
assert('isGlobHandleable: backtick injection → false',   !isGlobHandleable({ pattern: '`ls`' }));
assert('isGlobHandleable: dollar injection → false',     !isGlobHandleable({ pattern: '$HOME/**' }));
assert('isGlobHandleable: non-string path → false',      !isGlobHandleable({ pattern: '*.js', path: 42 }));
assert('isGlobHandleable: non-string pattern → false',   !isGlobHandleable({ pattern: 123 }));
assert('isGlobHandleable Windows backslash path → true',
  isGlobHandleable({ pattern: '**/*.ts', path: 'C:\\Users\\example\\src' }));

// globToRegex — pattern correctness
{
  const r1 = globToRegex('**/*.js');
  assert('globToRegex: **/*.js matches src/foo.js',    r1.test('src/foo.js'));
  assert('globToRegex: **/*.js matches deep/a/b/c.js', r1.test('deep/a/b/c.js'));
  assert('globToRegex: **/*.js rejects foo.ts',        !r1.test('foo.ts'));

  const r2 = globToRegex('*.ts');
  assert('globToRegex: *.ts matches foo.ts',           r2.test('foo.ts'));
  assert('globToRegex: *.ts rejects src/foo.ts',       !r2.test('src/foo.ts'));

  const r3 = globToRegex('src/*.{ts,tsx}');
  assert('globToRegex: {ts,tsx} matches src/app.ts',   r3.test('src/app.ts'));
  assert('globToRegex: {ts,tsx} matches src/app.tsx',  r3.test('src/app.tsx'));
  assert('globToRegex: {ts,tsx} rejects src/app.js',   !r3.test('src/app.js'));

  const r4 = globToRegex('src/?oo.js');
  assert('globToRegex: ? matches single char',         r4.test('src/foo.js'));
  assert('globToRegex: ? rejects empty',               !r4.test('src/oo.js'));

  const r5 = globToRegex('**');
  assert('globToRegex: ** matches any path',           r5.test('a/b/c.js'));
  assert('globToRegex: ** matches single file',        r5.test('readme.md'));
}

// handleGlobTool — live filesystem
{
  const os  = require('os');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-glob-test-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'src'));
    fs.mkdirSync(path.join(tmpDir, 'src', 'utils'));
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'),   'a');
    fs.writeFileSync(path.join(tmpDir, 'src', 'app.tsx'),    'b');
    fs.writeFileSync(path.join(tmpDir, 'src', 'utils', 'helpers.ts'), 'c');
    fs.writeFileSync(path.join(tmpDir, 'readme.md'),         'd');
    fs.writeFileSync(path.join(tmpDir, 'package.json'),      '{}');

    const r1 = handleGlobTool({ pattern: '**/*.{ts,tsx}', path: tmpDir });
    assert('handleGlobTool: exitCode 0',               r1.exitCode === 0);
    assert('handleGlobTool: finds index.ts',           r1.output.includes('index.ts'));
    assert('handleGlobTool: finds app.tsx',            r1.output.includes('app.tsx'));
    assert('handleGlobTool: finds helpers.ts',         r1.output.includes('helpers.ts'));
    assert('handleGlobTool: excludes readme.md',       !r1.output.includes('readme.md'));
    assert('handleGlobTool: matchCount = 3',           r1.matchCount === 3);

    const r2 = handleGlobTool({ pattern: '*.md', path: tmpDir });
    assert('handleGlobTool *.md: finds readme.md',     r2.output.includes('readme.md'));
    assert('handleGlobTool *.md: matchCount = 1',      r2.matchCount === 1);

    const r3 = handleGlobTool({ pattern: '*.go', path: tmpDir });
    assert('handleGlobTool no matches: exitCode 0',    r3.exitCode === 0);
    assert('handleGlobTool no matches: no-matches msg', r3.output.includes('(no matches)'));
    assert('handleGlobTool no matches: matchCount = 0', r3.matchCount === 0);

    const r4 = handleGlobTool({ pattern: '' });
    assert('handleGlobTool empty pattern: exitCode 1', r4.exitCode === 1);

    const r5 = handleGlobTool(null);
    assert('handleGlobTool null: exitCode 1',          r5.exitCode === 1);

  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ── 4. Grep tool — isGrepHandleable, handleGrepTool ────────────────────────
console.log('\n4. Grep tool — isGrepHandleable, handleGrepTool');

// Re-export shape
assert('interceptor re-exports isGrepHandleable', typeof isGrepHandleable === 'function');
assert('interceptor re-exports handleGrepTool',   typeof handleGrepTool   === 'function');

// isGrepHandleable — guard cases
assert('isGrepHandleable: null → false',              !isGrepHandleable(null));
assert('isGrepHandleable: empty object → false',      !isGrepHandleable({}));
assert('isGrepHandleable: empty pattern → false',     !isGrepHandleable({ pattern: '' }));
assert('isGrepHandleable: non-string pattern → false',!isGrepHandleable({ pattern: 42 }));
assert('isGrepHandleable: valid pattern → true',      isGrepHandleable({ pattern: 'foo' }));
assert('isGrepHandleable: with path → true',          isGrepHandleable({ pattern: 'foo', path: 'src' }));
assert('isGrepHandleable: with glob → true',          isGrepHandleable({ pattern: 'foo', glob: '*.ts' }));
assert('isGrepHandleable: with type → true',          isGrepHandleable({ pattern: 'foo', type: 'ts' }));
assert('isGrepHandleable: content mode → true',       isGrepHandleable({ pattern: 'foo', output_mode: 'content' }));
assert('isGrepHandleable: count mode → true',         isGrepHandleable({ pattern: 'foo', output_mode: 'count' }));
assert('isGrepHandleable: bad output_mode → false',   !isGrepHandleable({ pattern: 'foo', output_mode: 'xml' }));
assert('isGrepHandleable: multiline true → false',    !isGrepHandleable({ pattern: 'foo', multiline: true }));
assert('isGrepHandleable: multiline false → true',    isGrepHandleable({ pattern: 'foo', multiline: false }));
assert('isGrepHandleable: non-string path → false',   !isGrepHandleable({ pattern: 'foo', path: 123 }));
assert('isGrepHandleable: non-string glob → false',   !isGrepHandleable({ pattern: 'foo', glob: true }));
assert('isGrepHandleable: non-string type → false',   !isGrepHandleable({ pattern: 'foo', type: [] }));
assert('isGrepHandleable Windows backslash path → true',
  isGrepHandleable({ pattern: 'foo', path: 'C:\\Users\\example\\src' }));

// handleGrepTool — live filesystem
{
  const os     = require('os');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lf-grep-test-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'src'));
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'),
      'import foo from "bar";\nexport function greet() {}\nconst SECRET_KEY = "abc";\n');
    fs.writeFileSync(path.join(tmpDir, 'src', 'app.ts'),
      'const greeting = "hello world";\nfunction hello() { return 42; }\n');
    fs.writeFileSync(path.join(tmpDir, 'readme.md'),
      '# Hello\nThis project says hello.\n');
    fs.writeFileSync(path.join(tmpDir, 'config.json'),
      '{"hello": true}\n');

    // files_with_matches (default)
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir });
      assert('grep fwm: exitCode 0',              r.exitCode === 0);
      assert('grep fwm: finds app.ts',            r.output.includes('app.ts'));
      assert('grep fwm: finds readme.md',         r.output.includes('readme.md'));
      assert('grep fwm: finds config.json',       r.output.includes('config.json'));
      assert('grep fwm: not index.ts (no hello)', !r.output.includes('index.ts'));
      assert('grep fwm: matchCount ≥ 3',          r.matchCount >= 3);
    }

    // content mode
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir, output_mode: 'content' });
      assert('grep content: exitCode 0',          r.exitCode === 0);
      assert('grep content: line number present', /:\d+:/.test(r.output));
      assert('grep content: hello in output',     r.output.toLowerCase().includes('hello'));
    }

    // count mode
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir, output_mode: 'count' });
      assert('grep count: exitCode 0',            r.exitCode === 0);
      assert('grep count: has :N format',         /:\d+$/.test(r.output.trim().split('\n')[0]));
      assert('grep count: matchCount ≥ 3',        r.matchCount >= 3);
    }

    // case-insensitive (-i)
    {
      const sensitive   = handleGrepTool({ pattern: 'IMPORT', path: tmpDir });
      const insensitive = handleGrepTool({ pattern: 'IMPORT', path: tmpDir, '-i': true });
      assert('grep -i: sensitive finds nothing',  sensitive.matchCount === 0 || !sensitive.output.includes('index.ts'));
      assert('grep -i: insensitive finds import', insensitive.output.includes('index.ts'));
    }

    // context lines (-C)
    {
      const r = handleGrepTool({
        pattern: 'greet', path: tmpDir, output_mode: 'content', '-C': 1,
      });
      assert('grep -C: context lines present',    r.output.split('\n').length > 1);
      assert('grep -C: greet line included',      r.output.includes('greet'));
    }

    // glob filter
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir, glob: '*.md' });
      assert('grep glob *.md: finds readme.md',   r.output.includes('readme.md'));
      assert('grep glob *.md: no .ts files',      !r.output.includes('.ts'));
      assert('grep glob *.md: no .json files',    !r.output.includes('.json'));
    }

    // type filter
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir, type: 'ts' });
      assert('grep type ts: finds app.ts',        r.output.includes('app.ts'));
      assert('grep type ts: no readme.md',        !r.output.includes('readme.md'));
      assert('grep type ts: no config.json',      !r.output.includes('.json'));
    }

    // head_limit
    {
      const r = handleGrepTool({ pattern: 'hello', path: tmpDir, head_limit: 1 });
      assert('grep head_limit: exactly 1 result', r.output.split('\n').filter(l => !l.startsWith('(')).length === 1);
    }

    // no matches
    {
      const r = handleGrepTool({ pattern: 'zzzznothere9999', path: tmpDir });
      assert('grep no matches: exitCode 0',       r.exitCode === 0);
      assert('grep no matches: no-matches msg',   r.output.includes('(no matches)'));
      assert('grep no matches: matchCount 0',     r.matchCount === 0);
    }

    // direct file target
    {
      const r = handleGrepTool({ pattern: 'hello', path: path.join(tmpDir, 'src', 'app.ts') });
      assert('grep direct file: exitCode 0',      r.exitCode === 0);
      assert('grep direct file: finds match',     r.matchCount >= 1);
    }

  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// error cases
{
  const r1 = handleGrepTool({ pattern: '' });
  assert('grep empty pattern: exitCode 1',          r1.exitCode === 1);

  const r2 = handleGrepTool(null);
  assert('grep null input: exitCode 1',             r2.exitCode === 1);

  const r3 = handleGrepTool({ pattern: '[invalid regex' });
  assert('grep invalid regex: exitCode 1',          r3.exitCode === 1);
  assert('grep invalid regex: error in output',     r3.output.includes('invalid pattern'));

  const r4 = handleGrepTool({ pattern: 'foo', path: '/nonexistent-path-xyz-9999' });
  assert('grep bad path: exitCode 1',               r4.exitCode === 1);
}

// ── 5. Public API surface — drift guard ────────────────────────────────────
// Lock the set of exported names from src/interceptor and src/runtime so any
// accidental removal (e.g. dropping a re-export during a refactor) fails the
// suite loudly. ADD entries here deliberately; REMOVALS must be deliberate too.
console.log('\n5. Public API surface — drift guard');

const interceptorExports = Object.keys(require('./src/interceptor')).sort();
const runtimeExports     = Object.keys(require('./src/runtime')).sort();

const expectedInterceptor = [
  'FALLBACK_REASONS',
  'LOCAL_BASH_CMDS',
  'READ_SKIP_EXTENSIONS',
  'blocksToContent',
  'buildFollowUpHeaders',
  'classifyBlock',
  'expandPsEnvVars',
  'globToRegex',
  'handleGlobTool',
  'handleGrepTool',
  'handleReadTool',
  'handleTodoReadTool',
  'handleTodoWriteTool',
  'isBareGitReadOnly',
  'isCdSegment',
  'isCompoundHandleable',
  'isCompoundSegment',
  'isEchoSegment',
  'isGitCSegment',
  'isGlobHandleable',
  'isGrepHandleable',
  'isInterceptable',
  'isNativeHandleable',
  'isPowerShellNativeHandleable',
  'isReadHandleable',
  'isSetLocationSegment',
  'isTodoHandleable',
  'nativeHandle',
  'parseSSE',
  'readFileNative',
  'runLocally',
  'runOneRound',
  'scanToolResults',
].sort();

const expectedRuntime = [
  'GLOB_INJECTION_RE',
  'GLOB_MAX',
  'GLOB_SKIP',
  'GREP_FILE_CAP',
  'GREP_MAX_RESULTS',
  'GREP_TYPE_EXTS',
  'MAX_OUTPUT',
  'READ_SKIP_EXTENSIONS',
  'VALID_GREP_MODES',
  'executeLocalTool',
  'globToRegex',
  'handleGlobTool',
  'handleGrepTool',
  'handleReadTool',
  'handleTodoReadTool',
  'handleTodoWriteTool',
  'isGlobHandleable',
  'isGrepHandleable',
  'isReadHandleable',
  'isTodoHandleable',
  'readFileNative',
  'tryReadGrep',
  'walkGlob',
  'walkGrepFiles',
].sort();

function diffSets(label, actual, expected) {
  const missing = expected.filter(k => !actual.includes(k));
  const extra   = actual.filter(k => !expected.includes(k));
  assert(`${label}: no missing exports`, missing.length === 0,
    missing.length ? `missing=[${missing.join(',')}]` : '');
  assert(`${label}: no unexpected exports`, extra.length === 0,
    extra.length ? `extra=[${extra.join(',')}] — update snapshot if intentional` : '');
}

diffSets('src/interceptor', interceptorExports, expectedInterceptor);
diffSets('src/runtime',     runtimeExports,     expectedRuntime);

console.log('\n────────────────────────────────────────');
if (failed === 0) {
  console.log(`✓ All ${passed} native-handler tests passed\n`);
  process.exit(0);
} else {
  console.error(`✗ ${failed}/${passed + failed} native-handler tests failed\n`);
  process.exit(1);
}
