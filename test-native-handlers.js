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

// ── 3. Public API surface — drift guard ────────────────────────────────────
// Lock the set of exported names from src/interceptor and src/runtime so any
// accidental removal (e.g. dropping a re-export during a refactor) fails the
// suite loudly. ADD entries here deliberately; REMOVALS must be deliberate too.
console.log('\n3. Public API surface — drift guard');

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
