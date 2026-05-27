'use strict';

// Worker process for the multi-writer lock test in test-audit-chain.js.
// Spawned by `node test-audit-lock-worker.js <file> <count> <tag>`.
// Each invocation appends `count` rows to `file` and tags each event_id
// with `tag-i` so the parent can disambiguate writers.
//
// IMPORTANT: this worker uses the createAuditor PRODUCTION DEFAULT — no
// explicit { lock: true } argument. It validates that two concurrent
// writers, both constructed the way real users construct them (via
// the same code path as src/index.js and src/mcp-server.js), survive
// contention with the chain intact. If someone later flips the default
// back to lock:false, this test will break, by design.

const { createAuditor } = require('./src/audit/jsonl-auditor');

const [file, countStr, tag] = process.argv.slice(2);
if (!file || !countStr || !tag) {
  console.error('usage: test-audit-lock-worker.js <file> <count> <tag>');
  process.exit(2);
}
const count = parseInt(countStr, 10);

const a = createAuditor(file);
const decision = { action: 'PASS', reason: 'lock-test', policySource: 'default' };
const result   = { passThrough: true };

for (let i = 0; i < count; i++) {
  const event = {
    timestamp: new Date().toISOString(),
    id:        `${tag}-${i}`,
    sessionId: 'lock-test',
    runId:     tag,
    agent:     'test',
    protocol:  'test',
    direction: 'outbound',
    kind:      'tool_call',
    toolName:  'shell_bash',
    toolInput: { command: `echo ${tag} ${i}` },
  };
  const r = a.record(event, decision, result);
  if (!r.ok) {
    console.error(`worker ${tag}: append failed at i=${i}: ${r.error?.message}`);
    process.exit(1);
  }
}
process.exit(0);
