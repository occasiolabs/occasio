#!/usr/bin/env node
'use strict';

/**
 * test-identity-gate.js — the identity gate (P0).
 *
 * One rule under test: an AI agent may *request* an identity, it may not
 * silently *assume* one. Covers:
 *   1. Classifier verdicts (src/policy/identity-classifier.js)
 *   2. Loader compile + validate for deny_commands / identity_approval
 *   3. The acceptance matrix through the engine with the shipped template
 *   4. Audit enrichment: event_type / enforcement_point / coverage per decision,
 *      and the chain still verifies (Node verifier)
 *   5. End-to-end runOneRound BLOCK: the synthetic refusal reaches the agent and
 *      the command never executes
 *   6. occasio gate CLI exit codes (0 allow / 2 deny / 3 approval-pending)
 *   7. v1 (version: 1) policy is byte-for-byte unaffected
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

// Isolate the approval store from the real ~/.occasio (engine.checkIdentityApproval
// now records pending requests on every borrow eval). Set before any require that
// reaches the store.
process.env.OCCASIO_APPROVALS_FILE   = path.join(os.tmpdir(), `idgate-approvals-${process.pid}.jsonl`);
process.env.OCCASIO_APPROVAL_KEY_FILE = path.join(os.tmpdir(), `idgate-approvalkey-${process.pid}`);

require('./src/adapters/claude-code');   // register Bash → shell_bash
const loader   = require('./src/policy/loader');
const engine   = require('./src/policy/engine');
const validate = require('./src/policy/validate');
const { classify } = require('./src/policy/identity-classifier');
const { makeBoundaryEvent } = require('./src/core/boundary-event');
const { runOneRound } = require('./src/interceptor');
const { createAuditor } = require('./src/audit/jsonl-auditor');
const { verifyFile }    = require('./src/audit/verifier');
const gateCli  = require('./src/cli/gate');
const { enforceOutboundDenyPaths, enforceOutboundSecretRedaction, pathIsDenied, resolveInputPath } = require('./src/outbound-policy');
const { scanSecrets } = require('./src/analyzer');
const { dispatch } = require('./src/executor/dispatcher');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}

const TEMPLATE = path.join(__dirname, 'policy-templates', 'strict.yml');
// strictParsed = raw mapping (for _setOverrideForTests, which normalizes it the
// same way load() does). strictPolicy = the compiled form (for direct field
// assertions + gateShellCommand, which consume a normalized policy as-is).
const strictParsed = loader.parse(fs.readFileSync(TEMPLATE, 'utf8'));
const strictPolicy = loader.normalize(strictParsed);

function shellEvent(command) {
  return makeBoundaryEvent({
    direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http',
    sessionId: 's1', runId: 'r1',
    toolName: 'shell_bash', toolInput: { command },
  });
}

// `parsedPolicy` must be the RAW parsed mapping — _setOverrideForTests
// normalizes it (compiling deny_commands / identity_approval) exactly as load()
// would. Passing an already-normalized policy here would double-normalize and
// silently drop the compiled gate arrays.
function evalUnder(parsedPolicy, command) {
  loader._setOverrideForTests(parsedPolicy);
  try { return engine.evaluate(shellEvent(command)); }
  finally { loader._setOverrideForTests(null); }
}

// ── 1. Classifier ──────────────────────────────────────────────────────────
console.log('\n1. identity classifier');
{
  const secret = classify('printenv');
  assert('printenv → secret_identity_access / deny',
    secret && secret.action === 'secret_identity_access' && secret.default === 'deny');
  const key = classify('cat ~/.ssh/id_ed25519');
  assert('ssh key read → secret_identity_access',
    key && key.action === 'secret_identity_access');
  const ssh = classify('ssh azureuser@host');
  assert('ssh → identity_borrow / production / require_approval',
    ssh && ssh.action === 'identity_borrow' && ssh.target_class === 'production' && ssh.default === 'require_approval');
  const az = classify('az vm run-command invoke');
  assert('az → cloud_control_plane / cloud', az && az.action === 'cloud_control_plane' && az.target_class === 'cloud');
  const sudo = classify('sudo systemctl restart x');
  assert('sudo → service_control', sudo && sudo.action === 'service_control');
  assert('pytest → null (unrecognized)', classify('python -m pytest') === null);
  assert('editing source → null', classify('cat src/backtest.py') === null);
}

// ── 2. Loader compile + validate ────────────────────────────────────────────
console.log('\n2. loader + validate');
{
  assert('template compiles deny_commands', Array.isArray(strictPolicy.deny_commands) && strictPolicy.deny_commands.length >= 2);
  assert('template compiles identity_approval', Array.isArray(strictPolicy.identity_approval) && strictPolicy.identity_approval.length >= 3);
  assert('deny_commands entries are { label, regex }',
    strictPolicy.deny_commands.every(c => typeof c.label === 'string' && c.regex instanceof RegExp));
  assert('identity_approval entries carry target_class',
    strictPolicy.identity_approval.every(r => typeof r.target_class === 'string'));

  const { errors, warnings } = validate.validatePolicy(loader.parse(fs.readFileSync(TEMPLATE, 'utf8')));
  assert('template validates 0 errors', errors.length === 0, JSON.stringify(errors));
  assert('template validates 0 warnings', warnings.length === 0, JSON.stringify(warnings));

  assert('deny_commands / identity_approval in KNOWN_TOP_LEVEL',
    validate.KNOWN_TOP_LEVEL.has('deny_commands') && validate.KNOWN_TOP_LEVEL.has('identity_approval'));

  // invalid entries → errors
  const bad = validate.validatePolicy({
    deny_commands: { x: { command_regex: '(' } },                  // uncompilable
    identity_approval: { y: { command_regex: '\\bssh\\b', target_class: 'mars' } }, // bad enum
  });
  assert('uncompilable deny_commands regex → error',
    bad.errors.some(e => e.path.startsWith('deny_commands.x')));
  assert('invalid target_class → error',
    bad.errors.some(e => e.path === 'identity_approval.y.target_class'));

  // loader skip-invalid: a bad entry is dropped, good ones survive
  const mixed = loader.normalize(loader.parse([
    'identity_approval:',
    '  good:',
    "    command_regex: '\\bssh\\b'",
    '  bad:',
    '    command_regex: ',
  ].join('\n')));
  assert('loader skips the invalid identity_approval entry, keeps the good one',
    mixed.identity_approval.length === 1 && mixed.identity_approval[0].label === 'good');
}

// ── 3. Acceptance matrix ─────────────────────────────────────────────────────
console.log('\n3. acceptance matrix (strict-identity-gate)');
{
  const MATRIX = [
    ['cat .env',                                    'BLOCK',  null],
    ['printenv',                                    'BLOCK',  'env_dump'],
    ['env',                                         'BLOCK',  'env_dump'],
    ['grep -R EXAMPLE_API_KEY ~',                     'BLOCK',  'cred_discovery'],
    ['cat ~/.ssh/id_ed25519',                       'BLOCK',  null],
    ['ssh azureuser@bot-server',                    'BLOCK',  'approval_required'],
    ['az vm run-command invoke -g rg -n vm',        'BLOCK',  'approval_required'],
    ['sudo systemctl restart bias-bot.service',     'BLOCK',  'approval_required'],
    ['python -m pytest',                            'PASS',   null],
  ];
  for (const [command, action, reason] of MATRIX) {
    const d = evalUnder(strictParsed, command);
    const okAction = d.action === action;
    const okReason = reason === null || d.reason === reason;
    assert(`${command} → ${action}${reason ? '/' + reason : ''}`, okAction && okReason,
      `got ${d.action}/${d.reason}`);
  }
}

// ── 3b. Tool-agnostic path protection (adversarial) ──────────────────────────
// A sensitive FILE must be blocked regardless of which tool or command reads it,
// and WITHOUT relying on a command-string coincidence. Proven two ways: every
// read variant blocks via deny_paths, and it still holds with deny_commands
// stripped entirely.
console.log('\n3b. tool-agnostic path protection (adversarial)');
{
  // path-only policy: the template minus deny_commands
  const pathOnlyParsed = JSON.parse(JSON.stringify(strictParsed));
  delete pathOnlyParsed.deny_commands;

  const SHELL_READS = [
    'head .env', 'less .env', 'tail .env', "grep '' .env", "awk '{print}' .env",
    'cp .env /tmp/x', 'cat ./.env', 'cat "$HOME/.env"', 'cat .env',
    'cat ~/.ssh/id_ed25519', 'cat /tmp/stolen/id_rsa', 'cp /home/app/.env.production /tmp',
  ];
  for (const cmd of SHELL_READS) {
    const d = engine.gateShellCommand(cmd, strictPolicy);
    assert(`shell: ${cmd} → BLOCK via deny_paths`, d.action === 'BLOCK' && d.reason === 'path-denied', `${d.action}/${d.reason}`);
  }
  // command-regex independence: still blocked with deny_commands removed
  const pathOnly = loader.normalize(pathOnlyParsed);
  for (const cmd of SHELL_READS) {
    const d = engine.gateShellCommand(cmd, pathOnly);
    assert(`shell (no deny_commands): ${cmd} → still BLOCK`, d.action === 'BLOCK' && d.reason === 'path-denied', `${d.action}/${d.reason}`);
  }
  // the critical hole: the typed Read tool on .env / keys
  const READ_TARGETS = ['.env', './.env', 'config/.env', '.env.production', '~/.ssh/id_ed25519', '/tmp/stolen/id_rsa'];
  loader._setOverrideForTests(pathOnlyParsed);
  for (const fp of READ_TARGETS) {
    const ev = makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code',
      protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: fp } });
    const d = engine.evaluate(ev);
    assert(`Read ${fp} → BLOCK via deny_paths (no deny_commands)`, d.action === 'BLOCK' && d.reason === 'path-denied', `${d.action}/${d.reason}`);
  }
  loader._setOverrideForTests(null);

  // a non-sensitive read is NOT over-blocked
  loader._setOverrideForTests(strictParsed);
  const okRead = engine.evaluate(makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code',
    protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: 'src/backtest.py' } }));
  assert('Read src/backtest.py → not blocked', okRead.action !== 'BLOCK' || okRead.reason !== 'path-denied');
  assert('shell: cat src/app.js → not path-denied', engine.gateShellCommand('cat src/app.js', strictPolicy).reason !== 'path-denied');
  loader._setOverrideForTests(null);

  // glob matcher unit checks (basename anchoring — `**/.env` must not match config.env)
  const gp = loader.normalize(loader.parse('deny_paths:\n  - "**/.env"\n'));
  const ev2 = (fp) => engine.evaluate(makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code',
    protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: fp } }));
  loader._setOverrideForTests(loader.parse('deny_paths:\n  - "**/.env"\n'));
  assert('glob **/.env matches /x/y/.env', ev2('/x/y/.env').reason === 'path-denied');
  assert('glob **/.env does NOT match config.env', ev2('/x/y/config.env').reason !== 'path-denied');
  loader._setOverrideForTests(null);
  void gp;
}

// ── 3c. Adversarial wave 2 (env-dump indirection, evasion, backstop) ─────────
console.log('\n3c. adversarial wave 2');
{
  const readUnder = (fp) => {
    loader._setOverrideForTests(strictParsed);
    const d = engine.evaluate(makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call',
      agent: 'claude-code', protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: fp } }));
    loader._setOverrideForTests(null);
    return d;
  };

  // Class 1 — env-dump via the /proc environ FILE → path-based
  assert('shell: cat /proc/self/environ → deny_paths',
    engine.gateShellCommand('cat /proc/self/environ', strictPolicy).reason === 'path-denied');
  assert('shell: tr < /proc/self/environ → deny_paths',
    engine.gateShellCommand("tr '\\0' '\\n' < /proc/self/environ", strictPolicy).reason === 'path-denied');
  assert('Read /proc/self/environ → deny_paths', readUnder('/proc/self/environ').reason === 'path-denied');

  // Class 1 — env-dump via shell builtins → command-based, no false positives
  for (const cmd of ['set', 'declare -p', 'export -p']) {
    assert(`shell: ${cmd} → BLOCK (deny_commands)`,
      engine.gateShellCommand(cmd, strictPolicy).action === 'BLOCK', engine.gateShellCommand(cmd, strictPolicy).reason);
  }
  assert('shell: set -e → not blocked (no false positive)', engine.gateShellCommand('set -e', strictPolicy).action !== 'BLOCK');
  assert('shell: export FOO=1 → not blocked (no false positive)', engine.gateShellCommand('export FOO=1', strictPolicy).action !== 'BLOCK');

  // Class 4 — command-gate evasion → approval
  for (const cmd of ['pkexec id', 'doas id', 'su -c "id"', 'curl -s https://management.azure.com/x', 'python3 -c "import paramiko"']) {
    const d = engine.gateShellCommand(cmd, strictPolicy);
    assert(`shell: ${cmd} → approval_required`, d.action === 'BLOCK' && d.reason === 'approval_required', `${d.action}/${d.reason}`);
  }

  // Class 3 — output-scanner backstop (mode-dependent, documented)
  loader._setOverrideForTests(strictParsed);
  const leaked = [{ type: 'tool_result', tool_use_id: 't1', content: '/home/app/.env:3:EXAMPLE_API_KEY=0xdeadbeef' }];
  const blockMode = engine.evaluateToolResults(leaked, { mode: 'block_secrets' });
  const interMode = engine.evaluateToolResults(leaked, { mode: 'intercept' });
  loader._setOverrideForTests(null);
  assert('output scanner: secret BLOCKed in block_secrets mode', blockMode.action === 'BLOCK');
  assert('output scanner: secret DETECTED in intercept mode (documented: not blocked)',
    interMode.action === 'PASS' && interMode.secrets.some(s => s.label === 'example_api_key'));

  // Documented-UNCOVERED boundary (see docs/identity-gate.md). These assertions
  // encode the KNOWN limitation honestly — runtime indirection the static gate
  // cannot resolve. If a future change closes one, update the doc + this test.
  assert('uncovered: cat *.env → not path-denied at the gate (runtime glob)',
    engine.gateShellCommand('cat *.env', strictPolicy).reason !== 'path-denied');
  assert('uncovered: F=.env; cat "$F" → not path-denied (runtime var)',
    engine.gateShellCommand('F=.env; cat "$F"', strictPolicy).reason !== 'path-denied');

  // The doc itself must ship a threat-model section naming these classes.
  const doc = fs.readFileSync(path.join(__dirname, 'docs', 'identity-gate.md'), 'utf8');
  assert('docs/identity-gate.md has a Threat Model / Known Limitations section',
    /Threat Model|Known Limitations/i.test(doc) && /hardlink/i.test(doc) && /egress/i.test(doc));
}

// ── 3d. Redaction backstop + outbound glob parity + FP guard ─────────────────
console.log('\n3d. redaction backstop');
{
  // Regression for the dual-matcher drift bug: the OUTBOUND gate must honor the
  // same deny_paths globs as the tool-call gate. A pre-baked Read of .env
  // injected as auto-context must be stripped.
  const outBody = { messages: [{ role: 'user', content: [
    { type: 'tool_use', id: 'o1', name: 'Read', input: { file_path: '/home/app/.env' } },
    { type: 'tool_result', tool_use_id: 'o1', content: 'EXAMPLE_API_KEY=0xabc\nDB_HOST=prod' },
  ] }] };
  const stripped = enforceOutboundDenyPaths(outBody, strictPolicy);
  assert('outbound gate strips pre-baked .env Read (glob parity)', stripped.strips.length === 1);
  const sTr = stripped.messages[0].content.find(b => b.type === 'tool_result');
  assert('stripped content no longer contains the secret', !/EXAMPLE_API_KEY/.test(sTr.content));

  // Redaction: a secret in an agent-submitted tool_result is masked + labeled.
  const redBody = { messages: [{ role: 'user', content: [
    { type: 'tool_use', id: 'r1', name: 'Bash', input: { command: 'grep -ri secret /home' } },
    { type: 'tool_result', tool_use_id: 'r1', content: '/home/app/x:3:EXAMPLE_API_KEY=0xdeadbeef' },
  ] }] };
  const red = enforceOutboundSecretRedaction(redBody, strictPolicy);
  assert('grep -ri output: secret redacted', red.redactions.length === 1 && red.redactions[0].labels.includes('example_api_key'));
  const rTr = red.messages[0].content.find(b => b.type === 'tool_result');
  assert('redacted output masks the value', !/0xdeadbeef/.test(rTr.content));

  // The redaction must emit a first-class secret_redacted audit event with
  // coverage:best-effort + severity:low (machine-separable from enforced rows).
  const file = path.join(os.tmpdir(), `idgate-redact-${process.pid}-${Date.now()}.jsonl`);
  const auditor = createAuditor(file, { lock: false });
  for (const r of red.redactions) {
    auditor.record(
      makeBoundaryEvent({ direction: 'outbound', kind: 'tool_call', agent: 'claude-code',
        protocol: 'anthropic-http', runId: 'r1', toolName: 'shell_bash' }),
      { action: 'TRANSFORM', reason: r.reason, transform: 'redact-secrets', policySource: 'user' },
      { transformed: true, secretsRedacted: new Array(r.secretsRedacted), secretLabels: r.labels },
    );
  }
  const row = JSON.parse(fs.readFileSync(file, 'utf8').trim().split('\n').pop());
  assert('secret_redacted event_type', row.event_type === 'secret_redacted');
  assert('redaction coverage = best-effort', row.coverage === 'best-effort');
  assert('redaction severity = low', row.severity === 'low');
  assert('redaction records labels not values', Array.isArray(row.secret_labels) && row.secret_labels.includes('example_api_key') && !JSON.stringify(row).includes('0xdeadbeef'));
  assert('redaction chain verifies', verifyFile(file).ok === true);
  try { fs.unlinkSync(file); } catch { /* ignore */ }

  // PRECISION guard: canonical secret-LOOKING benigns must pass un-redacted.
  // Fixes the precision expectation as a regression, not just recall.
  const opts = { extraPatterns: strictPolicy.deny_patterns };
  const benign = {
    'UUID':            '550e8400-e29b-41d4-a716-446655440000',
    'git SHA':         'a94db57c1e2f3a4b5c6d7e8f9012345678abcdef',
    'base64 config':   'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==',
    'semver':          'v1.2.3-rc.4+build.567',
  };
  for (const [name, val] of Object.entries(benign)) {
    assert(`FP guard: ${name} not flagged as secret`, scanSecrets(val, opts).length === 0, JSON.stringify(scanSecrets(val, opts)));
  }

  // Crown-jewel vector — documented UNCOVERED (no path token; encoded output).
  const cj = 'python3 -c "import base64,os;print(base64.b64encode(os.environ[\'EXAMPLE_API_KEY\'].encode()))"';
  assert('crown-jewel: pathless env read not blocked at gate (documented uncovered)',
    engine.gateShellCommand(cj, strictPolicy).reason !== 'path-denied');
  const doc = fs.readFileSync(path.join(__dirname, 'docs', 'identity-gate.md'), 'utf8');
  assert('docs frame the direct-env-read threat + egress layer',
    /highest-value target/i.test(doc) && /egress/i.test(doc));
  assert('docs label redaction best-effort', /best-effort/i.test(doc));
}

// ── 3e. Cross-gate consistency guard (pins the drift-bug class shut) ─────────
// The same sensitive set must be classified identically by the inbound
// tool-call gate, the outbound auto-context gate, and the redaction detector.
// A future divergence (a new gate with its own weaker matcher) trips this.
console.log('\n3e. cross-gate consistency');
{
  const SENSITIVE = ['/home/app/.env', '/proc/self/environ', '/tmp/keys/id_rsa', '/home/u/.env.production'];
  loader._setOverrideForTests(strictParsed);
  for (const fp of SENSITIVE) {
    const inbound = engine.evaluate(makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call',
      agent: 'claude-code', protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: fp } })).reason === 'path-denied';
    const outbound = pathIsDenied(resolveInputPath(fp), strictPolicy) === 'path-denied';
    assert(`path gate parity: ${fp} inbound==outbound (both denied)`, inbound === true && outbound === true, `inbound=${inbound} outbound=${outbound}`);
  }
  // A non-sensitive path must be allowed by BOTH gates (not just over-blocked).
  const okFp = '/home/app/src/index.js';
  const okIn = engine.evaluate(makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call',
    agent: 'claude-code', protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: okFp } })).reason !== 'path-denied';
  const okOut = pathIsDenied(resolveInputPath(okFp), strictPolicy) !== 'path-denied';
  assert('path gate parity: benign path allowed by both gates', okIn && okOut);
  loader._setOverrideForTests(null);

  // Redaction detector parity: path-1 (dispatcher TRANSFORM) and path-2
  // (outbound) must both redact the SAME custom deny_pattern secret.
  (async () => {
    const tmp = path.join(os.tmpdir(), `idgate-p1-${process.pid}-${Date.now()}.txt`);
    fs.writeFileSync(tmp, 'EXAMPLE_API_KEY=0xfeedface\nharmless');
    const dec = { action: 'TRANSFORM', transform: 'redact-secrets', reason: 'r', extraPatterns: strictPolicy.deny_patterns };
    const p1 = await dispatch(
      makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code',
        protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: tmp } }), dec, {});
    fs.unlinkSync(tmp);
    const p2body = { messages: [{ role: 'user', content: [
      { type: 'tool_use', id: 'p2', name: 'Bash', input: { command: 'grep -ri x /home' } },
      { type: 'tool_result', tool_use_id: 'p2', content: 'EXAMPLE_API_KEY=0xfeedface' },
    ] }] };
    const p2 = enforceOutboundSecretRedaction(p2body, strictPolicy);
    const p1Redacted = !/0xfeedface/.test(p1.output);
    const p2Redacted = p2.redactions.length === 1 && !/0xfeedface/.test(p2.messages[0].content[1].content);
    assert('redaction parity: path-1 dispatcher redacts custom deny_pattern', p1Redacted);
    assert('redaction parity: path-2 outbound redacts custom deny_pattern', p2Redacted);
    assert('redaction parity: path-1 == path-2 on the same secret', p1Redacted === p2Redacted && p1Redacted === true);
    runConsistencyTail();
  })();
}

function runConsistencyTail() {

// ── 4. Audit enrichment + chain integrity ────────────────────────────────────
console.log('\n4. audit enrichment');
{
  const pipeline = require('./src/core/pipeline');
  const file = path.join(os.tmpdir(), `idgate-test-${process.pid}-${Date.now()}.jsonl`);
  const auditor = createAuditor(file, { lock: false });

  loader._setOverrideForTests(strictParsed);
  (async () => {
    const denyRes = await pipeline.processToolEvent(shellEvent('printenv'), { auditor });
    const apprRes = await pipeline.processToolEvent(shellEvent('ssh host'), { auditor });
    await pipeline.processToolEvent(shellEvent('python -m pytest'), { auditor }); // PASS, no identity
    loader._setOverrideForTests(null);

    assert('deny decision is BLOCK', denyRes.decision.action === 'BLOCK');
    assert('approval decision carries approval_required', apprRes.decision.approval_required === true);

    const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    const deny = rows.find(r => r.reason === 'env_dump');
    const appr = rows.find(r => r.reason === 'approval_required');
    const pass = rows.find(r => r.action === 'PASS');

    assert('deny row event_type = secret_identity_access_blocked', deny && deny.event_type === 'secret_identity_access_blocked');
    assert('approval row event_type = identity_borrow_request', appr && appr.event_type === 'identity_borrow_request');
    assert('deny row enforcement_point = proxy', deny && deny.enforcement_point === 'proxy');
    assert('deny row coverage = enforced', deny && deny.coverage === 'enforced');
    assert('approval row target_class = production', appr && appr.identity_requested && appr.identity_requested.target_class === 'production');
    assert('approval row has pending approval', appr && appr.approval && appr.approval.state === 'pending');
    assert('deny row has delegator id', deny && deny.delegator && typeof deny.delegator.id === 'string');
    assert('deny row command_hash is 64-hex', deny && deny.tool && /^[0-9a-f]{64}$/.test(deny.tool.command_hash));
    assert('PASS row carries no identity fields', pass && pass.event_type === undefined && pass.enforcement_point === undefined);

    const v = verifyFile(file);
    assert('enriched chain verifies (Node)', v.ok === true, JSON.stringify(v));
    try { fs.unlinkSync(file); } catch { /* ignore */ }

    runRemaining();
  })();
}

function runRemaining() {
  // ── 5. End-to-end runOneRound BLOCK ───────────────────────────────────────
  console.log('\n5. runOneRound — synthetic refusal reaches agent, command never runs');
  loader._setOverrideForTests(strictParsed);
  (async () => {
    const blk = { type: 'tool_use', id: 'tu_ssh', name: 'Bash', input: { command: 'ssh azureuser@bot-server' } };
    const out = await runOneRound([blk], {
      mode: 'intercept', todoStore: [], sessionId: 's', runId: 'r',
      auditor: null, verbose: false, agent: 'claude-code',
    });
    loader._setOverrideForTests(null);

    const content = out.toolResults[0] && out.toolResults[0].content;
    assert('agent receives a tool_result (turn stayed in the loop)', typeof content === 'string');
    assert('refusal mentions human approval', /human approval/i.test(content || ''), content);
    assert('refusal states request-not-assume', /request it, not assume it/i.test(content || ''));
    assert('blocked call recorded in toolsRun', out.toolsRun.some(t => t.blocked === true));
    assert('no command output leaked (never executed)', !/uid=|gid=|Linux|Microsoft Windows/i.test(content || ''));

    runCliAndV1();
  })();
}

function runCliAndV1() {
  // ── 6. occasio gate CLI exit codes ────────────────────────────────────────
  console.log('\n6. occasio gate CLI');
  {
    const args = (cmd) => [cmd, '--file', TEMPLATE, '--json'];
    // capture stdout
    function gateExit(cmd) {
      const orig = process.stdout.write;
      process.stdout.write = () => true;
      let code;
      try { code = gateCli.run(args(cmd)); } finally { process.stdout.write = orig; }
      return code;
    }
    assert('gate printenv → exit 2 (deny)',  gateExit('printenv') === 2);
    assert('gate ssh → exit 3 (approval)',   gateExit('ssh azureuser@host') === 3);
    assert('gate az → exit 3 (approval)',    gateExit('az vm run-command') === 3);
    assert('gate sudo → exit 3 (approval)',  gateExit('sudo systemctl restart x') === 3);
    assert('gate pytest → exit 0 (allow)',   gateExit('python -m pytest') === 0);
    // no-command case: suppress the usage banner it prints to stderr/stdout
    {
      const o = process.stdout.write, e = process.stderr.write;
      process.stdout.write = () => true; process.stderr.write = () => true;
      let code;
      try { code = gateCli.run(['--file', TEMPLATE]); } finally { process.stdout.write = o; process.stderr.write = e; }
      assert('gate no command → exit 1', code === 1);
    }
  }

  // ── 7. v1 policy byte-for-byte unaffected ─────────────────────────────────
  console.log('\n7. v1 policy unaffected (gate is opt-in)');
  {
    // A v1 policy with no identity keys must not block any identity command.
    const v1Parsed = loader.parse('version: 1\nblock_secrets_in_tool_results: true\n');
    const v1 = loader.normalize(v1Parsed);
    assert('v1 default deny_commands is empty', Array.isArray(v1.deny_commands) && v1.deny_commands.length === 0);
    assert('v1 default identity_approval is empty', Array.isArray(v1.identity_approval) && v1.identity_approval.length === 0);
    for (const cmd of ['printenv', 'ssh host', 'az vm run-command', 'sudo systemctl restart x']) {
      const d = evalUnder(v1Parsed, cmd);
      assert(`v1: ${cmd} not blocked by identity gate`, d.action !== 'BLOCK', `${d.action}/${d.reason}`);
    }
    // gateShellCommand on an empty policy → allow
    assert('gateShellCommand(v1, ssh) → PASS', engine.gateShellCommand('ssh host', v1).action === 'PASS');
  }

  // ── summary ───────────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(40));
  if (failed === 0) console.log(`✓ All ${passed} identity-gate tests passed`);
  else console.error(`✗ ${failed}/${passed + failed} identity-gate tests failed`);
  process.exit(failed === 0 ? 0 : 1);
}
} // end runConsistencyTail (sections 4–7 run after the 3e async parity check)
