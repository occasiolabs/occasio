#!/usr/bin/env node
'use strict';

/**
 * test-identity-approval.js — the human-vs-agent approval handshake.
 *
 * Covers: lifecycle (request→approve--once→consume→re-block), command_hash scope
 * (least-privilege), TTL + cap + expiry signal, fail-closed store, consume-once,
 * identity provenance, redaction-still-on, the control-plane deny-zone (proof the
 * handshake is not self-service), the HMAC forgery guard, and the documented-
 * uncovered residual. Chain verified by Node + the Python walker.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

// Isolate every store/identity/audit path from the real ~/.occasio. Set before
// any require that reaches them.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'idapprv-'));
process.env.OCCASIO_APPROVALS_FILE    = path.join(TMP, 'approvals.jsonl');
process.env.OCCASIO_APPROVAL_KEY_FILE = path.join(TMP, 'approval-key');
process.env.OCCASIO_IDENTITY_FILE     = path.join(TMP, 'identity.json');
process.env.OCCASIO_AUDIT_FILE        = path.join(TMP, 'pipeline-events.jsonl');

require('./src/adapters/claude-code');
const loader   = require('./src/policy/loader');
const engine   = require('./src/policy/engine');
const { runToolLoop } = require('./src/adapters/claude-code');
const { createIdentityStore, getStore, commandHash } = require('./src/policy/identity-store');
const { createAuditor } = require('./src/audit/jsonl-auditor');
const { verifyFile }    = require('./src/audit/verifier');
const { makeBoundaryEvent } = require('./src/core/boundary-event');
const { enforceOutboundSecretRedaction } = require('./src/outbound-policy');
const approvalsCli = require('./src/cli/approvals');
const identityCli  = require('./src/cli/identity');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`); failed++; }
}
function quiet(fn) { const o = process.stdout.write, e = process.stderr.write; process.stdout.write = () => true; process.stderr.write = () => true; try { return fn(); } finally { process.stdout.write = o; process.stderr.write = e; } }
function sleep(ms) { const until = Date.now() + ms; while (Date.now() < until) { /* spin */ } }

const strictParsed = loader.parse(fs.readFileSync(path.join(__dirname, 'policy-templates', 'strict.yml'), 'utf8'));
loader._setOverrideForTests(strictParsed);

function ev(cmd) {
  return makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code',
    protocol: 'anthropic-http', toolName: 'shell_bash', toolInput: { command: cmd } });
}
function sse(cmd) {
  const L = [
    { type: 'message_start', message: { id: 'm1', type: 'message', role: 'assistant', model: 'x', content: [], stop_reason: null, usage: { input_tokens: 5, output_tokens: 0 } } },
    { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'tu1', name: 'Bash', input: {} } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify({ command: cmd }) } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 10 } },
    { type: 'message_stop' },
  ];
  return Buffer.from(L.map(o => `data: ${JSON.stringify(o)}\n\n`).join(''), 'utf8');
}

(async () => {
  const store = getStore();
  const pipeline = require('./src/core/pipeline');

  // A blocked borrow through the recording pipeline writes the identity_borrow_request
  // audit row (engine.evaluate alone is read-only). No cloud call.
  await pipeline.processToolEvent(ev('ssh requestrow@host'),
    { auditor: createAuditor(process.env.OCCASIO_AUDIT_FILE, { lock: false }) });

  // ── 1. Lifecycle ──────────────────────────────────────────────────────────
  console.log('\n1. lifecycle: request → approve --once → consume → re-block');
  {
    const SSH = 'ssh azureuser@bot-server';
    const d1 = engine.evaluate(ev(SSH));
    assert('request → BLOCK approval_required with id', d1.action === 'BLOCK' && d1.reason === 'approval_required' && /^apr_/.test(d1.approval_id || ''));
    assert('message names the approve command', /occasio approvals approve apr_/.test(d1.syntheticResponse.message));

    quiet(() => approvalsCli.run(['approve', d1.approval_id, '--once']));
    const d2 = engine.evaluate(ev(SSH));
    assert('after approve → PASS granted', d2.action === 'PASS' && d2.identityApprovalGranted === true && d2.approval_id === d1.approval_id);

    // consume via the real runToolLoop (single write point)
    const auditor = createAuditor(process.env.OCCASIO_AUDIT_FILE, { lock: false });
    const r = await runToolLoop({ initialSse: sse(SSH), reqBody: { model: 'x', messages: [] }, reqHeaders: {}, mode: 'intercept', auditor, sessionId: 's', runId: 'run1' });
    assert('granted ssh passes through (intercepted=false)', r.intercepted === false);
    assert('token consumed (single-use)', store.get(d1.approval_id).state === 'consumed');

    const d3 = engine.evaluate(ev(SSH));
    assert('second attempt → BLOCK again (consumed)', d3.action === 'BLOCK' && d3.reason === 'approval_required');
  }

  // ── 2. command_hash scope (least-privilege) ─────────────────────────────────
  console.log('\n2. scope: approve binds the exact command');
  {
    const base = 'ssh azureuser@hostA';
    const d = engine.evaluate(ev(base));
    quiet(() => approvalsCli.run(['approve', d.approval_id, '--once']));
    assert('approved command → granted', engine.evaluate(ev(base)).identityApprovalGranted === true);
    assert('whitespace-only variant → SAME grant', engine.evaluate(ev('ssh   azureuser@hostA')).identityApprovalGranted === true);
    // consume it so the rest is clean
    store.consume(d.approval_id);
    assert('different host → BLOCK (not granted)', engine.evaluate(ev('ssh azureuser@hostB')).action === 'BLOCK');
    assert('extra remote arg → BLOCK (whole command bound)', engine.evaluate(ev('ssh azureuser@hostA "systemctl restart x"')).action === 'BLOCK');
  }

  // ── 3. TTL: cap + expiry + identity_borrow_expired ──────────────────────────
  console.log('\n3. TTL cap + expiry signal');
  {
    const d = engine.evaluate(ev('az vm run-command'));
    const res = store.approve(d.approval_id, { ttl_seconds: 7200, approved_by: 'a' });
    assert('--ttl 7200 capped to MAX_TTL (3600)', res.record.ttl_seconds === store.MAX_TTL);

    const d2 = engine.evaluate(ev('sudo systemctl restart x'));
    store.approve(d2.approval_id, { ttl_seconds: 1, approved_by: 'a' });
    assert('valid right after approve', store.lookup({ command_hash: commandHash('sudo systemctl restart x'), actor: 'ai_agent' }) !== null);
    sleep(1100);
    assert('after TTL → lookup null (expired)', store.lookup({ command_hash: commandHash('sudo systemctl restart x'), actor: 'ai_agent' }) === null);
    const swept = quiet(() => approvalsCli.run(['list']));   // CLI sweeps + audits expired
    void swept;
    const rows = fs.readFileSync(process.env.OCCASIO_AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
    assert('approved-but-unused expiry → identity_borrow_expired event', rows.some(r => r.event_type === 'identity_borrow_expired'));
  }

  // ── 4. fail-closed store ────────────────────────────────────────────────────
  console.log('\n4. fail-closed on a corrupt store');
  {
    const corruptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idcorrupt-'));
    const cf = path.join(corruptDir, 'approvals.jsonl');
    fs.writeFileSync(cf, 'not json {{{ \n garbage');
    const s = createIdentityStore({ file: cf, keyFile: path.join(corruptDir, 'k') });
    assert('corrupt approvals.jsonl → lookup null (fail-closed)', s.lookup({ command_hash: commandHash('ssh x'), actor: 'ai_agent' }) === null);
    fs.rmSync(corruptDir, { recursive: true, force: true });
  }

  // ── 5. consume-once (not double via evaluate-twice) ─────────────────────────
  console.log('\n5. consume-once');
  {
    const cmd = 'ssh consumeonce@host';
    const d = engine.evaluate(ev(cmd));
    quiet(() => approvalsCli.run(['approve', d.approval_id, '--once']));
    // engine.evaluate is read-only: evaluating twice does NOT consume
    engine.evaluate(ev(cmd)); engine.evaluate(ev(cmd));
    assert('engine evaluate is read-only (uses still 0)', store.get(d.approval_id).uses === 0);
    const auditor = createAuditor(process.env.OCCASIO_AUDIT_FILE, { lock: false });
    await runToolLoop({ initialSse: sse(cmd), reqBody: { model: 'x', messages: [] }, reqHeaders: {}, mode: 'intercept', auditor, sessionId: 's', runId: 'run5' });
    assert('runToolLoop consumes exactly one use', store.get(d.approval_id).uses === 1);
  }

  // ── 6. identity provenance ──────────────────────────────────────────────────
  console.log('\n6. identity provenance');
  {
    const d = engine.evaluate(ev('ssh prov@host'));
    quiet(() => approvalsCli.run(['approve', d.approval_id]));   // no identity set yet
    const rec = store.get(d.approval_id);
    assert('no identity set → os_fallback', rec.identity_source === 'os_fallback' && !!rec.approved_by);
    store.consume(d.approval_id);

    quiet(() => identityCli.run(['set', '--id', 'alice']));
    const d2 = engine.evaluate(ev('ssh prov2@host'));
    quiet(() => approvalsCli.run(['approve', d2.approval_id]));
    const rec2 = store.get(d2.approval_id);
    assert('explicit identity → approved_by=alice (explicit)', rec2.approved_by === 'alice' && rec2.identity_source === 'explicit');
    store.consume(d2.approval_id);
  }

  // ── 7. redaction stays on the approved path ─────────────────────────────────
  console.log('\n7. approval ≠ secret release (redaction still on)');
  {
    const body = { messages: [{ role: 'user', content: [
      { type: 'tool_use', id: 'g', name: 'Bash', input: { command: 'ssh host "cat .env"' } },
      { type: 'tool_result', tool_use_id: 'g', content: 'EXAMPLE_API_KEY=0xdeadbeef' },
    ] }] };
    const red = enforceOutboundSecretRedaction(body, loader.normalize(strictParsed));
    const tr = red.messages[0].content.find(b => b.type === 'tool_result');
    assert('secret in approved-command output is redacted', red.redactions.length === 1 && !/0xdeadbeef/.test(tr.content));
  }

  // ── 8. control-plane deny-zone (the proof it is not self-service) ────────────
  console.log('\n8. control-plane deny-zone — MANDATORY');
  {
    assert('agent: occasio approvals approve → control_plane_denied', engine.evaluate(ev('occasio approvals approve apr_x --once')).reason === 'control_plane_denied');
    assert('agent: oc approvals deny → control_plane_denied', engine.evaluate(ev('oc approvals deny apr_x')).reason === 'control_plane_denied');
    assert('agent: node bin/occasio.js identity set → control_plane_denied', engine.evaluate(ev('node bin/occasio.js identity set --id evil')).reason === 'control_plane_denied');
    assert('agent: npx occasio approvals approve → control_plane_denied', engine.evaluate(ev('npx occasio approvals approve apr_x')).reason === 'control_plane_denied');
    assert('benign occasio status → NOT control_plane', engine.evaluate(ev('occasio status')).reason !== 'control_plane_denied');
    // agent cannot forge the store/identity by direct file write
    assert('agent: echo > ~/.occasio/approvals.jsonl → path-denied', engine.evaluate(ev('echo x > ~/.occasio/approvals.jsonl')).reason === 'path-denied');
    const readEv = makeBoundaryEvent({ direction: 'inbound', kind: 'tool_call', agent: 'claude-code', protocol: 'anthropic-http', toolName: 'read_file', toolInput: { file_path: '~/.occasio/approvals.jsonl' } });
    assert('agent: Read ~/.occasio/approvals.jsonl → path-denied', engine.evaluate(readEv).reason === 'path-denied');
  }

  // ── 9. HMAC forgery guard ───────────────────────────────────────────────────
  console.log('\n9. HMAC forgery guard');
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'idhmac-'));
    const s = createIdentityStore({ file: path.join(dir, 'a.jsonl'), keyFile: path.join(dir, 'k') });
    const ch = commandHash('ssh forge@host');
    // legit approve to materialize a real signed record
    s.requestApproval({ command_hash: ch, actor: 'ai_agent' });
    const id = s.list({ state: 'pending' })[0].id;
    s.approve(id, { approved_by: 'a' });
    assert('legit signed token → valid', s.lookup({ command_hash: ch, actor: 'ai_agent' }) !== null);
    // hand-write an approved record with a bogus signature
    const forgedCh = commandHash('sudo rm -rf /');
    fs.appendFileSync(path.join(dir, 'a.jsonl'), JSON.stringify({ id: 'apr_forge', command_hash: forgedCh, actor: 'ai_agent', state: 'approved', approved_by: 'alice', expires_at: Math.floor(Date.now() / 1000) + 9999, max_uses: 1, uses: 0, sig: 'f'.repeat(64) }) + '\n');
    assert('forged bad-sig entry → lookup null', s.lookup({ command_hash: forgedCh, actor: 'ai_agent' }) === null);
    // tamper a field on the real record (bump max_uses) → signature mismatch
    const rows = fs.readFileSync(path.join(dir, 'a.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const real = rows.find(r => r.id === id); real.max_uses = 99;
    fs.writeFileSync(path.join(dir, 'a.jsonl'), rows.map(r => JSON.stringify(r)).join('\n') + '\n');
    assert('tampered field (bumped max_uses) → sig mismatch → null', s.lookup({ command_hash: ch, actor: 'ai_agent' }) === null);
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // ── 10. documented-uncovered residual (asserted as the known boundary) ──────
  console.log('\n10. documented-uncovered (obfuscated forge)');
  {
    // An interpreter that builds the path at runtime is NOT caught by the literal
    // guards — the doc must state this honestly (privilege escalation residual).
    const obf = 'python3 -c "import os;open(os.path.expanduser(chr(126)+chr(47)+chr(46)+\'occasio/approvals.jsonl\'),\'a\')"';
    assert('obfuscated ~/.occasio write NOT path-denied (residual, by construction)', engine.evaluate(ev(obf)).reason !== 'path-denied');
    const doc = fs.readFileSync(path.join(__dirname, 'docs', 'identity-gate.md'), 'utf8');
    assert('doc names the forgery residual + OS-level isolation', /Approval forgery/i.test(doc) && /OS-level store isolation/i.test(doc));
  }

  // ── 11. chain integrity (Node) ──────────────────────────────────────────────
  console.log('\n11. chain integrity');
  {
    const v = verifyFile(process.env.OCCASIO_AUDIT_FILE);
    assert('lifecycle chain verifies (Node)', v.ok === true, JSON.stringify(v));
    const rows = fs.readFileSync(process.env.OCCASIO_AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
    for (const et of ['identity_borrow_request', 'identity_borrow_approved', 'identity_borrow_consumed', 'identity_borrow_expired']) {
      assert(`chain has a ${et} row`, rows.some(r => r.event_type === et));
    }
  }

  loader._setOverrideForTests(null);
  console.log('\n' + '─'.repeat(40));
  if (failed === 0) {
    console.log(`✓ All ${passed} identity-approval tests passed`);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ }
  } else {
    console.error(`✗ ${failed}/${passed + failed} identity-approval tests failed`);
    console.error(`  (artifacts kept for inspection: ${TMP})`);
  }
  process.exit(failed === 0 ? 0 : 1);
})();
