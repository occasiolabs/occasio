#!/usr/bin/env node
'use strict';

/**
 * stress-verify.js — drive the REAL web/verify/verify.js in Node (DOM shimmed)
 * and hammer its verification logic with honest / tamper / malformed / edge /
 * XSS / large inputs. Non-shipped dev harness.
 *
 *   node scripts/stress-verify.js   →   exit 0 iff every case behaves correctly.
 *
 * The page's functions are loaded verbatim (vm), so this tests the shipped code,
 * not a copy. A small epilogue captures the module-scope consts for driving.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const vm   = require('vm');
const REPO = path.resolve(__dirname, '..');
const { createAuditor, computeHash, GENESIS } = require(path.join(REPO, 'src/audit/jsonl-auditor'));

let pass = 0, fail = 0;
const ok  = (l, c, d='') => { if (c) { pass++; } else { fail++; console.log('  ✗ ' + l + (d?'  '+d:'')); } };
const sect = s => console.log('\n' + s);

// ── DOM + browser-global shim ────────────────────────────────────────────────
const ELS = new Map();
function fakeEl(key){
  if (ELS.has(key)) return ELS.get(key);
  const el = {
    _key:key, className:'', hidden:false, innerHTML:'', textContent:'', children:[],
    classList:{ add(){}, remove(){} },
    addEventListener(){}, appendChild(n){ this.children.push(n); },
    querySelector(sel){ return fakeEl(key+' '+sel); },
  };
  ELS.set(key, el); return el;
}
const documentStub = {
  querySelector: sel => fakeEl(sel),
  createElement: () => ({ href:'', target:'', rel:'', textContent:'' }),
};
const alerts = [];
const ctx = {
  document: documentStub, window: {}, alert: m => alerts.push(m), console,
  crypto: globalThis.crypto, TextEncoder, atob: globalThis.atob, btoa: globalThis.btoa,
  URL,
};
vm.createContext(ctx);

// Load demo.js (sets window.OCCASIO_DEMO) then verify.js + a capture epilogue.
vm.runInContext(fs.readFileSync(path.join(REPO,'web/verify/demo.js'),'utf8'), ctx, {filename:'demo.js'});
const code = fs.readFileSync(path.join(REPO,'web/verify/verify.js'),'utf8')
  + '\n;globalThis.__api={ get state(){return state;}, canonicalize, chainCheck, predicateCheck, sigCheck, loadDemo, tamper, reset, classifyJson };';
vm.runInContext(code, ctx, {filename:'verify.js'});
const api = ctx.__api;
const DEMO = ctx.window.OCCASIO_DEMO;
const pristine = () => JSON.parse(JSON.stringify(DEMO.chainLines));
const cardCls = id => fakeEl(id).className;

(async () => {
  // ── 1. honest demo ─────────────────────────────────────────────────────────
  sect('1. honest demo');
  api.loadDemo();
  await new Promise(r=>setTimeout(r,0)); // let verifyAndRender's awaits settle
  let chain = await api.chainCheck(), pred = await api.predicateCheck(), sig = api.sigCheck();
  ok('chain ok', chain.status==='ok', JSON.stringify(chain));
  ok('predicate ok', pred.status==='ok', JSON.stringify(pred));
  ok('signature na (never green)', sig.status==='na');

  // ── 2. tamper() then reset() ─────────────────────────────────────────────────
  sect('2. tamper / reset');
  api.tamper();
  chain = await api.chainCheck();
  ok('tamper → chain fail', chain.status==='fail', JSON.stringify(chain));
  ok('tamper pinpoints a line', /line \d/i.test(chain.detail||''), chain.detail);
  api.reset();
  chain = await api.chainCheck();
  ok('reset → chain ok again', chain.status==='ok');

  // ── 3. tamper EVERY row at several byte positions ────────────────────────────
  sect('3. exhaustive single-row tamper');
  let everyFail = true;
  for (let i=0;i<DEMO.chainLines.length;i++){
    for (const pos of [10, Math.floor(DEMO.chainLines[i].length/2), DEMO.chainLines[i].length-20]){
      if (pos<1) continue;
      const lines = pristine();
      const orig = lines[i][pos];
      const repl = orig==='a'?'b':'a';
      lines[i] = lines[i].slice(0,pos)+repl+lines[i].slice(pos+1);
      if (lines[i]===pristine()[i]) continue; // no-op mutation, skip
      api.state.chain = { lines };
      const r = await api.chainCheck();
      if (r.status!=='fail'){ everyFail=false; console.log(`    ✗ row ${i} pos ${pos} NOT detected`); }
    }
  }
  ok('every single-row byte flip detected', everyFail);
  api.state.chain = { lines: pristine() };

  // ── 4. robustness: whitespace-insensitive, malformed JSON, reordered keys ────
  sect('4. robustness');
  // (a) leading/trailing whitespace around a line is tolerated (JSON.parse ignores
  //     structural whitespace; recompute re-serialises the parsed object compactly).
  { const lines=pristine(); lines[1]='  '+lines[1]+'  ';
    api.state.chain={lines}; const r=await api.chainCheck(); ok('surrounding whitespace tolerated', r.status==='ok', JSON.stringify(r)); }
  // (b) malformed JSON line → no crash, fail
  { const lines=pristine(); lines[1]='{ not valid json'; api.state.chain={lines};
    let threw=false,r; try{ r=await api.chainCheck(); }catch{ threw=true; }
    ok('malformed line: no crash', !threw); ok('malformed line: fail', r&&r.status==='fail', r&&r.detail); }
  // (c) reordered keys → hash mismatch (chain uses insertion order)
  { const lines=pristine(); const o=JSON.parse(lines[1]); const rev={}; Object.keys(o).reverse().forEach(k=>rev[k]=o[k]);
    lines[1]=JSON.stringify(rev); api.state.chain={lines}; const r=await api.chainCheck();
    ok('reordered keys → fail', r.status==='fail', JSON.stringify(r)); }
  api.state.chain = { lines: pristine() };

  // ── 5. attestation/bundle edge cases ─────────────────────────────────────────
  sect('5. predicate / signature edges');
  // (a) no bundle → predicate na
  { const save=api.state.bundle; api.state.bundle=null; const r=await api.predicateCheck(); ok('no bundle → predicate na', r.status==='na'); api.state.bundle=save; }
  // (b) predicate tamper: change run_id after signing → fail
  { const att=JSON.parse(JSON.stringify(DEMO.attestation)); att.subject.run_id='HACKED';
    const save=api.state.attestation; api.state.attestation=att; const r=await api.predicateCheck();
    ok('forged attestation → predicate fail', r.status==='fail', JSON.stringify(r)); api.state.attestation=save; }
  // (c) wrong payloadType → fail
  { const b=JSON.parse(JSON.stringify(DEMO.sigstore)); b.dsseEnvelope.payloadType='application/x-evil';
    const save=api.state.bundle; api.state.bundle=b; const r=await api.predicateCheck();
    ok('wrong payloadType → fail', r.status==='fail', r.detail); api.state.bundle=save; }
  // (d) unsigned attestation → signature na "unsigned"
  { const att=JSON.parse(JSON.stringify(DEMO.attestation)); att.signature=null;
    const save=api.state.attestation; api.state.attestation=att; const r=api.sigCheck();
    ok('unsigned → signature na', r.status==='na' && /unsigned/.test(r.detail)); api.state.attestation=save; }
  // (e) no chain → chain na
  { const save=api.state.chain; api.state.chain=null; const r=await api.chainCheck(); ok('no chain → chain na', r.status==='na'); api.state.chain=save; }

  // ── 6. XSS — hostile field values must be escaped in rendered HTML ───────────
  sect('6. XSS safety');
  { const att=JSON.parse(JSON.stringify(DEMO.attestation));
    att.signature.identity='<img src=x onerror=alert(1)>';
    att.policy.source='</td><script>alert(2)</script>';
    api.state.attestation=att; api.state.bundle=JSON.parse(JSON.stringify(DEMO.sigstore)); api.state.chain={lines:pristine()};
    // renderSummary runs inside verifyAndRender; call the public path:
    await (async()=>{ // emulate verifyAndRender's render by invoking sigCheck/predicate/chain + summary via loadDemo-like path is internal; call setCard+renderSummary indirectly:
      // verifyAndRender is internal; trigger via reset() which calls verifyAndRender on the demo — instead re-run the three checks + read #summary after a render.
    })();
    // Trigger a full render through the captured internal path: call loadDemo with a hijacked window.OCCASIO_DEMO
    ctx.window.OCCASIO_DEMO = { attestation: att, sigstore: DEMO.sigstore, chainLines: pristine() };
    api.loadDemo(); await new Promise(r=>setTimeout(r,25));
    // Only innerHTML surfaces can execute markup. #raw is set via textContent
    // (inert by definition), so it is NOT part of the XSS surface.
    const summary = fakeEl('#summary').innerHTML;
    ok('summary rendered (precondition)', summary.length > 0);
    ok('identity escaped in summary innerHTML', summary.includes('&lt;img') && !/<img src=x onerror/.test(summary), 'leak');
    ok('no raw <script> in summary innerHTML', !/<script>alert/.test(summary));
    ok('#raw uses textContent, not innerHTML', fakeEl('#raw').innerHTML === '' && fakeEl('#raw').textContent.length > 0);
    ctx.window.OCCASIO_DEMO = DEMO; // restore
  }

  // ── 7. large chain performance + correctness (2000 rows) ─────────────────────
  sect('7. large chain (2000 rows)');
  { const dir=fs.mkdtempSync(path.join(os.tmpdir(),'occ-stress-')); const f=path.join(dir,'c.jsonl');
    const a=createAuditor(f,{lock:false});
    for(let i=0;i<2000;i++) a.recordLimitExceeded({runId:'R',sessionId:'R',kind:'max_tool_calls_per_round',max:i,actual:i+1,round:i});
    const lines=fs.readFileSync(f,'utf8').split('\n').filter(Boolean);
    const first=JSON.parse(lines[0]).hash, last=JSON.parse(lines[lines.length-1]).hash;
    api.state.attestation={...JSON.parse(JSON.stringify(DEMO.attestation)), audit_chain:{...DEMO.attestation.audit_chain, first_hash:first, last_hash:last}};
    api.state.chain={lines};
    const t0=Date.now(); const r=await api.chainCheck(); const ms=Date.now()-t0;
    ok('2000-row honest chain ok', r.status==='ok', JSON.stringify(r));
    console.log('    re-hashed 2000 rows in '+ms+' ms');
    // one byte flip deep in the chain → fail
    lines[1337]=lines[1337].replace(/"actual":\d+/,'"actual":999999'); api.state.chain={lines};
    const r2=await api.chainCheck(); ok('deep tamper (row 1338) → fail', r2.status==='fail', r2.detail);
  }

  console.log('\n' + (fail===0?'✓ stress':'✗ stress') + ': '+pass+' passed, '+fail+' failed\n');
  process.exit(fail===0?0:1);
})();
