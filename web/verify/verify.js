/* Occasio attestation verifier — client-side, no build step, zero network.
 *
 * The verification core (canonicalize, the SHA-256 chain replay, the predicate
 * equivalence) is byte-identical to integrations/attest-view/viewer.js,
 * src/attest/{canonicalize,verify}.js, src/audit/verifier.js, and the Python
 * docs/{canonicalize,audit_walker,attest_verify}.py. DO NOT "improve" those
 * functions — byte-equivalence across browser / Node / Python depends on them
 * staying the same. The signature is honestly NOT verified in-browser.
 */
'use strict';

const PREDICATE_TYPE = 'https://github.com/occasiolabs/occasio/spec/agent-attestation/v1';
const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const GENESIS = '0'.repeat(64);
const $ = s => document.querySelector(s);

// ── XSS-safe helpers (every user value reaching the DOM goes through these) ──
function esc(s){ if(s==null) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function safeRekorUrl(raw){ if(typeof raw!=='string') return null; try{ const u=new URL(raw); if(u.protocol!=='https:') return null; if(u.host!=='search.sigstore.dev') return null; return u.toString(); }catch{ return null; } }

// ── Canonical JSON (RFC 8785 subset) — keep byte-identical (see header) ──────
function canonicalize(value){
  if(value===null) return 'null';
  switch(typeof value){
    case 'boolean': return value?'true':'false';
    case 'number':
      if(!Number.isFinite(value)) throw new Error('canonicalize: non-finite');
      if(!Number.isInteger(value)) throw new Error('canonicalize: non-integer number '+value);
      return JSON.stringify(value);
    case 'string': return JSON.stringify(value);
    case 'object':{
      if(Array.isArray(value)) return '['+value.map(v=>canonicalize(v===undefined?null:v)).join(',')+']';
      const keys=Object.keys(value).filter(k=>value[k]!==undefined).sort();
      return '{'+keys.map(k=>JSON.stringify(k)+':'+canonicalize(value[k])).join(',')+'}';
    }
    case 'undefined': throw new Error('canonicalize: undefined at top level');
    default: throw new Error('canonicalize: unsupported type '+typeof value);
  }
}

async function sha256hex(str){
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
// Matches the producer's JSON.stringify shape (insertion order) — same as
// src/audit/jsonl-auditor.js computeHash. A tampered/reordered row recomputes
// to a different hash, which is exactly the detection we want.
function stringifyRow(row){ return JSON.stringify(row); }

// ── State ────────────────────────────────────────────────────────────────────
const state = { attestation:null, bundle:null, chain:null };
let demoPristineLines = null;   // set when the demo is loaded; enables tamper/reset

function classifyJson(obj){
  if(obj && obj.predicate_type===PREDICATE_TYPE) return 'attestation';
  if(obj && obj.mediaType && /sigstore.bundle/.test(obj.mediaType)) return 'bundle';
  if(obj && obj.dsseEnvelope && obj.verificationMaterial) return 'bundle';
  if(obj && obj.audit_chain && obj.execution_summary) return 'attestation';
  return 'unknown';
}
async function ingestFile(file){
  const text = await file.text();
  if(/\.jsonl$/i.test(file.name) || (text.indexOf('\n')>0 && text.trimStart().indexOf('{')===0)){
    try{ const lines=text.split('\n').filter(Boolean); const first=JSON.parse(lines[0]);
      if(first && typeof first.hash==='string'){ state.chain={lines}; return; } }catch{}
  }
  try{ const obj=JSON.parse(text); const k=classifyJson(obj);
    if(k==='attestation') state.attestation=obj; else if(k==='bundle') state.bundle=obj; }catch{}
}
async function ingestFiles(list){
  state.attestation=null; state.bundle=null; state.chain=null; demoPristineLines=null;
  await Promise.all([...list].map(ingestFile));
  $('#democtl').hidden = true; $('#demonote').hidden = true;
  if(state.attestation) verifyAndRender();
  else alert('No attestation found. Drop a JSON file whose predicate_type is the Occasio attestation URI (plus its pipeline-events.jsonl).');
}

// ── The three checks (return {status, detail}) ───────────────────────────────
async function chainCheck(){
  if(!state.chain) return { status:'na', detail:'no pipeline-events.jsonl provided — chain replay skipped' };
  try{
    const first = state.attestation.audit_chain && state.attestation.audit_chain.first_hash;
    const last  = state.attestation.audit_chain && state.attestation.audit_chain.last_hash;
    let expectedPrev=null, chained=0, firstIdx=-1, lastIdx=-1; const errors=[];
    for(let i=0;i<state.chain.lines.length;i++){
      let row; try{ row=JSON.parse(state.chain.lines[i]); }catch{ errors.push(`line ${i+1}: invalid JSON`); continue; }
      if(typeof row.hash!=='string' || row.hash.length!==64) continue;   // legacy/unchained
      chained++;
      const { hash:stored, ...rest } = row;
      const recomputed = await sha256hex(stringifyRow(rest));
      if(recomputed!==stored) errors.push(`line ${i+1}: hash mismatch — this row was modified`);
      if(expectedPrev===null){ if(row.prev_hash!==GENESIS) errors.push(`line ${i+1}: first row is not anchored to GENESIS`); expectedPrev=GENESIS; }
      if(row.prev_hash!==expectedPrev) errors.push(`line ${i+1}: chain broken — prev_hash does not match`);
      expectedPrev = recomputed;
      if(row.hash===first && firstIdx===-1) firstIdx=i;
      if(row.hash===last) lastIdx=i;
    }
    if(errors.length) return { status:'fail', detail: errors.slice(0,3).join(' · ') };
    if(firstIdx===-1 || lastIdx===-1) return { status:'fail', detail:'attestation first/last hash not found in this chain' };
    if(lastIdx<firstIdx) return { status:'fail', detail:'last_hash precedes first_hash' };
    return { status:'ok', detail:`${chained} rows re-hashed · linked GENESIS → HEAD · slice rows ${firstIdx+1}..${lastIdx+1}` };
  }catch(e){ return { status:'fail', detail:e.message }; }
}
async function predicateCheck(){
  if(!state.bundle) return { status:'na', detail:'no .sigstore.json provided — no signed payload to compare' };
  try{
    const env = state.bundle.dsseEnvelope;
    if(!env || !env.payload) throw new Error('bundle missing dsseEnvelope.payload');
    if(env.payloadType!==DSSE_PAYLOAD_TYPE) throw new Error('unexpected payloadType: '+env.payloadType);
    const stmt = JSON.parse(atob(env.payload));
    if(stmt.predicateType!==PREDICATE_TYPE) throw new Error('unexpected predicateType: '+stmt.predicateType);
    const expected = { ...state.attestation }; delete expected.signature;
    if(canonicalize(stmt.predicate)!==canonicalize(expected)) throw new Error('signed predicate differs from this attestation');
    return { status:'ok', detail:'signed payload is byte-for-byte this attestation' };
  }catch(e){ return { status:'fail', detail:e.message }; }
}
function sigCheck(){
  const sig = state.attestation && state.attestation.signature;
  if(!sig) return { status:'na', detail:'attestation is unsigned (signature: null)' };
  return { status:'na', detail:'present but not cryptographically verified here. Verify for real: occasio attest verify <file>  ·  or  cosign verify-blob',
           rekor: safeRekorUrl(sig.rekor_entry) };
}

// ── Render ───────────────────────────────────────────────────────────────────
function setCard(id, res){
  const el = $(id); const cls = (res.status==='ok'||res.status==='fail'||res.status==='na')?res.status:'pend';
  el.className = 'card '+cls;
  el.querySelector('.mk').textContent = cls==='ok'?'✓':cls==='fail'?'✗':cls==='na'?'—':'○';
  const d = el.querySelector('.detail'); d.textContent = res.detail||'';
  if(res.rekor){ const a=document.createElement('a'); a.href=res.rekor; a.target='_blank'; a.rel='noopener noreferrer'; a.textContent=' Rekor entry ↗'; d.appendChild(a); }
}
function fmtHash(h){ return (typeof h==='string'&&h.length)? esc(h.slice(0,12))+'…'+esc(h.slice(-8)) : '—'; }
function renderSummary(a){
  const sum=a.execution_summary||{}; const gs=a.subject&&a.subject.git_state;
  const i=n=>Number.isFinite(+n)?Math.trunc(+n):0;
  const rows=[
    ['Agent', esc(a.agent&&a.agent.platform||'unknown')+(a.agent&&a.agent.model?' · '+esc(a.agent.model):'')],
    ['run_id', esc(a.subject&&a.subject.run_id||'')],
    a.subject&&a.subject.git_commit?['Git commit', esc(String(a.subject.git_commit).slice(0,12))]:null,
    gs&&gs.run_end?['Repo at run end', 'HEAD '+fmtHash(gs.run_end.head)+(gs.run_end.dirty?' · dirty':' · clean')+' · '+i((gs.run_end.changed_files||[]).length)+' changed']:null,
    ['Policy', fmtHash(a.policy&&a.policy.file_hash)+' <span class="warn">('+esc(a.policy&&a.policy.source||'?')+')</span>'],
    ['Tool calls', '<b>'+i(sum.tool_calls)+'</b> · LOCAL '+i(sum.local)+' · BLOCK <span class="'+(i(sum.blocked)>0?'warn':'')+'">'+i(sum.blocked)+'</span>'],
    ['Chain', fmtHash(a.audit_chain&&a.audit_chain.first_hash)+' → '+fmtHash(a.audit_chain&&a.audit_chain.last_hash)+' · '+i(a.audit_chain&&a.audit_chain.event_count)+' events'],
    a.signature&&a.signature.identity?['Identity', esc(a.signature.identity)]:null,
  ].filter(Boolean).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('');
  $('#summary').innerHTML = rows;
  $('#raw').textContent = JSON.stringify(a,null,2);
}
async function verifyAndRender(){
  $('#result').hidden = false;
  setCard('#card-sig', sigCheck());
  setCard('#card-pred', await predicateCheck());
  setCard('#card-chain', await chainCheck());
  renderSummary(state.attestation);
}

// ── Demo + tamper ─────────────────────────────────────────────────────────────
function deep(o){ return JSON.parse(JSON.stringify(o)); }
function loadDemo(){
  const d = window.OCCASIO_DEMO; if(!d){ alert('Demo data not loaded.'); return; }
  state.attestation = deep(d.attestation);
  state.bundle = deep(d.sigstore);
  state.chain = { lines: deep(d.chainLines) };
  demoPristineLines = deep(d.chainLines);
  $('#democtl').hidden = false; $('#demonote').hidden = false;
  verifyAndRender();
}
function tamper(){
  if(!demoPristineLines) return;
  // Flip a value in one recorded row — as if someone edited what the agent read.
  state.chain.lines[1] = demoPristineLines[1].replace('app.js','evil.js');
  verifyAndRender();
}
function reset(){
  if(!demoPristineLines) return;
  state.chain.lines = deep(demoPristineLines);
  verifyAndRender();
}

// ── Wiring (no inline handlers — CSP forbids them) ───────────────────────────
const dz=$('#dropzone');
['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('over');}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('over');}));
dz.addEventListener('drop',e=>{ if(e.dataTransfer&&e.dataTransfer.files) ingestFiles(e.dataTransfer.files); });
$('#filepick').addEventListener('change',e=>ingestFiles(e.target.files));
$('#loaddemo').addEventListener('click',loadDemo);
$('#tamper').addEventListener('click',tamper);
$('#reset').addEventListener('click',reset);
