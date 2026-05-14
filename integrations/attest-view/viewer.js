/* LocalFirst Attestation Viewer — client-side, no build step.
 *
 * Two non-crypto verifications happen in the browser:
 *
 *   (1) DSSE payload byte-equivalence: re-decode the bundle's payload, parse
 *       its in-toto Statement, and confirm `predicate` equals the attestation
 *       JSON the user provided (modulo the `signature` metadata field).
 *
 *   (2) Audit-chain replay: SHA-256-walk the chain (when the user uploads
 *       the chain file too) and confirm `first_hash` / `last_hash` are in
 *       order.
 *
 * Sigstore certificate-chain verification is DELIBERATELY not done here —
 * it requires bundling fulcio/rekor trust roots in-browser, which is a
 * serious build problem. Phase 2 instead surfaces the Rekor entry URL and
 * defers crypto-cert verification to `localfirst attest verify` or
 * cosign / sigstore-python. The page is honest about that — see Checks.
 */

const PREDICATE_TYPE =
  'https://github.com/localfirst-ai/localfirst/spec/agent-attestation/v1';
const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const GENESIS = '0'.repeat(64);

const $ = sel => document.querySelector(sel);

// ── HTML / URL escaping ─────────────────────────────────────────────────────
// All attestation/bundle data is user-supplied (drag-and-drop). Every value
// that reaches innerHTML or an href must pass through esc() or safeUrl().
// Use textContent where possible; reserve innerHTML for static markup + esc'd
// interpolations only.

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Allow only Rekor search URLs. Anything else (javascript:, data:, file:,
// http://attacker.example) is downgraded to a plain text label.
function safeRekorUrl(raw) {
  if (typeof raw !== 'string') return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return null;
    if (u.host !== 'search.sigstore.dev') return null;
    return u.toString();
  } catch { return null; }
}

// ── Canonical JSON (RFC 8785 subset) ────────────────────────────────────────
// Must stay byte-identical to src/attest/canonicalize.js + docs/canonicalize.py.
// Non-integer numbers are rejected so JS / Python / browser canonicalize the
// same JSON to the same bytes (see src/attest/canonicalize.js header for the
// JavaScript-vs-Python float-divergence rationale).

function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean': return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('canonicalize: non-finite');
      if (!Number.isInteger(value)) {
        throw new Error('canonicalize: non-integer number ' + value);
      }
      return JSON.stringify(value);
    case 'string': return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map(v =>
          canonicalize(v === undefined ? null : v)
        ).join(',') + ']';
      }
      const keys = Object.keys(value)
        .filter(k => value[k] !== undefined)
        .sort();
      return '{' + keys.map(k =>
        JSON.stringify(k) + ':' + canonicalize(value[k])
      ).join(',') + '}';
    }
    case 'undefined':
      throw new Error('canonicalize: undefined at top level');
    default:
      throw new Error('canonicalize: unsupported type ' + typeof value);
  }
}

// ── File ingestion ──────────────────────────────────────────────────────────

const state = { attestation: null, bundle: null, chain: null };

function classifyJson(name, obj) {
  if (obj && obj.predicate_type === PREDICATE_TYPE) return 'attestation';
  if (obj && obj.mediaType && /sigstore.bundle/.test(obj.mediaType)) return 'bundle';
  if (obj && obj.dsseEnvelope && obj.verificationMaterial) return 'bundle';
  return 'unknown';
}

async function ingestFile(file) {
  const text = await file.text();
  // Detect chain file (.jsonl) heuristically by content/name.
  if (/\.jsonl$/i.test(file.name) || text.indexOf('\n') > 0 && text.indexOf('{') === 0) {
    try {
      const lines = text.split('\n').filter(Boolean);
      const firstParsed = JSON.parse(lines[0]);
      if (firstParsed && typeof firstParsed.hash === 'string') {
        state.chain = { text, lines };
        return;
      }
    } catch {}
  }
  try {
    const obj = JSON.parse(text);
    const kind = classifyJson(file.name, obj);
    if (kind === 'attestation') state.attestation = obj;
    else if (kind === 'bundle') state.bundle = obj;
    else {
      // Try harder: maybe attestation with non-matching predicate_type (older version).
      if (obj && obj.audit_chain && obj.execution_summary) state.attestation = obj;
      else throw new Error(`Cannot classify ${file.name}`);
    }
  } catch (e) {
    console.warn('ingest failed', file.name, e);
  }
}

async function ingestFiles(fileList) {
  state.attestation = null; state.bundle = null; state.chain = null;
  await Promise.all([...fileList].map(ingestFile));
  if (state.attestation) render();
  else alert('No attestation file found. Expected JSON with predicate_type set to the LocalFirst URI.');
}

// ── Drag & drop wiring ──────────────────────────────────────────────────────

const dz = $('#dropzone');
['dragenter','dragover'].forEach(ev => dz.addEventListener(ev, e => {
  e.preventDefault(); dz.classList.add('over');
}));
['dragleave','drop'].forEach(ev => dz.addEventListener(ev, e => {
  e.preventDefault(); dz.classList.remove('over');
}));
dz.addEventListener('drop', e => {
  if (e.dataTransfer && e.dataTransfer.files) ingestFiles(e.dataTransfer.files);
});
$('#filepick').addEventListener('change', e => ingestFiles(e.target.files));

// ── Crypto helpers ──────────────────────────────────────────────────────────

async function sha256hex(strOrBytes) {
  const data = (typeof strOrBytes === 'string')
    ? new TextEncoder().encode(strOrBytes)
    : strOrBytes;
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Stable stringify matching the producer's JSON.stringify shape. The chain's
// rows are emitted in field-declaration order by the producer (see
// src/audit/jsonl-auditor.js record()), so default JSON.stringify on a parsed
// row WILL match — JS Map preserves insertion order. Caveat: a tampered file
// could reorder fields; in that case our recompute will detect the mismatch.
function stringifyRow(row) {
  return JSON.stringify(row);
}

// ── Verification ────────────────────────────────────────────────────────────

const checks = [];

function pushCheck(name, status, detail) {
  checks.push({ name, status, detail });
}

async function runPayloadCheck() {
  if (!state.bundle) {
    pushCheck('bundle payload matches attestation', 'pend', 'no bundle uploaded — skipping');
    return;
  }
  try {
    const env = state.bundle.dsseEnvelope;
    if (!env || !env.payload) throw new Error('bundle missing dsseEnvelope.payload');
    if (env.payloadType !== DSSE_PAYLOAD_TYPE) throw new Error(`unexpected payloadType: ${env.payloadType}`);
    const stmtJson = atob(env.payload);
    const stmt = JSON.parse(stmtJson);
    if (stmt.predicateType !== PREDICATE_TYPE) throw new Error(`unexpected predicateType: ${stmt.predicateType}`);
    // Compare predicate ignoring the attestation's signature field.
    // Canonical JSON on both sides so the check is deterministic across
    // browser/Node engines and re-serialisation.
    const expected = { ...state.attestation };
    delete expected.signature;
    if (canonicalize(stmt.predicate) !== canonicalize(expected)) {
      throw new Error('predicate differs from DSSE payload');
    }
    pushCheck('bundle payload matches attestation', 'ok', null);
  } catch (e) {
    pushCheck('bundle payload matches attestation', 'fail', e.message);
  }
}

async function runChainCheck() {
  if (!state.chain) {
    pushCheck('audit chain integrity', 'pend',
      'no pipeline-events.jsonl uploaded — chain replay skipped');
    return;
  }
  try {
    let expectedPrev = null, chained = 0, errors = [];
    let firstSliceIdx = -1, lastSliceIdx = -1;
    const first = state.attestation.audit_chain.first_hash;
    const last  = state.attestation.audit_chain.last_hash;
    for (let i = 0; i < state.chain.lines.length; i++) {
      let row;
      try { row = JSON.parse(state.chain.lines[i]); }
      catch { errors.push(`line ${i+1}: invalid JSON`); continue; }
      if (typeof row.hash !== 'string' || row.hash.length !== 64) continue; // legacy
      chained++;
      const { hash: storedHash, ...rowWithoutHash } = row;
      const recomputed = await sha256hex(stringifyRow(rowWithoutHash));
      if (recomputed !== storedHash) {
        errors.push(`line ${i+1}: hash mismatch`);
      }
      if (expectedPrev === null) {
        if (row.prev_hash !== GENESIS) errors.push(`line ${i+1}: expected GENESIS prev_hash`);
        expectedPrev = GENESIS;
      }
      if (row.prev_hash !== expectedPrev) errors.push(`line ${i+1}: chain broken`);
      expectedPrev = recomputed;
      if (row.hash === first && firstSliceIdx === -1) firstSliceIdx = i;
      if (row.hash === last) lastSliceIdx = i;
    }
    if (errors.length) throw new Error(errors.slice(0, 3).join('; '));
    if (firstSliceIdx === -1) throw new Error('first_hash not found in chain');
    if (lastSliceIdx  === -1) throw new Error('last_hash not found in chain');
    if (lastSliceIdx < firstSliceIdx) throw new Error('last_hash precedes first_hash');
    pushCheck('audit chain integrity', 'ok',
      `chain_length=${chained}; slice rows ${firstSliceIdx+1}..${lastSliceIdx+1}`);
  } catch (e) {
    pushCheck('audit chain integrity', 'fail', e.message);
  }
}

function pushSigstoreCheck() {
  const sig = state.attestation && state.attestation.signature;
  if (!sig) {
    pushCheck('sigstore signature', 'pend', 'attestation is unsigned (signature: null)');
    return;
  }
  // We DON'T verify the cert chain in-browser. Be explicit.
  pushCheck('sigstore signature (offline)', 'pend',
    'cert/rekor verification deferred to `localfirst attest verify` or cosign');
}

// ── Rendering ───────────────────────────────────────────────────────────────

function fmtHash(h) {
  if (typeof h !== 'string' || h.length === 0) return '<code>—</code>';
  return `<code>${esc(h.slice(0,12))}…${esc(h.slice(-8))}</code>`;
}

async function render() {
  checks.length = 0;
  pushSigstoreCheck();
  await runPayloadCheck();
  await runChainCheck();

  const a = state.attestation;
  const sum = a.execution_summary || {};

  // Integer helper — coerce-to-int, escape unnecessary because the result is a number.
  const intOr0 = n => Number.isFinite(+n) ? Math.trunc(+n) : 0;

  // Rekor URL: only render as a link if it points at the public Sigstore Rekor
  // search domain over https. Anything else (incl. javascript:) → text only.
  const rekorRaw  = a.signature?.rekor_entry;
  const rekorSafe = safeRekorUrl(rekorRaw);
  const rekorCell = rekorSafe
    ? `<a href="${esc(rekorSafe)}" target="_blank" rel="noopener noreferrer">${esc(rekorSafe)}</a>`
    : (rekorRaw ? `<code>${esc(rekorRaw)}</code> <span class="warn">(non-Rekor URL — not linked)</span>` : '');

  const tableHTML = [
    ['Predicate',     `<code>${esc(a.predicate_type)}</code>`],
    ['Schema',        `<code>${esc(a.schema_version)}</code>`],
    ['Agent',         `<code>${esc(a.agent?.platform || 'unknown')}</code>` +
                      (a.agent?.model ? ` · ${esc(a.agent.model)}` : '')],
    ['run_id',        `<code>${esc(a.subject?.run_id || '')}</code>`],
    a.subject?.git_commit
      ? ['Git commit', `<code>${esc(String(a.subject.git_commit).slice(0,12))}</code>`]
      : null,
    Array.isArray(a.subject?.files_changed) && a.subject.files_changed.length
      ? ['Files changed', `<code>${intOr0(a.subject.files_changed.length)} file(s)</code>`]
      : null,
    ['Started',       `<code>${esc(a.agent?.started_at || '')}</code>`],
    ['Wall time',     `<code>${intOr0(a.agent?.wall_time_s)} s</code>`],
    ['Policy hash',   `${fmtHash(a.policy?.file_hash)} <span class="warn">(${esc(a.policy?.source || '?')})</span>`],
    ['Tool calls',    `<strong>${intOr0(sum.tool_calls)}</strong> · LOCAL ${intOr0(sum.local)} · PASS ${intOr0(sum.passed)} · ` +
                      `<span class="${intOr0(sum.blocked)>0?'fail':''}">BLOCK ${intOr0(sum.blocked)}</span> · ` +
                      `TRANSFORM ${intOr0(sum.transformed)}`],
    ['Secrets redacted', `${intOr0(sum.secrets_redacted)}`],
    ['Chain',         `${fmtHash(a.audit_chain?.first_hash)} → ${fmtHash(a.audit_chain?.last_hash)} · ${intOr0(a.audit_chain?.event_count)} events`],
    a.signature?.identity
      ? ['Identity', `<code>${esc(a.signature.identity)}</code>`]
      : null,
    rekorCell
      ? ['Rekor', rekorCell]
      : null,
  ].filter(Boolean).map(([k,v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('');
  $('#summary-table').innerHTML = tableHTML;

  const checksHTML = checks.map(c => {
    // Only allow the known status classes to land in HTML; default to 'pend'.
    const cls = (c.status === 'ok' || c.status === 'fail' || c.status === 'pend') ? c.status : 'pend';
    const mark = cls === 'ok' ? '✓' : cls === 'fail' ? '✗' : '○';
    // c.detail often contains error strings echoing user-supplied JSON fields
    // (e.g. `unexpected payloadType: <value>`) — escape both.
    return `<li class="${cls}"><span class="mark">${mark}</span><span>${esc(c.name)}` +
      (c.detail ? ` <span class="detail">— ${esc(c.detail)}</span>` : '') + `</span></li>`;
  }).join('');
  $('#checks-list').innerHTML = checksHTML;

  // Blocked events
  const blocked = Array.isArray(sum.blocked_events) ? sum.blocked_events : [];
  if (blocked.length) {
    $('#blocked-card').hidden = false;
    $('#blocked-tbody').innerHTML = blocked.map(b => `
      <tr>
        <td><code>${esc(b.tool || '')}</code></td>
        <td><code>${esc(b.target || '')}</code></td>
        <td><code>${esc(b.rule || '')}</code></td>
        <td>T+${intOr0(b.at_offset_s)}s</td>
      </tr>`).join('');
  } else {
    $('#blocked-card').hidden = true;
  }

  // Raw attestation
  $('#raw-att').textContent = JSON.stringify(a, null, 2);

  $('#result').hidden = false;
}
