'use strict';

/**
 * detectors.js — richer, explainable secret detection (Idea #5).
 *
 * Separate from analyzer.scanSecrets (which stays byte-for-byte stable for the
 * live BLOCK path and its exact-count tests). This module adds prefix / JWT /
 * .env / Shannon-entropy detectors with an allowlist, and emits explainable
 * findings: { detector, label, confidence, reason, line, snippet, value_sha256 }.
 *
 * The matched value is NEVER returned in plaintext — only a masked snippet and
 * a sha256. `redactWithLedger` redacts in place and records a hash-only ledger.
 *
 * Pure (no I/O). Zero dependencies: crypto + Buffer + regex.
 */

const crypto = require('crypto');
const { redactLine } = require('../analyzer');

function sha256(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex'); }

function shannonEntropy(s) {
  if (!s || !s.length) return 0;
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  const n = s.length;
  for (const k in freq) { const p = freq[k] / n; h -= p * Math.log2(p); }
  return h;
}

// ── prefix detectors (structural, high confidence) ───────────────────────────
const PREFIX_PATTERNS = [
  { re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/,                 label: 'github-token',   confidence: 0.98 },
  { re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/,              label: 'github-fine-pat',confidence: 0.98 },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/,                  label: 'gitlab-pat',     confidence: 0.97 },
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,                 label: 'anthropic-key',  confidence: 0.98 },
  { re: /\bsk-[A-Za-z0-9]{20,}\b/,                       label: 'openai-key',     confidence: 0.9  },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,              label: 'slack-token',    confidence: 0.95 },
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,                 label: 'aws-access-key', confidence: 0.97 },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/,                     label: 'google-api-key', confidence: 0.95 },
  { re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/,  label: 'stripe-key',     confidence: 0.97 },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/,                       label: 'npm-token',      confidence: 0.95 },
];

const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/;
const ENV_RE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"]{8,})['"]?\s*$/;
const SECRET_KEY_RE = /(SECRET|TOKEN|KEY|PASSWORD|PASSWD|PWD|API|AUTH|CREDENTIAL|PRIVATE)/i;
// No '=' in the class: it would merge `key=value` into one candidate.
const ENTROPY_CANDIDATE_RE = /[A-Za-z0-9+/_-]{20,}/g;
const ENTROPY_THRESHOLD = 3.5;

const UUID_RE        = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_ONLY_RE    = /^[0-9a-fA-F]+$/;
const PLACEHOLDER_RE = /^(changeme|placeholder|example|dummy|none|null|true|false|your[_-].*|<.*>|x{3,}|\.{3,})$/i;

function looksLikeJwt(tok) {
  try {
    const header = JSON.parse(Buffer.from(tok.split('.')[0], 'base64').toString('utf8'));
    return !!(header && (header.alg || header.typ));
  } catch { return false; }
}

function charsetClasses(s) {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  return n;
}

function isPlaceholder(v) {
  return PLACEHOLDER_RE.test(v) || /EXAMPLE/i.test(v) || /^x+$/i.test(v);
}

function buildAllowlist(extra) {
  const literals = new Set();
  const regexes = [];
  for (const e of (Array.isArray(extra) ? extra : [])) {
    if (e instanceof RegExp) regexes.push(e);
    else if (typeof e === 'string') { try { regexes.push(new RegExp(e)); } catch { literals.add(e); } }
  }
  return { literals, regexes };
}

// Allowlist applied to ALL detectors. NOTE: UUID / pure-hex are deliberately
// NOT here — a prefix/env secret that happens to be hex is still a secret;
// hex+UUID suppression belongs only to the entropy gate (hashes/checksums).
function isAllowlisted(value, allow) {
  if (!value) return true;
  if (/EXAMPLE/i.test(value)) return true;              // doc/test fixtures (e.g. AKIAIOSFODNN7EXAMPLE)
  if (isPlaceholder(value)) return true;
  if (allow) {
    if (allow.literals.has(value)) return true;
    for (const r of allow.regexes) { try { if (r.test(value)) return true; } catch { /* ignore */ } }
  }
  return false;
}

function entropyConfidence(tok, h) {
  let c = 0.4 + (h - ENTROPY_THRESHOLD) * 0.15 + (tok.length >= 40 ? 0.1 : 0);
  return Math.max(0.4, Math.min(0.85, Number(c.toFixed(2))));
}

// Internal: detect with the raw matched value retained (never exported).
function _detect(text, opts = {}) {
  if (typeof text !== 'string') return [];
  const allow = buildAllowlist(opts.allowlist);
  const lines = text.split('\n');
  const hits = [];
  const seen = new Set();

  const add = (detector, label, confidence, reason, lineIdx, value) => {
    if (!value || isAllowlisted(value, allow)) return;
    const key = `${detector}:${label}:${lineIdx}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push({ detector, label, confidence, reason, line: lineIdx + 1,
                snippet: redactLine(lines[lineIdx]), value, value_sha256: sha256(value) });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const p of PREFIX_PATTERNS) {
      const m = line.match(p.re);
      if (m) add('prefix', p.label, p.confidence, `known credential prefix (${p.label})`, i, m[0]);
    }

    const jm = line.match(JWT_RE);
    if (jm && looksLikeJwt(jm[0])) add('jwt', 'jwt', 0.95, 'JWT structure (header.payload.signature)', i, jm[0]);

    const em = line.match(ENV_RE);
    if (em && SECRET_KEY_RE.test(em[1]) && !isPlaceholder(em[2])) {
      add('env-key', `env:${em[1]}`, 0.8, `secret-like env assignment (${em[1]})`, i, em[2]);
    }

    const cands = line.match(ENTROPY_CANDIDATE_RE) || [];
    for (const tok of cands) {
      if (tok.length < 20) continue;
      if (HEX_ONLY_RE.test(tok)) continue;          // hash/sha — handled as non-secret
      if (UUID_RE.test(tok)) continue;              // UUIDs are not secrets
      if (charsetClasses(tok) < 2) continue;        // dictionary-ish / single class
      const h = shannonEntropy(tok);
      if (h >= ENTROPY_THRESHOLD) {
        add('entropy', 'high-entropy', entropyConfidence(tok, h),
            `high-entropy token (len ${tok.length}, H≈${h.toFixed(2)})`, i, tok);
      }
    }
  }
  return hits;
}

/**
 * Public detection — explainable findings, no plaintext value.
 * @returns {Array<{detector,label,confidence,reason,line,snippet,value_sha256}>}
 */
function detectSecrets(text, opts) {
  return _detect(text, opts).map(({ value: _value, ...rest }) => rest);  // strip plaintext value
}

/**
 * Redact detected secrets in place and return a hash-only ledger.
 * @returns {{ redacted: string, ledger: Array<{detector,label,reason,line,value_sha256,replacement}> }}
 */
function redactWithLedger(text, opts) {
  if (typeof text !== 'string') return { redacted: text, ledger: [] };
  const hits = _detect(text, opts);
  const lines = text.split('\n');
  const ledger = [];
  for (const h of hits) {
    const replacement = `[REDACTED:${h.label}]`;
    const idx = h.line - 1;
    if (lines[idx] && lines[idx].includes(h.value)) {
      lines[idx] = lines[idx].split(h.value).join(replacement);
    }
    ledger.push({ detector: h.detector, label: h.label, reason: h.reason,
                  line: h.line, value_sha256: h.value_sha256, replacement });
  }
  return { redacted: lines.join('\n'), ledger };
}

module.exports = {
  detectSecrets, redactWithLedger, shannonEntropy, isAllowlisted, buildAllowlist,
  PREFIX_PATTERNS, ENTROPY_THRESHOLD,
};
