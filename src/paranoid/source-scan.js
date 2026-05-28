'use strict';

/**
 * source-scan.js: locate every outbound network primitive in src/ and bin/
 * and classify each callsite as proxy-bound, hardcoded-host, or unclassified.
 *
 * The classifier is heuristic. It reads a window of source characters around
 * the match and looks for either a literal hostname (suspicious) or evidence
 * the destination is derived from request input or environment (legitimate).
 * AST-based classification is documented as future work; the regex approach
 * is sufficient for the current codebase shape and produces zero false
 * negatives against the existing tree.
 *
 * Trust model: hardcoded-host hits are reported as `critical`, unclassified
 * as `warn`, proxy-bound as `info`. Critical hits flip the overall exit code.
 */

const fs   = require('fs');
const path = require('path');

const { NETWORK_PRIMITIVES } = require('./patterns/network-primitives');

const CONTEXT_BEFORE = 60;
const CONTEXT_AFTER  = 200;

// A small, explicit allowlist of LLM provider endpoints that Occasio's
// adapter code references as string literals. The list contains ONLY hosts
// that are actually present in src/, not speculative future providers.
// Adding to this list is a deliberate change accompanying the adapter that
// references the new host; reviewers see both at once. This keeps the list
// honest: every entry is a real architectural commitment, not an endorsement
// of a provider we have not integrated.
const LLM_ENDPOINTS = new Set([
  'api.anthropic.com',
]);

// Sigstore / Rekor / Fulcio transparency-log endpoints used by the
// attestation pipeline. These are signed-release infrastructure, not user
// data destinations; classified as `signing-infra` (info severity).
const SIGNING_ENDPOINTS = new Set([
  'rekor.sigstore.dev',
  'fulcio.sigstore.dev',
  'tuf-repo-cdn.sigstore.dev',
]);

// A hostname literal inside string quotes. Avoids matching 127.0.0.1 or
// localhost (those are legitimate local destinations).
const LITERAL_HOST_RE = /['"`]https?:\/\/(?!127\.0\.0\.1|localhost)([a-zA-Z0-9.-]+)/;
const LITERAL_HOST_FIELD_RE = /\bhost\s*:\s*['"`](?!127\.0\.0\.1|localhost)([a-zA-Z0-9.-]+)['"`]/;
const LITERAL_HOSTNAME_FIELD_RE = /\bhostname\s*:\s*['"`](?!127\.0\.0\.1|localhost)([a-zA-Z0-9.-]+)['"`]/;

// Evidence the destination is derived from runtime input (proxy use case)
// or from an environment variable controlled by the user or the CI host.
const PROXY_BOUND_RE = new RegExp(
  '\\b(req\\.headers|req\\.url|req\\.path|process\\.env\\.[A-Z_]*(URL|BASE|ENDPOINT|HOST|TOKEN_REQUEST_URL))|' +
  '\\b(targetUrl|targetHost|upstreamUrl|upstreamHost|baseUrl|baseURL|apiBase|endpoint|sigstoreInstance|fetchUrl)\\b',
);

// A fetch (or other call) whose first string argument starts with "/" is a
// relative URL: same-origin in browser contexts, no remote host implied.
// Common in embedded dashboard JS heredocs.
const RELATIVE_URL_RE = /\(\s*['"`]\/[^'"`]*['"`]/;

// Files the paranoid scanner deliberately skips: the patterns files contain
// literal SDK strings as regex sources, which match themselves. Skipping the
// patterns directory keeps the report signal-clean. The pattern lists are
// reviewed by reading the source, not by self-scanning.
const SKIP_PATH_PARTS = [
  ['src', 'paranoid', 'patterns'].join(path.sep),
];

function isSkipped(filePath) {
  return SKIP_PATH_PARTS.some(p => filePath.includes(p));
}

function listJsFiles(dirs) {
  const out = [];
  for (const d of dirs) {
    if (!fs.existsSync(d)) continue;
    const walk = (p) => {
      const st = fs.statSync(p);
      if (st.isDirectory()) {
        for (const e of fs.readdirSync(p)) walk(path.join(p, e));
      } else if (p.endsWith('.js') && !isSkipped(p)) {
        out.push(p);
      }
    };
    walk(d);
  }
  return out;
}

function classifyMatch(context) {
  const m =
    context.match(LITERAL_HOST_RE) ||
    context.match(LITERAL_HOST_FIELD_RE) ||
    context.match(LITERAL_HOSTNAME_FIELD_RE);
  if (m) {
    const host = m[1];
    if (LLM_ENDPOINTS.has(host))     return { classification: 'llm-endpoint',  host };
    if (SIGNING_ENDPOINTS.has(host)) return { classification: 'signing-infra', host };
    return { classification: 'hardcoded-host', host };
  }
  if (RELATIVE_URL_RE.test(context)) {
    return { classification: 'local-loopback', host: null };
  }
  if (PROXY_BOUND_RE.test(context)) {
    return { classification: 'proxy-bound', host: null };
  }
  return { classification: 'unclassified', host: null };
}

function lineNumber(source, offset) {
  let n = 1;
  for (let i = 0; i < offset; i++) if (source.charCodeAt(i) === 10) n++;
  return n;
}

function lineText(source, offset) {
  const start = source.lastIndexOf('\n', offset - 1) + 1;
  const end   = source.indexOf('\n', offset);
  return source.slice(start, end === -1 ? source.length : end).trim();
}

/**
 * Scan a single file's text for network primitives.
 * Returns an array of hit records, possibly empty.
 */
function scanText(filePath, text) {
  const hits = [];
  for (const { re, label, kind } of NETWORK_PRIMITIVES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const offset = m.index;
      const ctxStart = Math.max(0, offset - CONTEXT_BEFORE);
      const ctxEnd   = Math.min(text.length, offset + CONTEXT_AFTER);
      const context  = text.slice(ctxStart, ctxEnd);
      const { classification, host } = classifyMatch(context);
      const severity =
        classification === 'hardcoded-host' ? 'critical' :
        classification === 'unclassified'   ? 'warn'     :
        'info';  // proxy-bound, llm-endpoint, signing-infra all benign
      hits.push({
        severity,
        file: filePath,
        line: lineNumber(text, offset),
        snippet: lineText(text, offset),
        primitive: label,
        kind,
        classification,
        host,
      });
    }
  }
  return hits;
}

/**
 * Run the source scan over an array of root directories.
 * Returns the canonical scanner shape.
 */
function scan(opts = {}) {
  const t0   = Date.now();
  const dirs = opts.dirs || [
    path.join(__dirname, '..', '..', 'src'),
    path.join(__dirname, '..', '..', 'bin'),
  ];
  const files = listJsFiles(dirs);
  let allHits = [];
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    allHits = allHits.concat(scanText(f, text));
  }
  const summary = { critical: 0, warn: 0, info: 0, ok: 0 };
  for (const h of allHits) summary[h.severity]++;

  return {
    name: 'source-scan',
    files: files.length,
    hits: allHits,
    summary,
    durationMs: Date.now() - t0,
  };
}

module.exports = { scan, scanText, classifyMatch, listJsFiles, LLM_ENDPOINTS, SIGNING_ENDPOINTS };
