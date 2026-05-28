'use strict';

/**
 * render.js: turn a paranoid report into the human terminal view or the
 * structured JSON view. Every emitted line ends with an ANSI reset to
 * avoid the bleed bug that affects Windows Terminal (see policy/doctor.js).
 */

const ANSI_RESET = '\x1b[0m';
const col = {
  r: s => `\x1b[31m${s}${ANSI_RESET}`,
  g: s => `\x1b[32m${s}${ANSI_RESET}`,
  y: s => `\x1b[33m${s}${ANSI_RESET}`,
  c: s => `\x1b[36m${s}${ANSI_RESET}`,
  d: s => `\x1b[2m${s}${ANSI_RESET}`,
  b: s => `\x1b[1m${s}${ANSI_RESET}`,
};
const safe = (s) => `${s}${ANSI_RESET}`;

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function colourForCount(count, goodIsZero) {
  if (goodIsZero) return count === 0 ? col.g : col.r;
  return count > 0 ? col.g : col.r;
}

function renderHuman(report) {
  const out = [];
  const push = (line) => out.push(safe(line));

  push('');
  push(col.b('⚡ Occasio Paranoid Doctor'));
  push('');

  // ── Static source scan ──────────────────────────────────────────────────
  const src = report.scanners['source-scan'];
  const srcByClass = {
    'proxy-bound': 0, 'hardcoded-host': 0, 'unclassified': 0,
    'llm-endpoint': 0, 'signing-infra': 0, 'local-loopback': 0,
  };
  const hostsByClass = { 'llm-endpoint': new Set(), 'signing-infra': new Set() };
  for (const h of src.hits) {
    srcByClass[h.classification] = (srcByClass[h.classification] || 0) + 1;
    if (h.host && hostsByClass[h.classification]) hostsByClass[h.classification].add(h.host);
  }
  push(col.b('  Static source scan'));
  push(`    ${col.d('Files scanned       ')} ${src.files} .js files under src/, bin/`);
  push(`    ${col.d('Network primitives  ')} ${src.hits.length} callsites located`);
  push(`    ${col.d('Proxy-bound         ')} ${col.g(srcByClass['proxy-bound'])} (URLs from request input or env)`);
  push(`    ${col.d('LLM endpoints       ')} ${col.g(srcByClass['llm-endpoint'])} (${[...hostsByClass['llm-endpoint']].join(', ') || 'none'})`);
  push(`    ${col.d('Signing infra       ')} ${col.g(srcByClass['signing-infra'])} (${[...hostsByClass['signing-infra']].join(', ') || 'none'})`);
  push(`    ${col.d('Local-loopback      ')} ${col.g(srcByClass['local-loopback'])} (relative URLs, same-origin)`);
  push(`    ${col.d('Hardcoded outbound  ')} ${colourForCount(srcByClass['hardcoded-host'], true)(srcByClass['hardcoded-host'])}`);
  push(`    ${col.d('Unclassified        ')} ${srcByClass['unclassified'] ? col.y(srcByClass['unclassified']) : col.g(0)}`);
  for (const h of src.hits) {
    if (h.classification === 'hardcoded-host') {
      push(`      ${col.r('!')} ${h.file}:${h.line}  ${col.d(h.snippet)}  ${col.r('host=' + (h.host || '?'))}`);
    }
  }
  push('');

  // ── Telemetry self-audit ─────────────────────────────────────────────────
  const sa = report.scanners['self-audit'];
  const srcMatches = sa.hits.filter(h => h.kind !== 'dependency').length;
  push(col.b('  Telemetry self-audit'));
  push(`    ${col.d('Source patterns     ')} ${sa.patternCount} known SDKs checked`);
  push(`    ${col.d('Source matches      ')} ${colourForCount(srcMatches, true)(srcMatches)}`);
  push(`    ${col.d('Dependency packages ')} ${sa.deps.runtime} runtime, ${sa.deps.dev} dev`);
  push(`    ${col.d('Dependency matches  ')} ${colourForCount(sa.deps.hits.length, true)(sa.deps.hits.length)}`);
  for (const h of sa.hits) {
    if (h.kind === 'dependency') {
      push(`      ${col.r('!')} ${h.package}  ${col.d('(' + h.scope + ' dep)')}`);
    } else {
      push(`      ${col.r('!')} ${h.file}:${h.line}  ${col.d(h.pattern)}  ${col.d(h.snippet)}`);
    }
  }
  push('');

  // ── Package integrity ────────────────────────────────────────────────────
  const pi = report.scanners['package-integrity'];
  push(col.b('  Package integrity'));
  push(`    ${col.d('Name                ')} ${pi.package.name || '(unknown)'}`);
  push(`    ${col.d('Version             ')} ${pi.package.version || '(unknown)'}`);
  push(`    ${col.d('Install path        ')} ${pi.package.installPath || '(unknown)'}`);
  push(`    ${col.d('Verify              ')} reproducible recipe printed below`);
  push('');

  // ── Audit chain ──────────────────────────────────────────────────────────
  const ch = report.scanners['chain-summary'];
  push(col.b('  Audit chain'));
  push(`    ${col.d('Rows walked         ')} ${ch.chain.chained} chained (+ ${ch.chain.legacy} legacy)`);
  push(`    ${col.d('GENESIS to tip      ')} ${ch.chain.ok ? col.g('intact') : col.y('with historical breaks (see below)')}`);
  push(`    ${col.d('Breaks              ')} ${ch.chain.breakCount === 0 ? col.g(0) : col.y(ch.chain.breakCount + ' (pre-v0.9 concurrent-writer events)')}`);
  push('');

  // ── Runtime network watch (optional, present when --watch is used) ──────
  if (report.scanners['network-watch']) {
    const nw = report.scanners['network-watch'];
    push(col.b('  Runtime network watch'));
    push(`    ${col.d('Window              ')} ${nw.windowSeconds}s (${nw.windowStartedAt} to ${nw.windowEndedAt})`);
    push(`    ${col.d('Connections observed')} ${nw.observations.length}`);
    push(`    ${col.d('Unique destinations ')} ${nw.destinations.length}`);
    if (nw.destinations.length === 0) {
      push(`    ${col.g('No outbound connection attempts during the window.')}`);
    } else {
      for (const d of nw.destinations) {
        push(`      ${col.d('•')} ${d.host || '?'}:${d.port || '?'} ${col.d('(' + d.transport + ', ' + d.count + 'x)')}`);
      }
    }
    push('');
  }

  // ── Closing block: the thing that travels ───────────────────────────────
  const srcZeroHard  = srcByClass['hardcoded-host'] === 0;
  const teleZero     = sa.hits.length === 0;
  const llmHostList  = [...hostsByClass['llm-endpoint']].join(', ') || '(none referenced statically)';
  push(col.d('  ────────────────────────────────────────'));
  push(`    ${srcZeroHard ? col.g('0') : col.r(srcByClass['hardcoded-host'])} hardcoded outbound URLs outside known LLM endpoints.`);
  push(`    ${teleZero ? col.g('0') : col.r(sa.hits.length)} telemetry endpoints found.`);
  push(`    ${srcZeroHard && teleZero ? col.g('0') : col.r('!')} phone-home routes detected.`);
  push('');
  push(`    LLM endpoints referenced: ${col.c(llmHostList)}.`);
  push('    Your agent authenticates against these with your own API key.');
  push('    There is no Occasio cloud.');
  push(col.d('  ────────────────────────────────────────'));
  push('');

  // ── Reproducible verify ─────────────────────────────────────────────────
  if (pi.recipe) {
    push(col.b('  Reproducible verify'));
    for (const cmd of pi.recipe) push(`    ${col.c(cmd)}`);
    push(`    ${col.d(pi.note)}`);
    push('');
  }

  // ── Signed report ────────────────────────────────────────────────────────
  push(col.b('  Signed report'));
  if (report.signature) {
    push(`    ${col.d('Status     ')} ${col.g('signed (Sigstore keyless)')}`);
    if (report.signature.identity?.subject)
      push(`    ${col.d('Identity   ')} ${report.signature.identity.subject}`);
    if (report.signature.rekor_entry)
      push(`    ${col.d('Rekor      ')} ${col.c(report.signature.rekor_entry)}`);
    push(`    ${col.d('SHA-256    ')} ${report.signature.payload_sha256}`);
  } else {
    push(col.d('    Unsigned. Pass --sign to produce a Sigstore-signed bundle'));
    push(col.d('    (requires GitHub Actions OIDC env, or --oidc-token <jwt>).'));
  }
  push('');

  return out.join('\n');
}

function renderJson(report) {
  return JSON.stringify(report, null, 2);
}

module.exports = { renderHuman, renderJson };
