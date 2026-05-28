'use strict';

/**
 * occasio compliance export --run <id> [--framework nist-ai-rmf|eu-ai-act|soc2]
 *
 * Bundle one run into an auditor-ready package:
 *   - chain.jsonl            (the slice of pipeline-events.jsonl for the run)
 *   - attestation.json       (the agent-attestation/v1 predicate if available)
 *   - bom.cyclonedx.json     (CycloneDX 1.6 ML-BOM, via src/bom/cyclonedx.js)
 *   - receipt.json           (small summary, via src/cli/receipt.js)
 *   - framework-mapping.json (this skeleton; documented stubs only)
 *   - summary.md             (human-readable cover sheet)
 *
 * Framework mapping is intentionally a SKELETON. Each supported framework
 * carries a small number of obviously-correct mappings (e.g., "EU AI Act
 * Art. 12 (logging) is satisfied by pipeline-events.jsonl as the canonical
 * log file") plus a clear "extend me" pointer to a paid policy bundle from
 * Occasio Labs for full coverage. This honest-skeleton approach keeps the
 * MVP shippable while signposting that complete mapping is a curated
 * deliverable, not a one-night auto-generation.
 *
 * Out of scope for this MVP:
 *   - Cryptographic signing of the bundle as a whole (use --sign on the
 *     individual artefacts; bundle-level signing lands in v0.10.x).
 *   - Full NIST AI RMF function-by-function mapping.
 *   - Full EU AI Act Article 12 / Article 13 control-by-control mapping.
 */

const fs   = require('fs');
const path = require('path');

const {
  loadEvents, summarize, buildToolStats, currentRunId,
} = require('../models/events');

const FRAMEWORKS = ['nist-ai-rmf', 'eu-ai-act', 'soc2'];

function exportRun(runId, outDir, framework) {
  const all = loadEvents({ runId });
  if (!all.length) return { ok: false, reason: 'no events for run' };

  fs.mkdirSync(outDir, { recursive: true });

  // 1. Chain slice
  const chainSlice = all.map(e => JSON.stringify(e)).join('\n') + '\n';
  fs.writeFileSync(path.join(outDir, 'chain.jsonl'), chainSlice);

  // 2. Receipt
  const { buildReceipt } = require('./receipt');
  const receipt = buildReceipt(runId);
  if (receipt) {
    fs.writeFileSync(path.join(outDir, 'receipt.json'), JSON.stringify(receipt, null, 2));
  }

  // 3. CycloneDX ML-BOM
  const { buildBom } = require('../bom/cyclonedx');
  const bom = buildBom(runId);
  if (bom) {
    fs.writeFileSync(path.join(outDir, 'bom.cyclonedx.json'), JSON.stringify(bom, null, 2));
  }

  // 4. Framework mapping skeleton
  const mapping = buildFrameworkMapping(runId, framework, all);
  fs.writeFileSync(path.join(outDir, 'framework-mapping.json'),
    JSON.stringify(mapping, null, 2));

  // 5. Summary cover sheet
  const summary = buildSummary(runId, receipt, mapping, framework);
  fs.writeFileSync(path.join(outDir, 'summary.md'), summary);

  return { ok: true, outDir, files: [
    'chain.jsonl', 'receipt.json', 'bom.cyclonedx.json',
    'framework-mapping.json', 'summary.md',
  ]};
}

function buildFrameworkMapping(runId, framework, events) {
  const acct  = summarize(events.filter(e => e.kind === 'request'));
  const tools = buildToolStats(events.filter(e => e.kind === 'tool_call'));

  const baseMapping = {
    framework,
    run_id: runId,
    generated_at: new Date().toISOString(),
    note: 'This mapping is a skeleton MVP. Full framework coverage is a curated deliverable available as a paid policy bundle from Occasio Labs. See docs/SUSTAINABILITY.md.',
    controls: [],
  };

  // Mappings that hold regardless of framework
  const generic = [
    {
      control_id: 'occasio:audit-chain',
      description: 'A tamper-evident hash-chained log of every governed tool call, request, and policy load exists for this run.',
      evidence: { chain_file: 'chain.jsonl', event_count: events.length },
      status: 'satisfied',
    },
    {
      control_id: 'occasio:policy-binding',
      description: 'The active policy at decision time is recorded as a policy_loaded event bound to the chain by hash.',
      evidence: { policy_loaded_events: events.filter(e => e.kind === 'policy_loaded').length },
      status: events.some(e => e.kind === 'policy_loaded') ? 'satisfied' : 'partial',
    },
  ];

  if (framework === 'eu-ai-act') {
    baseMapping.controls = generic.concat([
      {
        control_id: 'eu-ai-act/art-12',
        description: 'Automatic recording of events (logs) of high-risk AI systems throughout their lifecycle.',
        evidence: { chain_file: 'chain.jsonl', verifiable_via: 'occasio audit verify' },
        status: 'satisfied',
        note: 'Article 12 requires the existence and tamper-evidence of an event log. Occasio provides both. Full control coverage (12.2 retention, 12.3 traceability) requires the EU-AI-Act policy bundle.',
      },
      {
        control_id: 'eu-ai-act/art-13',
        description: 'Transparency and provision of information to deployers about the system.',
        evidence: { receipt: 'receipt.json', bom: 'bom.cyclonedx.json' },
        status: 'partial',
        note: 'Receipt + ML-BOM cover the runtime side. Model card / training data documentation is out of scope for Occasio.',
      },
    ]);
  } else if (framework === 'nist-ai-rmf') {
    baseMapping.controls = generic.concat([
      {
        control_id: 'nist-ai-rmf/measure-2.7',
        description: 'AI system trustworthiness, validity and reliability characteristics are measured.',
        evidence: { tool_stats: tools, accounting: acct },
        status: 'partial',
        note: 'Runtime behavioural metrics covered. Full MEASURE function alignment requires the NIST AI RMF policy bundle.',
      },
      {
        control_id: 'nist-ai-rmf/manage-2.2',
        description: 'AI risks and benefits from third-party resources are regularly monitored.',
        evidence: { llm_endpoints_referenced: ['api.anthropic.com'] },
        status: 'partial',
        note: 'Endpoint monitoring covered via paranoid doctor. Full third-party assurance requires custom policy.',
      },
    ]);
  } else if (framework === 'soc2') {
    baseMapping.controls = generic.concat([
      {
        control_id: 'soc2/cc-7.1',
        description: 'The entity uses detection and monitoring procedures to identify changes that could result in security vulnerabilities.',
        evidence: { anomaly_detectors: 4, chain_file: 'chain.jsonl' },
        status: 'partial',
        note: 'Anomaly detectors fire on demand. Continuous monitoring integration requires the SOC2 policy bundle plus SIEM tail integration.',
      },
    ]);
  } else {
    baseMapping.controls = generic;
    baseMapping.note += ' Unknown framework, only generic controls emitted.';
  }

  return baseMapping;
}

function buildSummary(runId, receipt, mapping, framework) {
  const r = receipt || { duration_s: 0, accounting: {}, tools: {} };
  return [
    `# Occasio Compliance Bundle`,
    ``,
    `**Run:** \`${runId}\`  `,
    `**Framework:** \`${framework || 'generic'}\`  `,
    `**Generated:** ${new Date().toISOString()}`,
    ``,
    `## What is in this bundle`,
    ``,
    `- \`chain.jsonl\`: the hash-chained audit log slice for this run. Verify with \`occasio audit verify --file chain.jsonl\` (or the Python walker at \`docs/audit_walker.py\`).`,
    `- \`receipt.json\`: a small summary of the run, suitable for inclusion in audit narratives.`,
    `- \`bom.cyclonedx.json\`: CycloneDX 1.6 ML-BOM listing models, tools, and files referenced.`,
    `- \`framework-mapping.json\`: control-level mapping skeleton for the chosen framework.`,
    ``,
    `## Headline numbers`,
    ``,
    `- Duration: ${r.duration_s}s`,
    `- Requests: ${r.accounting?.requests ?? 0}, cost: $${(r.accounting?.cost_usd ?? 0).toFixed(4)}`,
    `- Tool calls: ${r.tools?.total ?? 0} (local: ${r.tools?.local ?? 0}, blocked: ${r.tools?.blocked ?? 0}, shaped: ${r.tools?.transformed ?? 0})`,
    `- Secrets redacted in tool results: ${r.tools?.secrets_redacted ?? 0}`,
    ``,
    `## Verification`,
    ``,
    `Third parties verify this bundle offline. See \`docs/VERIFY.md\` (shipped in the Occasio repo) for the step-by-step procedure.`,
    ``,
    `## Mapping scope`,
    ``,
    `The framework mapping is an MVP skeleton. Generic controls (audit chain, policy binding) are populated automatically. Framework-specific control coverage is a curated deliverable available as a paid policy bundle from Occasio Labs. See \`docs/SUSTAINABILITY.md\` in the source repository for the revenue model.`,
    ``,
  ].join('\n');
}

function run(args) {
  const a = args || [];
  if (a[0] !== 'export') {
    process.stderr.write('usage: occasio compliance export --run <id> [--framework <name>] [--out dir]\n');
    process.stderr.write(`frameworks: ${FRAMEWORKS.join(', ')}\n`);
    return 2;
  }
  const rest    = a.slice(1);
  const runIdx  = rest.indexOf('--run');
  const fwIdx   = rest.indexOf('--framework');
  const outIdx  = rest.indexOf('--out');
  const runId     = runIdx >= 0 ? rest[runIdx + 1] : currentRunId();
  const framework = fwIdx >= 0 ? rest[fwIdx + 1] : 'generic';
  const outDir    = outIdx >= 0 ? rest[outIdx + 1]
                                : path.join(process.cwd(), `occasio-compliance-${runId || 'norun'}`);

  if (!runId) {
    process.stderr.write('No run_id available. Pass --run <id>.\n');
    return 2;
  }

  const res = exportRun(runId, outDir, framework);
  if (!res.ok) {
    process.stderr.write(`Export failed: ${res.reason}\n`);
    return 1;
  }
  process.stdout.write(`Compliance bundle written to ${res.outDir}\n`);
  for (const f of res.files) process.stdout.write(`  ${f}\n`);
  process.stdout.write(`\nVerify with: occasio audit verify --file ${path.join(res.outDir, 'chain.jsonl')}\n`);
  return 0;
}

module.exports = { run, exportRun, buildFrameworkMapping };
