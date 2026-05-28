'use strict';

/**
 * CycloneDX 1.6 AI-BOM emitter from an Occasio audit-chain slice.
 *
 * CycloneDX 1.6 added ML-BOM extensions (https://cyclonedx.org/capabilities/mlbom/)
 * for describing AI systems: models referenced, datasets accessed, services
 * called, and the relationships between them. Occasio chains carry exactly the
 * data needed to populate the runtime side of that picture: which model
 * answered each request, which tools the agent invoked, which files it
 * touched.
 *
 * What this emitter produces is a CycloneDX 1.6 JSON document with:
 *   - bom-ref pointing at the Occasio run
 *   - one machine-learning-model component per unique model observed
 *   - one library component per unique tool invoked (with action metadata)
 *   - one data component per file path accessed (read or written)
 *   - services entries for the LLM endpoints contacted
 *   - dependencies graph linking the agent run to its observed components
 *
 * What it does NOT do:
 *   - validate against the canonical CycloneDX JSON schema (use cyclonedx-cli
 *     for that). The shape is targeted but not formally validated here.
 *   - emit dataset components (Occasio does not have training-data context).
 *   - infer model lineage. Models are listed as observed, not as composed.
 *
 * MVP scope: the JSON output is structurally close to a valid 1.6 ML-BOM.
 * Future work: full schema-conformance pass, formulation block for training
 * provenance, signature embedding.
 *
 * Sharing note: the emitted BOM contains absolute file paths the agent
 * touched (as `data` components and `metadata.component.properties`). This
 * is correct for an internal audit deliverable, where reviewers want to
 * know what was accessed. Before publishing the BOM externally, callers
 * should review and scrub paths that should not leave the environment.
 * The receipt at src/cli/receipt.js is the path-free surface intended for
 * public sharing.
 */

const crypto = require('crypto');
const {
  loadEvents, summarize, buildToolStats, currentRunId,
} = require('../models/events');

const CDX_SPEC_VERSION = '1.6';
const TOOL_VENDOR      = 'Occasio Labs';
const TOOL_NAME        = 'occasio';
const TOOL_VERSION     = '0.9.2';

function makeSerial() {
  return 'urn:uuid:' + crypto.randomUUID();
}

function isoNow() {
  return new Date().toISOString();
}

/**
 * Build a CycloneDX 1.6 ML-BOM from a run slice.
 * Returns a plain object suitable for JSON.stringify.
 */
function buildBom(runId, opts = {}) {
  const all       = loadEvents({ runId });
  const reqEvents = all.filter(e => e.kind === 'request');
  const tool      = all.filter(e => e.kind === 'tool_call');
  if (!all.length) return null;

  const acct      = summarize(reqEvents);
  const toolStats = buildToolStats(tool);

  // Unique models observed in this run
  const models = new Set();
  for (const e of reqEvents) {
    if (e.model) models.add(e.model);
  }

  // Unique tools invoked
  const toolsByName = new Map();
  for (const e of tool) {
    const name = e.tool_name || 'unknown';
    const entry = toolsByName.get(name) || { name, count: 0, actions: {} };
    entry.count++;
    entry.actions[e.action || 'UNKNOWN'] = (entry.actions[e.action || 'UNKNOWN'] || 0) + 1;
    toolsByName.set(name, entry);
  }

  // Unique file paths accessed (extracted from normalised tool_inputs where present)
  const files = new Set();
  for (const e of tool) {
    const inp = e.tool_inputs || {};
    if (inp.path)      files.add(inp.path);
    if (inp.file_path) files.add(inp.file_path);
  }

  const components = [];

  for (const model of models) {
    components.push({
      'bom-ref': `model:${model}`,
      type: 'machine-learning-model',
      name: model,
      properties: [
        { name: 'occasio:role',     value: 'inference' },
        { name: 'occasio:observed', value: 'runtime' },
      ],
    });
  }

  for (const t of toolsByName.values()) {
    components.push({
      'bom-ref': `tool:${t.name}`,
      type: 'library',
      name: t.name,
      properties: [
        { name: 'occasio:invocations', value: String(t.count) },
        { name: 'occasio:actions',     value: JSON.stringify(t.actions) },
      ],
    });
  }

  for (const f of files) {
    components.push({
      'bom-ref': `file:${f}`,
      type: 'data',
      name: f,
      properties: [{ name: 'occasio:role', value: 'accessed' }],
    });
  }

  const services = [];
  // Today the proxy talks to api.anthropic.com (see allowlist in
  // src/paranoid/source-scan.js). Future adapters will add more.
  if (models.size > 0) {
    services.push({
      'bom-ref': 'service:llm-endpoint',
      name: 'api.anthropic.com',
      endpoints: ['https://api.anthropic.com/v1/messages'],
      authenticated: true,
      'x-trust-boundary': true,
      properties: [
        { name: 'occasio:role', value: 'llm-inference' },
      ],
    });
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: CDX_SPEC_VERSION,
    serialNumber: makeSerial(),
    version: 1,
    metadata: {
      timestamp: isoNow(),
      tools: { components: [{
        type:    'application',
        vendor:  TOOL_VENDOR,
        name:    TOOL_NAME,
        version: TOOL_VERSION,
      }] },
      component: {
        'bom-ref': `occasio:run:${runId}`,
        type: 'application',
        name: `occasio-agent-run-${runId}`,
        version: TOOL_VERSION,
        properties: [
          { name: 'occasio:run_id',           value: runId },
          { name: 'occasio:event_count',      value: String(all.length) },
          { name: 'occasio:request_count',    value: String(acct.requests) },
          { name: 'occasio:tool_call_count',  value: String(toolStats.total) },
          { name: 'occasio:cost_usd',         value: acct.cost.toFixed(6) },
          { name: 'occasio:blocked_count',    value: String(toolStats.blocked) },
          { name: 'occasio:transformed_count', value: String(toolStats.transformed) },
        ],
      },
    },
    components,
    services,
    dependencies: [{
      ref: `occasio:run:${runId}`,
      dependsOn: components.map(c => c['bom-ref']).concat(services.map(s => s['bom-ref'])),
    }],
  };

  return bom;
}

function usage() {
  return [
    'occasio bom export — emit a CycloneDX 1.6 ML-BOM from a run slice',
    '',
    'usage: occasio bom export [--run <id>] [--out <path>]',
    '',
    'flags:',
    '  --run <id>     explicit run_id (default: currentRunId from session.json)',
    '  --out <path>   write JSON BOM to file (default: stdout)',
    '',
    'example:',
    '  occasio bom export --run <id> --out bom.cyclonedx.json',
    '',
    'note: emitted BOM contains absolute file paths from the run. Intended for',
    'internal audit; scrub before public distribution.',
    '',
  ].join('\n');
}

function run(args) {
  const a = args || [];
  if (a.includes('--help') || a.includes('-h')) {
    process.stdout.write(usage());
    return 0;
  }
  const runIdx = a.indexOf('--run');
  const outIdx = a.indexOf('--out');
  const runId  = runIdx >= 0 ? a[runIdx + 1] : currentRunId();
  const out    = outIdx >= 0 ? a[outIdx + 1] : null;

  if (!runId) {
    process.stderr.write(usage());
    return 2;
  }

  const bom = buildBom(runId);
  if (!bom) {
    process.stderr.write(`No events found for run_id ${runId}.\n`);
    return 1;
  }

  const json = JSON.stringify(bom, null, 2);
  if (out) {
    require('fs').writeFileSync(out, json);
    process.stderr.write(`CycloneDX 1.6 ML-BOM written to ${out}\n`);
  } else {
    process.stdout.write(json + '\n');
  }
  return 0;
}

module.exports = { run, buildBom, usage };
