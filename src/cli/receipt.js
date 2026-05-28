'use strict';

/**
 * occasio receipt [--run <id>] [--sign] [--out <path>]
 *
 * Emit a tiny session receipt (target size around 1 to 2 KB) summarising one
 * agent run. The receipt is the shareable artefact a user can post anywhere
 * without leaking actual prompts, file contents, or tool inputs.
 *
 * What the receipt carries:
 *   - run_id, start, end, duration
 *   - counts: requests, cost, tokens in/out, savings
 *   - tool stats: total, local, blocked, transformed, secrets redacted
 *   - chain commitment: first_hash, last_hash of the slice
 *   - optional signature block when --sign is used
 *
 * What it does NOT carry:
 *   - tool inputs (file paths, prompts, command strings)
 *   - file contents, response bodies
 *   - any identifier beyond the run_id (no cwd, no email, no host) in the
 *     unsigned receipt body
 *
 * Signature identity note: when --sign is used the embedded
 * `signature.identity` object carries OIDC claims (issuer, subject,
 * audience). For GitHub Actions OIDC, `subject` is the workflow URL plus
 * a ref (e.g. `https://github.com/.../publish.yml@refs/heads/main`),
 * which reveals the producer's workflow path. Some OIDC providers
 * include the user email in the subject claim. Before redistributing a
 * signed receipt to an untrusted audience, callers can strip
 * `signature.identity` and keep only `signature.rekor_entry` (which is
 * a public Sigstore log URL anyone can verify against).
 *
 * Verification of a receipt is two-step:
 *   1. If --sign was used, verify the Sigstore bundle against the receipt JSON.
 *   2. Re-walk the producer's chain (when available) and confirm first_hash
 *      and last_hash appear in the correct order.
 *
 * The receipt is intentionally not an in-toto Statement. It is a one-line
 * brag with cryptographic backing, not an SLSA artefact attestation.
 */

const fs   = require('fs');
const path = require('path');

const {
  loadEvents, summarize, buildToolStats, currentRunId,
} = require('../models/events');

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`, c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,  b: s => `\x1b[1m${s}\x1b[0m`,
};

function buildReceipt(runId) {
  const all = loadEvents({ runId });
  if (!all.length) return null;

  const reqEvents  = all.filter(e => e.kind === 'request');
  const toolEvents = all.filter(e => e.kind === 'tool_call');
  const chained    = all.filter(e => e.hash && e.prev_hash);

  const acct  = summarize(reqEvents);
  const tools = buildToolStats(toolEvents);

  const firstHash = chained.length ? chained[0].prev_hash : null;
  const lastHash  = chained.length ? chained[chained.length - 1].hash : null;

  const startTs = all.find(e => e.ts)?.ts || null;
  const endTs   = [...all].reverse().find(e => e.ts)?.ts || null;
  const durationS = (startTs && endTs)
    ? Math.max(0, Math.round((new Date(endTs) - new Date(startTs)) / 1000))
    : 0;

  return {
    schema:        'occasio-receipt/v1',
    run_id:        runId,
    started_at:    startTs,
    ended_at:      endTs,
    duration_s:    durationS,
    accounting: {
      requests:           acct.requests,
      input_tokens:       acct.input_tokens,
      output_tokens:      acct.output_tokens,
      cost_usd:           Number(acct.cost.toFixed(6)),
      cache_savings_usd:  Number(acct.cache_savings.toFixed(6)),
      lao_savings_usd:    Number(acct.lao_cost_saved.toFixed(6)),
      distill_savings_usd: Number(acct.distill_cost_saved.toFixed(6)),
    },
    tools: {
      total:            tools.total,
      local:            tools.local,
      cloud:            tools.pass,
      blocked:          tools.blocked,
      transformed:      tools.transformed,
      secrets_redacted: tools.secrets_redacted,
    },
    chain: {
      first_hash:  firstHash,
      last_hash:   lastHash,
      event_count: chained.length,
    },
    generated_at: new Date().toISOString(),
    signature:    null,
  };
}

async function maybeSign(receipt, opts) {
  if (!opts.sign) return null;
  const { signParanoidReport } = require('../paranoid/sign');
  const payload = JSON.stringify(receipt);
  // Receipts reuse the paranoid signing helper since the payload-type-by-suffix
  // is the same shape. The DSSE payload type tag is "paranoid-report+json"
  // today; that string is the only difference and is reviewed alongside the
  // signing call site in src/paranoid/sign.js.
  const { bundle, signatureBlock } = await signParanoidReport(payload, {
    oidcToken: opts.oidcToken,
  });
  receipt.signature = signatureBlock;
  return bundle;
}

function renderReceiptHuman(receipt) {
  const lines = [];
  lines.push(col.b('\n⚡ Occasio session receipt'));
  lines.push('');
  lines.push(`  ${col.d('run_id      ')} ${receipt.run_id}`);
  if (receipt.started_at) lines.push(`  ${col.d('started     ')} ${receipt.started_at}`);
  if (receipt.ended_at)   lines.push(`  ${col.d('ended       ')} ${receipt.ended_at}`);
  lines.push(`  ${col.d('duration    ')} ${receipt.duration_s}s`);
  lines.push('');
  lines.push(col.b('  Accounting'));
  lines.push(`    ${col.d('cost      ')} ${col.y('$' + receipt.accounting.cost_usd.toFixed(4))}`);
  lines.push(`    ${col.d('requests  ')} ${receipt.accounting.requests}`);
  lines.push(`    ${col.d('tokens    ')} ${receipt.accounting.input_tokens} in, ${receipt.accounting.output_tokens} out`);
  lines.push('');
  lines.push(col.b('  Tools'));
  lines.push(`    ${col.d('total     ')} ${receipt.tools.total}`);
  lines.push(`    ${col.d('local     ')} ${col.g(receipt.tools.local)}`);
  lines.push(`    ${col.d('cloud     ')} ${receipt.tools.cloud}`);
  if (receipt.tools.blocked)          lines.push(`    ${col.d('blocked   ')} ${col.r(receipt.tools.blocked)}`);
  if (receipt.tools.transformed)      lines.push(`    ${col.d('shaped    ')} ${col.c(receipt.tools.transformed)}`);
  if (receipt.tools.secrets_redacted) lines.push(`    ${col.d('secrets   ')} ${col.c(receipt.tools.secrets_redacted)} redacted`);
  lines.push('');
  lines.push(col.b('  Chain commitment'));
  lines.push(`    ${col.d('first_hash')} ${receipt.chain.first_hash || '(none)'}`);
  lines.push(`    ${col.d('last_hash ')} ${receipt.chain.last_hash || '(none)'}`);
  lines.push(`    ${col.d('events    ')} ${receipt.chain.event_count}`);
  if (receipt.signature) {
    lines.push('');
    lines.push(col.b('  Signature'));
    lines.push(`    ${col.d('type      ')} ${receipt.signature.type}`);
    if (receipt.signature.rekor_entry)
      lines.push(`    ${col.d('rekor     ')} ${col.c(receipt.signature.rekor_entry)}`);
    lines.push(`    ${col.d('sha256    ')} ${receipt.signature.payload_sha256}`);
  }
  lines.push('');
  return lines.join('\n');
}

async function run(args) {
  const a = args || [];
  const runIdx  = a.indexOf('--run');
  const outIdx  = a.indexOf('--out');
  const tokenIdx = a.indexOf('--oidc-token');
  const runIdArg = runIdx >= 0 ? a[runIdx + 1] : null;
  const outArg   = outIdx >= 0 ? a[outIdx + 1] : null;
  const jsonOut  = a.includes('--json');
  const sign     = a.includes('--sign');
  const oidcToken = tokenIdx >= 0 ? a[tokenIdx + 1] : undefined;

  const runId = runIdArg || currentRunId();
  if (!runId) {
    process.stderr.write('No run_id available. Pass --run <id> or start a session first.\n');
    return 2;
  }
  const receipt = buildReceipt(runId);
  if (!receipt) {
    process.stderr.write(`No events found for run_id ${runId}.\n`);
    return 1;
  }

  let bundle = null;
  if (sign) {
    try { bundle = await maybeSign(receipt, { sign, oidcToken }); }
    catch (e) {
      process.stderr.write(`\n  Sign failed: ${e.message}\n  Emitting unsigned receipt.\n\n`);
    }
  }

  const json = JSON.stringify(receipt);

  if (outArg) {
    fs.writeFileSync(outArg, json);
    if (bundle) {
      const sigPath = outArg.replace(/\.json$/, '') + '.sigstore.json';
      fs.writeFileSync(sigPath, JSON.stringify(bundle));
      process.stderr.write(`Receipt written to ${outArg}\nSignature bundle written to ${sigPath}\n`);
    } else {
      process.stderr.write(`Receipt written to ${outArg}\n`);
    }
    return 0;
  }

  if (jsonOut) {
    process.stdout.write(json + '\n');
  } else {
    process.stdout.write(renderReceiptHuman(receipt));
  }
  return 0;
}

module.exports = { run, buildReceipt, renderReceiptHuman };
