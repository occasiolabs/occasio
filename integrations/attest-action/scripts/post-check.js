#!/usr/bin/env node
'use strict';

/**
 * post-check.js — invoked by action.yml step `check`.
 *
 * Reads the produced attestation, formats a GitHub Check Run with a
 * Markdown summary, and posts it via the Checks API.
 *
 * Requires the workflow to grant `permissions: checks: write`.
 *
 * Node 20+: uses built-in fetch.
 */

const fs   = require('fs');
const path = require('path');

// Summary builder + Markdown escapers live in src/ so the npm-published
// package + this Action share the same implementation. See
// src/attest/check-summary.js for the JSDoc.
const {
  mdCode, mdText, intOr0, safeRekorUrl, buildSummary,
} = require('../../../src/attest/check-summary');

function out(key, val) {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${key}=${String(val).replace(/\r?\n/g, ' ')}\n`;
  if (file) fs.appendFileSync(file, line, 'utf8');
  else      process.stdout.write(`::set-output name=${key}::${val}\n`);
}

function die(msg, exitCode = 1) {
  process.stderr.write(`[attest-action:check] ${msg}\n`);
  process.exit(exitCode);
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  const TOKEN = process.env.GITHUB_TOKEN;
  const REPO  = process.env.GITHUB_REPOSITORY;
  const SHA   = process.env.LF_HEAD_SHA;
  const ATT   = process.env.LF_ATTESTATION_PATH;
  const REK   = process.env.LF_REKOR_ENTRY || '';
  const VIEW  = (process.env.LF_VIEW_BASE_URL || '').replace(/\/+$/, '');

  if (!TOKEN) die('GITHUB_TOKEN missing — set inputs.github-token or grant `checks: write`.');
  if (!REPO || !SHA) die('GITHUB_REPOSITORY / head SHA env vars missing.');
  if (!ATT || !fs.existsSync(ATT)) die(`attestation file not found: ${ATT}`);

  const att = JSON.parse(fs.readFileSync(ATT, 'utf8'));
  const { title, summary, signed } = buildSummary(att, REK);

  const detailsUrl = VIEW
    ? `${VIEW}/?repo=${encodeURIComponent(REPO)}&sha=${encodeURIComponent(SHA)}`
    : undefined;

  const body = {
    name:         'Occasio Attested',
    head_sha:     SHA,
    status:       'completed',
    // Neutral when unsigned (informational), success when signed. BLOCK events
    // are policy doing its job, not a CI regression.
    conclusion:   signed ? 'success' : 'neutral',
    started_at:   att.agent?.started_at || new Date().toISOString(),
    completed_at: new Date().toISOString(),
    details_url:  detailsUrl,
    output:       { title, summary },
  };

  const url = `https://api.github.com/repos/${REPO}/check-runs`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${TOKEN}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'occasiolabs-attest-action',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const txt = await res.text();
    die(`Check Run creation failed: ${res.status} ${res.statusText}\n${txt}`);
  }
  const json = await res.json();
  out('check-run-url', json.html_url || '');
  process.stdout.write(`[attest-action:check] ✓ Created Check Run #${json.id}: ${json.html_url}\n`);
}

if (require.main === module) {
  main().catch(e => die(e.stack || e.message));
}

module.exports = {
  mdCode, mdText, intOr0, safeRekorUrl, buildSummary, main,
};
