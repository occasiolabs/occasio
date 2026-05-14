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

// ── Markdown escaping ───────────────────────────────────────────────────────
// Values from the attestation come from the agent's tool calls — a malicious
// or compromised tool name can contain Markdown control characters that
// break out of the table cell, inject links, or smuggle raw HTML through
// GitHub's renderer. Escape before interpolating into the Check Run summary.
//
// `mdCode` is for values rendered inside `` `...` `` cells: only the
// backtick itself needs handling (we strip rather than escape, because
// inline-code in GitHub-Flavored Markdown has no escape mechanism).
function mdCode(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/[\r\n]+/g, ' ')   // collapse newlines so cells stay one-line
    .replace(/`/g, 'ˋ')    // backtick → ˋ (visually similar, breaks out impossible)
    .replace(/\|/g, '\\|')      // GFM table cell separator
    .slice(0, 256);             // truncate runaway values
}
// `mdText` is for values rendered as raw Markdown text (no code fence
// around them). Escape the full GFM punctuation set.
function mdText(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/[\r\n]+/g, ' ')
    .replace(/([\\`*_{}\[\]()#+\-.!|<>])/g, '\\$1')
    .slice(0, 256);
}
function intOr0(n) { return Number.isFinite(+n) ? Math.trunc(+n) : 0; }

// Only render Rekor as a link if it is the public Sigstore search domain
// over https. Anything else → display as escaped text, no clickable link.
function safeRekorUrl(raw) {
  if (typeof raw !== 'string') return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return null;
    if (u.host !== 'search.sigstore.dev') return null;
    return u.toString();
  } catch { return null; }
}

// ── Summary builder ─────────────────────────────────────────────────────────
// Pure function — no env access, no I/O — so it can be unit-tested directly.
// Returns { title, summary } ready for the Checks API body.
function buildSummary(att, rekorRaw) {
  const sum    = att.execution_summary || {};
  const signed = !!(att.signature && att.signature.type);

  const title = String(
    `LocalFirst Attested · ${intOr0(sum.tool_calls)} calls · ${intOr0(sum.blocked)} blocked`
  ).slice(0, 255);

  const lines = [];
  lines.push(`**Predicate:** \`${mdCode(att.predicate_type)}\``);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Agent | \`${mdCode(att.agent?.platform || 'unknown')}\` ${att.agent?.model ? '· `' + mdCode(att.agent.model) + '`' : ''} |`);
  lines.push(`| run_id | \`${mdCode(att.subject?.run_id || 'unknown')}\` |`);
  if (att.subject?.git_commit) {
    lines.push(`| commit | \`${mdCode(String(att.subject.git_commit).slice(0,12))}\` |`);
  }
  lines.push(`| Policy hash | \`${mdCode((att.policy?.file_hash || '').slice(0,16))}…\` (${mdText(att.policy?.source || 'unknown')}) |`);
  lines.push(`| Tool calls | **${intOr0(sum.tool_calls)}** (LOCAL ${intOr0(sum.local)} · PASS ${intOr0(sum.passed)} · BLOCK ${intOr0(sum.blocked)} · TRANSFORM ${intOr0(sum.transformed)}) |`);
  lines.push(`| Secrets redacted | ${intOr0(sum.secrets_redacted)} |`);
  lines.push(`| Chain | \`${mdCode((att.audit_chain?.first_hash || '').slice(0,12) || '∅')}…${mdCode((att.audit_chain?.last_hash || '').slice(0,12) || '∅')}\` · ${intOr0(att.audit_chain?.event_count)} events |`);
  lines.push(`| Signature | ${signed ? `✓ \`${mdCode(att.signature.type)}\`` : '— unsigned (informational only)'} |`);
  const rekorSafe = safeRekorUrl(rekorRaw);
  if (rekorSafe)       lines.push(`| Rekor | [search.sigstore.dev](${rekorSafe}) |`);
  else if (rekorRaw)   lines.push(`| Rekor | \`${mdCode(rekorRaw)}\` (non-Rekor URL — not linked) |`);
  lines.push('');

  if (Array.isArray(sum.blocked_events) && sum.blocked_events.length) {
    lines.push('### Blocked attempts');
    lines.push('');
    lines.push('| Tool | Target | Rule | When |');
    lines.push('|---|---|---|---|');
    for (const b of sum.blocked_events.slice(0, 25)) {
      lines.push(`| \`${mdCode(b.tool)}\` | \`${mdCode((b.target || '').slice(0, 80))}\` | \`${mdCode(b.rule)}\` | T+${intOr0(b.at_offset_s)}s |`);
    }
    if (sum.blocked_events.length > 25) {
      lines.push(`| … | (${intOr0(sum.blocked_events.length - 25)} more in artifact) | | |`);
    }
    lines.push('');
  }

  lines.push(`<sub>Spec: <a href="https://github.com/localfirst-ai/localfirst/blob/main/spec/agent-attestation/v1/README.md">agent-attestation/v1</a> · Independent verifier: <code>localfirst attest verify</code> · Artifacts attached to this workflow run.</sub>`);

  return { title, summary: lines.join('\n'), signed };
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
    name:         'LocalFirst Attested',
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
      'User-Agent': 'localfirst-ai-attest-action',
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
