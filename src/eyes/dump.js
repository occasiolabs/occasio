'use strict';

/**
 * eyes/dump.js — render a captured payload as plain copy-friendly text.
 *
 * Used by the `c` hotkey to push the current outbound onto the system
 * clipboard. No ANSI; faithful to what was actually in the JSON request body.
 */

const SR_RE = /<system-reminder>[\s\S]*?<\/system-reminder>/g;

function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024*1024)).toFixed(2) + ' MB';
}

function dumpText(payload, opts) {
  opts = opts || {};
  if (!payload) return '(no payload)\n';
  const stripReminders = !!opts.stripReminders;
  const lines = [];
  lines.push(`# OUTBOUND #${payload.seq} → api.anthropic.com`);
  lines.push(`# ${payload.ts}  ·  ${fmtBytes(payload.byteCount?.after)}  ·  ${payload.redactionCount || 0} redacted  ·  ${payload.blockedCount || 0} blocked`);
  if (payload.model) lines.push(`# model: ${payload.model}`);
  if (payload.runId) lines.push(`# run:   ${payload.runId}`);
  lines.push('');

  if (payload.system?.text) {
    lines.push(`## system prompt (${fmtBytes(payload.system.bytes)})`);
    lines.push(payload.system.text);
    lines.push('');
  }

  if (Array.isArray(payload.messages)) {
    for (const m of payload.messages) {
      lines.push(`## [${m.role}]`);
      for (const b of m.blocks || []) {
        if (b.kind === 'text') {
          const t = stripReminders ? (b.text || '').replace(SR_RE, '').trim() : b.text;
          if (t) lines.push(t);
        } else if (b.kind === 'tool_use') {
          lines.push(`→ tool_use ${b.toolName} ${JSON.stringify(b.input || {})}`);
        } else if (b.kind === 'tool_result') {
          lines.push(`← tool_result (${fmtBytes(b.bytes)}${b.isError ? ', ERROR' : ''})`);
          if (b.text) lines.push(b.text);
        } else {
          lines.push(`[${b.kind}${b.type ? ' ' + b.type : ''}]`);
        }
      }
      lines.push('');
    }
  }

  if (payload.response) {
    const r = payload.response;
    lines.push(`## ← [assistant${r.model ? ' · ' + r.model : ''}${r.stopReason ? ' · ' + r.stopReason : ''}]`);
    for (const b of r.blocks || []) {
      if (b.kind === 'text') lines.push(b.text || '');
      else if (b.kind === 'tool_use') lines.push(`→ tool_use ${b.toolName} ${JSON.stringify(b.input || {})}`);
      else lines.push(`[${b.kind}${b.type ? ' ' + b.type : ''}]`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function copyToClipboard(text) {
  // Best-effort, async; never throws. Returns a promise that resolves to
  // { ok, via } so the UI can show a tiny confirmation.
  return new Promise((resolve) => {
    let cmd, args;
    if (process.platform === 'win32') { cmd = 'clip'; args = []; }
    else if (process.platform === 'darwin') { cmd = 'pbcopy'; args = []; }
    else { cmd = 'xclip'; args = ['-selection', 'clipboard']; }
    let child;
    try {
      const { spawn } = require('child_process');
      child = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'], shell: process.platform === 'win32' });
    } catch {
      return resolve({ ok: false, via: cmd });
    }
    child.on('error', () => resolve({ ok: false, via: cmd }));
    child.on('close', (code) => resolve({ ok: code === 0, via: cmd }));
    try { child.stdin.end(text); }
    catch { resolve({ ok: false, via: cmd }); }
  });
}

module.exports = { dumpText, copyToClipboard };
