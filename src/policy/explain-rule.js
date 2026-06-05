'use strict';

/**
 * explain-rule.js — re-derive which policy rule produced a BLOCK, for
 * `occasio explain`. The audit row stores only the reason code (e.g.
 * "path-denied"), not the matching rule, so we reconstruct it from the event's
 * normalised inputs against the policy file. Pure: the caller supplies the
 * already-read policy text + parse (no I/O here).
 *
 * Only the CURRENT policy.yml content is available (the chain stores the old
 * policy's hash, not its bytes). When the current hash differs from the event's
 * policy_loaded hash, `provenance` is 'policy-changed' so the renderer can flag
 * the rule as best-effort. This changes no runtime behaviour — read-only.
 */

const engine = require('./engine');
let extractShellReadPaths, extractCommandPathTokens;
try { ({ extractShellReadPaths, extractCommandPathTokens } = require('./shell-path')); }
catch { extractShellReadPaths = () => []; extractCommandPathTokens = () => []; }

// ── raw-text line locators (no YAML location metadata in the parser) ─────────

function sectionHeaderLine(rawText, section) {
  if (typeof rawText !== 'string') return null;
  const lines = rawText.split('\n');
  const re = new RegExp('^(\\s*)' + section + '\\s*:');
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i].replace(/#.*$/, ''))) return i + 1;
  }
  return null;
}

function unquote(s) {
  const m = /^(['"])([\s\S]*)\1$/.exec(s);
  return m ? m[2] : s;
}

// Line (1-based) of a `- <value>` item under `section:`, or null.
function findListEntryLine(rawText, section, value) {
  if (typeof rawText !== 'string') return null;
  const lines = rawText.split('\n');
  const headRe = new RegExp('^(\\s*)' + section + '\\s*:\\s*$');
  let inSection = false, secIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const noComment = lines[i].replace(/#.*$/, '');
    if (!inSection) {
      const m = headRe.exec(noComment);
      if (m) { inSection = true; secIndent = m[1].length; }
      continue;
    }
    const trimmed = noComment.trim();
    if (trimmed === '') continue;
    const indent = (noComment.match(/^(\s*)/) || ['', ''])[1].length;
    if (indent <= secIndent) { inSection = false; i--; continue; }   // section ended; re-check line as a header
    const lm = /^-\s+(.*)$/.exec(trimmed);
    if (lm && unquote(lm[1].trim()) === value) return i + 1;
  }
  return null;
}

// Line (1-based) of a child `key:` under `section:`, or null.
function findKeyLine(rawText, section, key) {
  if (typeof rawText !== 'string') return null;
  const lines = rawText.split('\n');
  const headRe = new RegExp('^(\\s*)' + section + '\\s*:\\s*$');
  const keyRe  = new RegExp('^' + String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*:');
  let inSection = false, secIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const noComment = lines[i].replace(/#.*$/, '');
    if (!inSection) {
      const m = headRe.exec(noComment);
      if (m) { inSection = true; secIndent = m[1].length; }
      continue;
    }
    const trimmed = noComment.trim();
    if (trimmed === '') continue;
    const indent = (noComment.match(/^(\s*)/) || ['', ''])[1].length;
    if (indent <= secIndent) { inSection = false; i--; continue; }
    if (keyRe.test(trimmed)) return i + 1;
  }
  return null;
}

// ── reason → rule resolution ─────────────────────────────────────────────────

function inputPathOf(event) {
  const ti = event.tool_inputs || {};
  return (typeof ti.path === 'string' && ti.path) ||
         (typeof ti.file_path === 'string' && ti.file_path) || null;
}

// Which deny_paths entry matched this event? Returns { entry, index, via } | null.
function matchDenyEntry(event, parsed) {
  const deny = Array.isArray(parsed.deny_paths) ? parsed.deny_paths : [];
  if (!deny.length) return null;
  const candidates = [];
  const direct = inputPathOf(event);
  if (direct) candidates.push(direct);
  const ti = event.tool_inputs || {};
  if ((event.tool_name === 'shell_bash' || event.tool_name === 'shell_powershell') && typeof ti.command === 'string') {
    // Mirror the gate's extraction exactly: known read verbs PLUS the
    // verb-agnostic token backstop, so explain can pinpoint the rule for a
    // block caught by the backstop (e.g. `less .env`), not just `cat`/`head`.
    for (const p of extractShellReadPaths(ti.command)) candidates.push(p);
    for (const p of extractCommandPathTokens(ti.command)) candidates.push(p);
  }
  for (const c of candidates) {
    for (let i = 0; i < deny.length; i++) {
      if (typeof deny[i] === 'string' && engine.pathPrefixMatch(c, deny[i])) {
        return { entry: deny[i], index: i, via: c };
      }
    }
  }
  return null;
}

/**
 * @param {object} event  an audit row (BLOCK tool_call or limit_exceeded)
 * @param {object} ctx    { rawText, parsed, policyPath, currentHash, eventHash }
 * @returns {null|{section, rule_id, matched_value, line, index, provenance, alternatives}}
 */
function resolveBlockedRule(event, ctx = {}) {
  if (!event) return null;
  const rawText = ctx.rawText || '';
  const parsed  = ctx.parsed  || {};
  const reason  = event.reason;
  const provenance = (ctx.currentHash && ctx.eventHash && ctx.currentHash !== ctx.eventHash)
    ? 'policy-changed' : 'current';

  // limit_exceeded
  if (event.kind === 'limit_exceeded' || reason === 'limit-exceeded') {
    const ti = event.tool_inputs || {};
    const name = ti.limit || '(unknown limit)';
    return {
      section: 'limits',
      rule_id: `limits.${name}`,
      matched_value: `max ${ti.max} · actual ${ti.actual}`,
      line: findKeyLine(rawText, 'limits', name),
      index: null,
      provenance,
      alternatives: [
        `Raise \`limits.${name}\` in policy.yml (cap ${ti.max}; this round used ${ti.actual}).`,
        `Or split the work so a single round stays within the cap.`,
      ],
    };
  }

  if (reason === 'path-denied') {
    const m = matchDenyEntry(event, parsed);
    return {
      section: 'deny_paths',
      rule_id: m ? `deny_paths[${m.index}]` : 'deny_paths',
      matched_value: m ? m.entry : inputPathOf(event),
      line: m ? findListEntryLine(rawText, 'deny_paths', m.entry) : null,
      index: m ? m.index : null,
      provenance,
      alternatives: [
        m ? `Remove or narrow \`${m.entry}\` in deny_paths to allow this access.`
          : `Remove or narrow the matching deny_paths entry.`,
        `Paths outside the deny list are allowed by default.`,
      ],
    };
  }

  if (reason === 'path-not-allowed') {
    const p = inputPathOf(event);
    const allow = Array.isArray(parsed.allow_paths) ? parsed.allow_paths : [];
    return {
      section: 'allow_paths',
      rule_id: 'allow_paths',
      matched_value: p,
      line: sectionHeaderLine(rawText, 'allow_paths'),
      index: null,
      provenance,
      alternatives: [
        `allow_paths is set, so only listed prefixes are readable.`,
        p ? `Add a prefix covering \`${p}\` to allow_paths.` : `Add a covering prefix to allow_paths.`,
        allow.length ? `Currently allowed: ${allow.join(', ')}.` : `allow_paths is currently empty.`,
      ],
    };
  }

  // secret / deny_patterns (best-effort; conservative match to stay stable)
  if (typeof reason === 'string' && /^secret|deny-pattern|secret-in-result/.test(reason)) {
    return {
      section: 'deny_patterns / secret-scanner',
      rule_id: 'deny_patterns',
      matched_value: null,
      line: sectionHeaderLine(rawText, 'deny_patterns'),
      index: null,
      provenance,
      alternatives: [
        `A secret or deny_patterns match was found in the tool result.`,
        `To allow: fix the leak, or remove/adjust the matching deny_patterns entry.`,
      ],
    };
  }

  return null;
}

module.exports = { resolveBlockedRule, findListEntryLine, findKeyLine, sectionHeaderLine, matchDenyEntry };
