'use strict';

/**
 * occasio recap — markdown summary of a past session, sized to paste into
 * a new Claude prompt so the next agent picks up where the last one left off.
 *
 * Reads from ~/.occasio/pipeline-events.jsonl (read-only). Groups by run_id,
 * picks the most recent session by default. No network, no signing, no policy
 * decisions made — pure read view.
 *
 * Usage:
 *   occasio recap                       # last session, markdown
 *   occasio recap --last 3              # last 3 sessions
 *   occasio recap --run <id>            # specific session
 *   occasio recap --format text|json    # alt outputs
 *
 * The output is shaped to be useful as agent context — short, factual,
 * decisions-first. Not an audit view (use `occasio replay --detail` for that).
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// Recap reads exclusively from the hash-chained audit log. Conversation text
// from Claude Code's own session files (~/.claude/projects/*) is intentionally
// not pulled in: it has no run_id mapping and was previously leaking a current
// user prompt into recaps of older sessions.
const CHAIN_FILE = path.join(os.homedir(), '.occasio', 'pipeline-events.jsonl');

const col = {
  r:  s => `\x1b[31m${s}\x1b[0m`,
  g:  s => `\x1b[32m${s}\x1b[0m`,
  y:  s => `\x1b[33m${s}\x1b[0m`,
  c:  s => `\x1b[36m${s}\x1b[0m`,
  d:  s => `\x1b[2m${s}\x1b[0m`,
  b:  s => `\x1b[1m${s}\x1b[0m`,
};

// Normalise tool names: chain has both PascalCase (Claude-Code-style) and
// snake_case (shell-tool aliases via interceptor). Render as the canonical
// display name so the recap doesn't double-count Read/read_file.
const TOOL_DISPLAY = {
  read_file:    'Read',
  read:         'Read',
  Read:         'Read',
  grep:         'Grep',
  Grep:         'Grep',
  glob:         'Glob',
  Glob:         'Glob',
  find_files:   'Glob',
  edit_file:    'Edit',
  Edit:         'Edit',
  MultiEdit:    'Edit',
  write_file:   'Write',
  Write:        'Write',
  bash:         'Bash',
  Bash:         'Bash',
  shell_bash:   'Bash',
  shell_powershell: 'PowerShell',
  TodoWrite:    'TodoWrite',
  TodoRead:     'TodoRead',
  WebFetch:     'WebFetch',
  WebSearch:    'WebSearch',
};
const TOOLS_THAT_READ     = new Set(['Read', 'Grep', 'Glob']);
const TOOLS_THAT_MODIFY   = new Set(['Edit', 'Write']);

function normTool(name) { return TOOL_DISPLAY[name] || name || 'unknown'; }

function readChain(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch { /* skip malformed */ }
  }
  return out;
}

function groupByRun(rows) {
  const map = new Map();
  for (const r of rows) {
    const id = r.run_id || 'legacy';
    if (!map.has(id)) map.set(id, []);
    map.get(id).push(r);
  }
  for (const arr of map.values()) {
    arr.sort((a, b) => (a.ts || '') < (b.ts || '') ? -1 : 1);
  }
  return map;
}

function pickRecentRuns(rowsByRun, n) {
  const entries = [...rowsByRun.entries()].map(([id, rows]) => ({
    id,
    rows,
    end: rows.length ? rows[rows.length - 1].ts || '' : '',
  }));
  entries.sort((a, b) => a.end < b.end ? 1 : -1);
  return entries.slice(0, n);
}

function pathOf(row) {
  const t = row.tool_inputs || {};
  return t.path || t.file_path || t.pattern || t.command || null;
}

function aggregate(rows) {
  const tools = {};
  const readPaths = new Set();
  const modifyPaths = new Set();
  const blocked = [];
  const transformed = [];
  const toolCalls = [];

  for (const r of rows) {
    if (r.kind !== 'tool_call') continue;
    const tool = normTool(r.tool_name);
    tools[tool] = (tools[tool] || 0) + 1;
    toolCalls.push(r);

    const p = pathOf(r);
    if (p && r.action !== 'BLOCK') {
      if (TOOLS_THAT_READ.has(tool))   readPaths.add(p);
      if (TOOLS_THAT_MODIFY.has(tool)) modifyPaths.add(p);
    }
    if (r.action === 'BLOCK') {
      blocked.push({ tool, target: p, reason: r.reason || 'policy' });
    }
    if (r.action === 'TRANSFORM') {
      transformed.push({ tool, target: p, redacted: r.secrets_redacted || 0 });
    }
  }

  return {
    tools, readPaths: [...readPaths], modifyPaths: [...modifyPaths],
    blocked, transformed, toolCalls,
    start: rows[0]?.ts || null,
    end:   rows[rows.length - 1]?.ts || null,
  };
}

function shortPath(p, root) {
  if (!p) return '(no path)';
  if (root && p.startsWith(root)) {
    const rel = p.slice(root.length).replace(/^[\\/]+/, '');
    return rel || p;
  }
  return p;
}

function durationStr(start, end) {
  if (!start || !end) return 'unknown';
  const ms = new Date(end) - new Date(start);
  if (!Number.isFinite(ms) || ms < 0) return 'unknown';
  const min = Math.round(ms / 60000);
  if (min < 1) return '<1 min';
  if (min < 60) return min + ' min';
  return Math.floor(min/60) + 'h ' + (min%60) + 'm';
}

function lastActionsLines(toolCalls, root, n = 5) {
  const last = toolCalls.slice(-n);
  return last.map((r, i) => {
    const tool = normTool(r.tool_name);
    const p = shortPath(pathOf(r), root);
    const action = r.action || '';
    const tag = action === 'BLOCK' ? '✗' : action === 'TRANSFORM' ? '⚙' : '·';
    return `${i+1}. ${tag} ${tool}  ${p}${action && action !== 'PASS' && action !== 'LOCAL' ? '  → ' + action : ''}`;
  });
}

function renderMarkdown(run, root) {
  const a = aggregate(run.rows);
  const dur = durationStr(a.start, a.end);
  const date = a.start ? new Date(a.start).toISOString().replace('T', ' ').slice(0, 16) : 'unknown';

  const lines = [];
  lines.push(`# Previous session — ${date}, ${dur}`);
  lines.push('');

  if (a.readPaths.length || a.modifyPaths.length) {
    lines.push('## Files touched');
    if (a.modifyPaths.length) {
      const shown = a.modifyPaths.slice(0, 10).map(p => shortPath(p, root));
      const more = a.modifyPaths.length > 10 ? ` (+${a.modifyPaths.length - 10} more)` : '';
      lines.push(`- modified: ${shown.join(', ')}${more}`);
    }
    if (a.readPaths.length) {
      const shown = a.readPaths.slice(0, 10).map(p => shortPath(p, root));
      const more = a.readPaths.length > 10 ? ` (+${a.readPaths.length - 10} more)` : '';
      lines.push(`- read: ${shown.join(', ')}${more}`);
    }
    lines.push('');
  }

  const toolEntries = Object.entries(a.tools).sort((x, y) => y[1] - x[1]);
  if (toolEntries.length) {
    lines.push('## Tools used');
    lines.push('- ' + toolEntries.map(([k, v]) => `${v} ${k}`).join(' · '));
    lines.push('');
  }

  if (a.blocked.length || a.transformed.length) {
    lines.push('## Decisions');
    if (a.blocked.length) {
      const byTarget = {};
      for (const b of a.blocked) {
        const key = `${b.tool}  ${shortPath(b.target, root)}`;
        byTarget[key] = (byTarget[key] || 0) + 1;
      }
      for (const [k, count] of Object.entries(byTarget)) {
        lines.push(`- ${count}× BLOCK  ${k}`);
      }
    }
    if (a.transformed.length) {
      const total = a.transformed.reduce((s, t) => s + (t.redacted || 0), 0);
      lines.push(`- ${a.transformed.length}× TRANSFORM (${total} secret${total === 1 ? '' : 's'} redacted)`);
    }
    lines.push('');
  }

  if (a.toolCalls.length) {
    lines.push('## Last actions');
    for (const line of lastActionsLines(a.toolCalls, root)) lines.push(line);
    lines.push('');
  }

  // Open-thread heuristic: surface last Bash/Edit/Write so the next agent
  // knows the most recent state-changing action.
  const lastBash  = [...a.toolCalls].reverse().find(r => normTool(r.tool_name) === 'Bash' || normTool(r.tool_name) === 'PowerShell');
  const lastWrite = [...a.toolCalls].reverse().find(r => TOOLS_THAT_MODIFY.has(normTool(r.tool_name)));
  if (lastBash || lastWrite) {
    lines.push('## Open thread (best-guess from last actions)');
    if (lastWrite) {
      lines.push(`- last write: ${normTool(lastWrite.tool_name)}  ${shortPath(pathOf(lastWrite), root)}`);
    }
    if (lastBash) {
      const cmd = (lastBash.tool_inputs && (lastBash.tool_inputs.command || lastBash.tool_inputs.cmd)) || '(no cmd)';
      const exit = (typeof lastBash.exit_code === 'number') ? ` (exit ${lastBash.exit_code})` : '';
      lines.push(`- last shell: ${cmd.slice(0, 80)}${cmd.length > 80 ? '…' : ''}${exit}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function renderText(run, root) {
  // Plain text variant, no markdown noise — convenient for CLI piping.
  return renderMarkdown(run, root).replace(/^#+\s*/gm, '').replace(/\n{3,}/g, '\n\n');
}

function renderJson(run, root) {
  const a = aggregate(run.rows);
  return JSON.stringify({
    run_id: run.id,
    started_at: a.start,
    ended_at:   a.end,
    duration:   durationStr(a.start, a.end),
    files: {
      read:     a.readPaths.map(p => shortPath(p, root)),
      modified: a.modifyPaths.map(p => shortPath(p, root)),
    },
    tools: a.tools,
    decisions: { blocked: a.blocked, transformed: a.transformed },
    last_actions: a.toolCalls.slice(-5).map(r => ({
      tool: normTool(r.tool_name), action: r.action,
      path: shortPath(pathOf(r), root), ts: r.ts,
    })),
  }, null, 2);
}

function parseArgs(argv) {
  const out = { last: 1, run: null, format: 'md' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--last') out.last = Math.max(1, parseInt(argv[++i], 10) || 1);
    else if (a === '--run') out.run = argv[++i];
    else if (a === '--format') out.format = argv[++i];
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function printHelp() {
  process.stdout.write(`
${col.b('occasio recap')}  ${col.d('— session summary for agent context')}

  Markdown summary of a past Occasio session: files touched, tools used,
  decisions made, last actions. Designed to paste into a new Claude prompt
  so the next session picks up where the last one left off.

${col.b('Usage')}
  occasio recap                       last session (markdown)
  occasio recap --last 3              last 3 sessions
  occasio recap --run <id>            specific session
  occasio recap --format text|json    alternative output

${col.b('Note')}
  Conversation text is not included — recap shows only what the audit
  chain records (tools, decisions, costs). For raw transcripts, see
  ${col.d('~/.claude/projects/')}.

${col.b('Tip')}
  occasio recap | clip               ${col.d('(Windows)')}
  occasio recap | pbcopy             ${col.d('(macOS)')}
  occasio recap | xclip -sel clip    ${col.d('(Linux)')}

`);
}

function run(argv) {
  const opts = parseArgs(argv || []);
  if (opts.help) { printHelp(); return 0; }

  const rows = readChain(CHAIN_FILE);
  if (!rows.length) {
    process.stderr.write(col.d(`No chain at ${CHAIN_FILE} — run \`occasio claude\` first.\n`));
    return 1;
  }

  const byRun = groupByRun(rows);
  let runs;
  if (opts.run) {
    if (!byRun.has(opts.run)) {
      process.stderr.write(col.r(`No session with run_id ${opts.run}\n`));
      return 1;
    }
    runs = [{ id: opts.run, rows: byRun.get(opts.run) }];
  } else {
    runs = pickRecentRuns(byRun, opts.last);
  }

  const root = process.cwd();
  const parts = [];
  for (const r of runs) {
    if (opts.format === 'json') {
      parts.push(renderJson(r, root));
    } else if (opts.format === 'text') {
      parts.push(renderText(r, root));
    } else {
      parts.push(renderMarkdown(r, root));
    }
  }

  process.stdout.write(parts.join('\n\n---\n\n') + '\n');
  return 0;
}

module.exports = { run, aggregate, renderMarkdown, normTool };
