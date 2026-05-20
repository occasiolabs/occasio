'use strict';

/**
 * eyes/state.js — pure reducer over pipeline-events rows.
 *
 * No I/O, no time-of-day. Each call is deterministic given (state, row, now).
 * `now` is injected (ms-since-epoch) so tests + replay can drive animation
 * phase without wall-clock dependence.
 */

const TOOL_DISPLAY = {
  read_file: 'Read', read: 'Read', Read: 'Read',
  grep: 'Grep', Grep: 'Grep',
  glob: 'Glob', Glob: 'Glob', find_files: 'Glob',
  edit_file: 'Edit', Edit: 'Edit', MultiEdit: 'Edit',
  write_file: 'Write', Write: 'Write',
  bash: 'Bash', Bash: 'Bash', shell_bash: 'Bash',
  shell_powershell: 'PowerShell', PowerShell: 'PowerShell',
  TodoWrite: 'TodoWrite', TodoRead: 'TodoRead',
  WebFetch: 'WebFetch', WebSearch: 'WebSearch',
};

function normTool(name) { return TOOL_DISPLAY[name] || name || 'unknown'; }

function pathOf(row) {
  const t = row.tool_inputs || {};
  return t.path || t.file_path || t.pattern || t.command || null;
}

function initialState() {
  return {
    now: null,                 // most recent row, shown big
    recent: [],                // [{tool, path, action, ts, bytes, redactions, savedUsd}], newest first
    totals: {
      local: 0,                // count of LOCAL/PASS rows
      cloud: 0,                // count of rows that went to cloud (PASS w/o executor=local)
      blocks: 0,
      redactions: 0,           // sum of secrets_redacted
      savedUsd: 0,             // sum of tokens_saved * price-per-token estimate
      savedTokens: 0,
      callCount: 0,
    },
    policy: { hash: null, source: null, hotReloads: 0 },
    runId: null,
    lastEventAt: 0,            // ms — when latest row arrived in our state
  };
}

// $3/Mtok input, $15/Mtok output. We don't know the ratio per-row, so use a
// midpoint estimate ($6/Mtok) — same approach as the existing dashboard.
// Honest because tokens_saved is the actual ledger value; only the dollar
// projection is a fixed conversion.
const USD_PER_TOKEN_ESTIMATE = 6 / 1_000_000;

function bytesOfRow(row) {
  const t = row.tool_inputs || {};
  if (typeof t.bytes === 'number') return t.bytes;
  if (typeof row.tokens_saved === 'number') return row.tokens_saved * 4;
  return null;
}

function reduce(state, row, now) {
  if (!row || typeof row !== 'object') return state;
  const next = {
    ...state,
    totals: { ...state.totals },
    policy: { ...state.policy },
    recent: state.recent,
  };

  if (row.kind === 'policy_loaded') {
    const ti = row.tool_inputs || {};
    if (next.policy.hash && ti.policy_hash && ti.policy_hash !== next.policy.hash) {
      next.policy.hotReloads = next.policy.hotReloads + 1;
    }
    next.policy.hash = ti.policy_hash || next.policy.hash;
    next.policy.source = row.policy_source || next.policy.source;
    next.lastEventAt = typeof now === 'number' ? now : next.lastEventAt;
    next.now = {
      kind: 'policy_loaded',
      tool: 'policy',
      path: shortHash(ti.policy_hash),
      action: 'INFO',
      ts: row.ts || null,
      bytes: null,
      redactions: 0,
      savedUsd: 0,
    };
    return next;
  }

  if (row.kind !== 'tool_call') return state;

  const tool = normTool(row.tool_name);
  const action = row.action || 'PASS';
  const redactions = row.secrets_redacted || 0;
  const savedTokens = row.tokens_saved || 0;
  const savedUsd = savedTokens * USD_PER_TOKEN_ESTIMATE;
  const isLocal = row.executor === 'local' || row.result_kind === 'local' || action === 'LOCAL';

  next.totals.callCount += 1;
  if (action === 'BLOCK') next.totals.blocks += 1;
  else if (isLocal) next.totals.local += 1;
  else next.totals.cloud += 1;
  next.totals.redactions += redactions;
  next.totals.savedTokens += savedTokens;
  next.totals.savedUsd += savedUsd;

  if (row.run_id) next.runId = row.run_id;

  const item = {
    kind: 'tool_call',
    tool,
    path: pathOf(row),
    action,
    isLocal,
    ts: row.ts || null,
    bytes: bytesOfRow(row),
    redactions,
    savedUsd,
    exitCode: typeof row.exit_code === 'number' ? row.exit_code : null,
    reason: row.reason || null,
  };

  next.now = item;
  next.recent = [item, ...state.recent].slice(0, 12);
  next.lastEventAt = typeof now === 'number' ? now : next.lastEventAt;
  return next;
}

function shortHash(h) {
  if (!h || typeof h !== 'string') return null;
  return h.slice(0, 8) + '…';
}

module.exports = { initialState, reduce, normTool, pathOf, shortHash, USD_PER_TOKEN_ESTIMATE };
