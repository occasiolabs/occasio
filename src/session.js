'use strict';

/**
 * session.js — Path constant for the run pointer file.
 *
 * After Phase 5 of the truth-source unification, session.json is a *pointer*
 * to the active run (run_id, start, cwd, mode, budget, model, log_file). All
 * per-request counters live on the hash-chained audit log and are read via
 * src/models/events.js. The previous incrementSessionMcpCount helper is gone:
 * tools_mcp_count is now derived from kind:"tool_call" rows in the chain.
 */

const path = require('path');
const os   = require('os');

const SESSION_FILE = path.join(os.homedir(), '.occasio', 'session.json');

module.exports = { SESSION_FILE };
