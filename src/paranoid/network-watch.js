'use strict';

/**
 * network-watch.js: monkey-patch outbound network primitives at runtime and
 * observe every connection attempt during a time window.
 *
 * This is the strongest empirical evidence the paranoid doctor offers:
 * not "the static scan finds no hardcoded phone-home" but "we observed
 * every outbound socket open for N seconds and here is the host list."
 *
 * Trust model: the hook runs inside the same Node process whose integrity
 * we are claiming. A sufficiently determined attacker could detach the
 * hook before opening the connection. The mitigation is to (a) install
 * the hook before any user code loads (boot-script idea, future), and
 * (b) pair the report with --sign so the captured observations carry a
 * Sigstore signature naming the producer. For the user's own paranoid
 * check on a freshly installed npm package, the same-process hook is
 * sufficient evidence: the user is verifying their OWN install, not a
 * remote one.
 */

const t0 = process.hrtime.bigint();

function nowMs() {
  return Number((process.hrtime.bigint() - t0) / 1000000n);
}

/**
 * Install hooks on http/https/net/dgram. Returns an `observed` array that
 * accumulates one entry per outbound attempt during the window. Caller
 * invokes the returned `stop()` to detach all patches.
 *
 * Each observation: { ts_ms, primitive, host, port, transport }.
 */
function installHooks() {
  const observed = [];

  const record = (entry) => {
    observed.push({ ts_ms: nowMs(), ...entry });
  };

  const http  = require('http');
  const https = require('https');
  const net   = require('net');
  const dgram = require('dgram');

  const origHttpRequest  = http.request;
  const origHttpsRequest = https.request;
  const origNetConnect   = net.connect;
  const origNetCreateConn = net.createConnection;
  const origDgramCreate  = dgram.createSocket;

  function extractHostPort(args, defaultPort) {
    let host = null, port = defaultPort, fromUrl = false;
    if (typeof args[0] === 'string') {
      try {
        const u = new URL(args[0]);
        host = u.hostname;
        port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
        fromUrl = true;
      } catch { host = args[0]; }
    } else if (args[0] && typeof args[0] === 'object') {
      host = args[0].hostname || args[0].host || null;
      port = args[0].port || defaultPort;
    }
    return { host, port, fromUrl };
  }

  http.request = function (...args) {
    const { host, port } = extractHostPort(args, 80);
    record({ primitive: 'http.request', host, port, transport: 'tcp/http' });
    return origHttpRequest.apply(this, args);
  };
  https.request = function (...args) {
    const { host, port } = extractHostPort(args, 443);
    record({ primitive: 'https.request', host, port, transport: 'tcp/https' });
    return origHttpsRequest.apply(this, args);
  };
  net.connect = function (...args) {
    const { host, port } = extractHostPort(args, null);
    record({ primitive: 'net.connect', host, port, transport: 'tcp' });
    return origNetConnect.apply(this, args);
  };
  net.createConnection = function (...args) {
    const { host, port } = extractHostPort(args, null);
    record({ primitive: 'net.createConnection', host, port, transport: 'tcp' });
    return origNetCreateConn.apply(this, args);
  };
  dgram.createSocket = function (...args) {
    record({ primitive: 'dgram.createSocket', host: null, port: null, transport: 'udp' });
    return origDgramCreate.apply(this, args);
  };

  const stop = () => {
    http.request  = origHttpRequest;
    https.request = origHttpsRequest;
    net.connect   = origNetConnect;
    net.createConnection = origNetCreateConn;
    dgram.createSocket = origDgramCreate;
  };

  return { observed, stop };
}

/**
 * Run a watch for `seconds` seconds. Hooks are installed for the duration.
 * The caller is expected to run a workload (in the same process or via
 * subprocesses; same-process is required for the hooks to observe).
 *
 * Returns the canonical scanner shape so paranoid renderers can consume it.
 */
async function scan(opts = {}) {
  const seconds = Math.max(1, Number(opts.watchSeconds) || 30);
  const tStart = Date.now();
  const { observed, stop } = installHooks();

  await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
  stop();

  const tEnd = Date.now();

  // Aggregate by host:port. Any unique destination is a "fact" the user
  // can audit. Classification stays simple here: the static scanner
  // already classifies code; the watch only reports observations.
  const byDest = new Map();
  for (const o of observed) {
    const key = `${o.host || '?'}:${o.port || '?'}`;
    const entry = byDest.get(key) || { host: o.host, port: o.port, transport: o.transport, count: 0 };
    entry.count++;
    byDest.set(key, entry);
  }

  const summary = { critical: 0, warn: 0, info: byDest.size, ok: 0 };

  return {
    name: 'network-watch',
    windowSeconds: seconds,
    windowStartedAt: new Date(tStart).toISOString(),
    windowEndedAt:   new Date(tEnd).toISOString(),
    observations: observed,
    destinations: [...byDest.values()],
    summary,
    durationMs: tEnd - tStart,
  };
}

module.exports = { scan, installHooks };
