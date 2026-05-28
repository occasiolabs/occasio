'use strict';

/**
 * Network outbound primitives that the source scanner looks for.
 *
 * The goal is to locate every callsite in src/ and bin/ that could initiate
 * an outbound network connection. Inbound server primitives (http.createServer,
 * net.createServer, etc.) are intentionally excluded; this scan is about
 * data leaving the machine.
 *
 * Each entry has:
 *   - re:    a RegExp matching the callsite pattern
 *   - label: a short human name shown in the report
 *   - kind:  "http" | "tcp" | "udp" | "dns" | "client-lib"
 *
 * The regexes are deliberately conservative: they match callable forms only
 * (a `(` follows the name), not bare references. This keeps the noise floor
 * low when the report cites file:line locations.
 */

const NETWORK_PRIMITIVES = [
  // global fetch (Node 18+)
  { re: /\bfetch\s*\(/g,                       label: 'fetch',                  kind: 'http'      },

  // classic http / https modules
  { re: /\bhttp\.request\s*\(/g,               label: 'http.request',           kind: 'http'      },
  { re: /\bhttps\.request\s*\(/g,              label: 'https.request',          kind: 'http'      },
  { re: /\bhttp\.get\s*\(/g,                   label: 'http.get',               kind: 'http'      },
  { re: /\bhttps\.get\s*\(/g,                  label: 'https.get',              kind: 'http'      },

  // raw TCP
  { re: /\bnet\.connect\s*\(/g,                label: 'net.connect',            kind: 'tcp'       },
  { re: /\bnet\.createConnection\s*\(/g,       label: 'net.createConnection',   kind: 'tcp'       },

  // UDP
  { re: /\bdgram\.createSocket\s*\(/g,         label: 'dgram.createSocket',     kind: 'udp'       },

  // DNS
  { re: /\bdns\.lookup\s*\(/g,                 label: 'dns.lookup',             kind: 'dns'       },
  { re: /\bdns\.resolve\w*\s*\(/g,             label: 'dns.resolve',            kind: 'dns'       },

  // Popular HTTP client libraries via require()
  { re: /require\(\s*['"]axios['"]\s*\)/g,     label: 'axios (require)',        kind: 'client-lib' },
  { re: /require\(\s*['"]node-fetch['"]\s*\)/g, label: 'node-fetch (require)',  kind: 'client-lib' },
  { re: /require\(\s*['"]got['"]\s*\)/g,       label: 'got (require)',          kind: 'client-lib' },
  { re: /require\(\s*['"]undici['"]\s*\)/g,    label: 'undici (require)',       kind: 'client-lib' },
  { re: /require\(\s*['"]ky['"]\s*\)/g,        label: 'ky (require)',           kind: 'client-lib' },
  { re: /require\(\s*['"]superagent['"]\s*\)/g, label: 'superagent (require)',  kind: 'client-lib' },
  { re: /require\(\s*['"]request['"]\s*\)/g,   label: 'request (require)',      kind: 'client-lib' },

  // Popular HTTP client invocations (variable or namespace forms)
  { re: /\baxios\s*\(/g,                       label: 'axios()',                kind: 'client-lib' },
  { re: /\baxios\.\w+\s*\(/g,                  label: 'axios.method()',         kind: 'client-lib' },
  { re: /\bgot\s*\(/g,                         label: 'got()',                  kind: 'client-lib' },
  { re: /\bgot\.\w+\s*\(/g,                    label: 'got.method()',           kind: 'client-lib' },
  { re: /\bky\s*\(/g,                          label: 'ky()',                   kind: 'client-lib' },
  { re: /\bky\.\w+\s*\(/g,                     label: 'ky.method()',            kind: 'client-lib' },
];

module.exports = { NETWORK_PRIMITIVES };
