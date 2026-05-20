'use strict';

/**
 * eyes/demo-content.js — synthetic outbound payloads for `occasio eyes --demo`.
 *
 * Each entry is a fully-formed extracted payload (same shape as capture
 * writes to disk). No real source code; everything is hand-crafted so the
 * demo is deterministic and ships zero real-user content.
 */

const T0 = '2026-05-20T14:22:00.000Z';
function plus(sec) {
  const d = new Date(Date.parse(T0) + sec * 1000);
  return d.toISOString();
}

const PAYLOADS = [
  {
    schema: 1, seq: 1, ts: plus(0), runId: 'demo-eyes-content',
    model: 'claude-opus-4-7',
    byteCount: { before: 2840, after: 2840 },
    system: {
      text: 'You are Claude Code, Anthropic\'s official CLI for Claude.\nYou are an interactive agent that helps users with software engineering tasks.',
      bytes: 145, truncated: false,
    },
    messages: [
      { role: 'user', blocks: [
        { kind: 'text', text: 'read the auth middleware and tell me what auth method it uses', bytes: 60, truncated: false },
      ]},
    ],
    laoDropped: [], redactionCount: 0, blockedCount: 0,
  },
  {
    schema: 1, seq: 2, ts: plus(2), runId: 'demo-eyes-content',
    model: 'claude-opus-4-7',
    byteCount: { before: 3680, after: 3520 },
    response: {
      role: 'assistant',
      model: 'claude-opus-4-7',
      stopReason: 'end_turn',
      usage: { input_tokens: 940, output_tokens: 88, cache_read_input_tokens: 5800 },
      blocks: [
        { kind: 'text', bytes: 220, truncated: false, text:
            'It uses JWT (signed with HS256) over bcrypt-hashed passwords. The JWT secret is\n' +
            'loaded from an env var — Occasio redacted the literal before this reached me,\n' +
            'so I see "[REDACTED jwt_secret]" in place of the value but the structure is clear.' },
      ],
    },
    system: { text: 'You are Claude Code…', bytes: 145, truncated: false },
    messages: [
      { role: 'user', blocks: [{ kind: 'text', text: 'read the auth middleware and tell me what auth method it uses', bytes: 60 }] },
      { role: 'assistant', blocks: [
        { kind: 'text', text: 'I\'ll start by looking at the auth middleware file.', bytes: 50 },
        { kind: 'tool_use', toolName: 'Read', toolUseId: 'tu_001', input: { path: 'src/auth.js' } },
      ]},
      { role: 'user', blocks: [
        { kind: 'tool_result', toolUseId: 'tu_001', bytes: 1820, truncated: false, text:
            "const jwt = require('jsonwebtoken');\n" +
            "const bcrypt = require('bcrypt');\n" +
            "\n" +
            "async function authenticate(req, res) {\n" +
            "  const { email, password } = req.body;\n" +
            "  const user = await db.users.findByEmail(email);\n" +
            "  if (!user) return res.status(401).json({ error: 'no such user' });\n" +
            "\n" +
            "  const ok = await bcrypt.compare(password, user.pwHash);\n" +
            "  if (!ok) return res.status(401).json({ error: 'wrong password' });\n" +
            "\n" +
            "  // 🚨 secret was redacted before this reached the cloud\n" +
            "  const SECRET = '[REDACTED jwt_secret]';\n" +
            "  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, {\n" +
            "    expiresIn: '24h',\n" +
            "  });\n" +
            "\n" +
            "  return res.json({ token, user: publicProfile(user) });\n" +
            "}\n" +
            "\n" +
            "module.exports = { authenticate };\n",
        },
      ]},
    ],
    laoDropped: [], redactionCount: 1, blockedCount: 0,
  },
  {
    schema: 1, seq: 3, ts: plus(5), runId: 'demo-eyes-content',
    model: 'claude-opus-4-7',
    byteCount: { before: 4200, after: 4200 },
    system: { text: 'You are Claude Code…', bytes: 145, truncated: false },
    messages: [
      { role: 'assistant', blocks: [
        { kind: 'text', text: 'It uses JWT with bcrypt. Let me also check the config file.', bytes: 60 },
        { kind: 'tool_use', toolName: 'Read', toolUseId: 'tu_002', input: { path: '/etc/passwd' } },
      ]},
      { role: 'user', blocks: [
        { kind: 'tool_result', toolUseId: 'tu_002', bytes: 0, isError: true, text:
            '[BLOCKED by policy: deny_paths matched /etc/passwd — content never read]\n',
        },
      ]},
    ],
    laoDropped: [], redactionCount: 0, blockedCount: 1,
  },
  {
    schema: 1, seq: 4, ts: plus(9), runId: 'demo-eyes-content',
    model: 'claude-opus-4-7',
    byteCount: { before: 5980, after: 4760 },
    system: { text: 'You are Claude Code…', bytes: 145, truncated: false },
    messages: [
      { role: 'assistant', blocks: [
        { kind: 'text', text: 'I\'ll scan the codebase for any other auth touch points.', bytes: 58 },
        { kind: 'tool_use', toolName: 'Grep', toolUseId: 'tu_003', input: { pattern: 'jwt.sign|bcrypt.compare' } },
      ]},
      { role: 'user', blocks: [
        { kind: 'tool_result', toolUseId: 'tu_003', bytes: 2400, truncated: false, text:
            "src/auth.js:14: const token = jwt.sign({ id: user.id, role: user.role }, SECRET, {\n" +
            "src/auth.js:11: const ok = await bcrypt.compare(password, user.pwHash);\n" +
            "src/admin/login.js:7: const token = jwt.sign({ id: admin.id, scope: 'admin' }, [REDACTED jwt_secret], { expiresIn: '1h' });\n" +
            "src/admin/login.js:5: const ok = await bcrypt.compare(req.body.password, admin.pwHash);\n" +
            "src/api/refresh.js:18: const next = jwt.sign({ id: payload.id }, [REDACTED jwt_secret], { expiresIn: '5m' });\n",
        },
      ]},
    ],
    laoDropped: ['src/utils/legacy-md5.js', 'docs/old-auth-design.md'], redactionCount: 2, blockedCount: 0,
  },
];

module.exports = { PAYLOADS };
