#!/usr/bin/env python3
"""
Independent walker for Occasio's pipeline-events.jsonl audit log.

Re-walks the SHA-256 hash chain without using any Occasio code, so the
audit-trail integrity claim does not depend on trusting Occasio's own
verifier. See docs/AUDIT.md for the row schema and the canonical-
serialization rules this script implements.

The canonical form is, per the auditor contract, exactly
``SHA-256(JSON.stringify(rowWithoutHash))`` — i.e. V8's JSON.stringify with
default options. So this walker reimplements V8's serialization faithfully,
including ECMAScript's Number-to-string rules (decimal vs. exponential
notation), which differ from Python's ``json.dumps`` for small floats
(e.g. V8 emits ``0.00003`` where ``json.dumps`` emits ``3e-05``). Using
``json.dumps`` here would FALSELY reject any chain containing such a value.

Usage:
    python3 audit_walker.py ~/.occasio/pipeline-events.jsonl

Exit code 0 on success, 1 on first inconsistency or I/O error.
"""

import hashlib
import json
import sys
from decimal import Decimal

GENESIS = "0" * 64


def _v8_number(x: float) -> str:
    """ECMAScript Number::toString (ECMA-262 §6.1.6.1.20) for a finite float.

    Both V8 and Python pick the *same* shortest round-tripping digits; they
    only disagree on where to place the decimal point / when to go exponential.
    So we take Python's shortest digits (via Decimal(repr(x))) and re-notate
    them with V8's thresholds.
    """
    if x != x or x in (float("inf"), float("-inf")):
        return "null"            # JSON.stringify renders these as null
    if x == 0:
        return "0"               # also normalises -0.0

    sign, digits, exp = Decimal(repr(x)).as_tuple()
    s = "".join(str(d) for d in digits)
    # Minimal significant digits (drop trailing zeros, tracking the exponent).
    while len(s) > 1 and s.endswith("0"):
        s = s[:-1]
        exp += 1
    k = len(s)          # number of significant digits
    n = exp + k         # position of the decimal point: value = s × 10**(n-k)
    neg = "-" if sign else ""

    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        mant = s[0] + ("." + s[1:] if k > 1 else "")
        e = n - 1
        out = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return neg + out


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t",
            "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _v8_quote(s: str) -> str:
    """V8 JSON.stringify string escaping: escape ", \\, the named control
    chars, other C0 controls as \\u00xx; non-ASCII emitted literally."""
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _v8_json(value) -> str:
    """Serialise a json.loads'd value exactly as V8 JSON.stringify would."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _v8_quote(value)
    if isinstance(value, bool):       # unreachable (handled above) but explicit
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _v8_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_v8_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_v8_quote(str(k)) + ":" + _v8_json(v)
                              for k, v in value.items()) + "}"
    raise TypeError("non-JSON value: %r" % (value,))


def canonical_serialize(row_without_hash: dict) -> bytes:
    return _v8_json(row_without_hash).encode("utf-8")


def walk(path: str) -> int:
    prev_hash = GENESIS
    chained = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line:
                continue
            row = json.loads(line)
            stored_hash = row.pop("hash", None)
            # Legacy rows (pre-hash-chain) have no hash field — skip silently.
            if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                continue
            if row.get("prev_hash") != prev_hash:
                print(f"MISMATCH at line {lineno}: prev_hash chain broken", file=sys.stderr)
                return 1
            recomputed = hashlib.sha256(canonical_serialize(row)).hexdigest()
            if recomputed != stored_hash:
                print(f"MISMATCH at line {lineno}: stored hash {stored_hash} != recomputed {recomputed}", file=sys.stderr)
                return 1
            prev_hash = stored_hash
            chained += 1
    print(f"OK: {chained} rows verified")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: audit_walker.py <pipeline-events.jsonl>", file=sys.stderr)
        sys.exit(2)
    sys.exit(walk(sys.argv[1]))
