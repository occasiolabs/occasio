"""
canonicalize.py — RFC 8785 subset for byte-stable JSON serialisation.

Companion to docs/audit_walker.py and docs/attest_verify.py: lets an
auditor in a Python-only environment re-verify a Occasio
attestation against the producer's canonical form without trusting
the producer's code.

Must stay byte-identical to src/attest/canonicalize.js and the
inline copy in integrations/attest-view/viewer.js. The three
implementations exist so the schema is provably language-independent;
diverging them defeats the point.

Cross-language invariant (load-bearing):
    JavaScript has a single ``number`` type. ``JSON.parse('1.0')``
    yields the integer 1; ``JSON.stringify(1)`` emits ``'1'``.
    Python distinguishes int from float: ``json.loads('1.0')`` yields
    ``float(1.0)``; ``json.dumps(1.0)`` emits ``'1.0'``. If we silently
    accepted floats, the JS verifier and the Python verifier would
    canonicalize the same JSON file to different bytes — silent
    byte-equivalence breakage. This module:

      - rejects non-integer floats (e.g. 1.5) with a clear error
      - coerces integer-valued floats (e.g. 1.0) to the integer
        representation so that a Python parse of ``"1.0"`` and a JS
        parse of ``"1.0"`` canonicalize identically

    If a future schema requires decimal precision, encode it as a
    string. The canonicalize boundary stays integer-only.

Deviations from strict RFC 8785 (documented, intentional):
    - Float rejection above (instead of RFC 8785's prescribed form).
      Load-bearing for cross-language byte-equivalence.
    - Lone-surrogate handling matches Python json.dumps (escapes
      via \\uXXXX). JCS specifies the same.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(value: Any) -> str:
    """Return the canonical-JSON string for ``value``.

    Rules:
      - object keys sorted lexicographically by UTF-16 code unit
        (Python's default ``sorted`` on strs is UTF-16-equivalent for
        the BMP, which covers every key in the v1 schema)
      - ``None`` ``True`` ``False`` map to ``null``/``true``/``false``
      - object members whose value is ``None`` are kept (they encode
        explicit nullable fields like ``policy.version``); members
        absent from the dict are not invented
      - arrays preserve order
      - rejects ``float('nan')``/``inf``, callables, types,
        non-string keys

    Raises ``ValueError`` on rejected inputs.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("canonicalize: non-finite number")
        # Cross-language invariant: a JSON literal like "1.0" parses to
        # int(1) in JavaScript but float(1.0) in Python. Coerce the
        # integer-valued case so both implementations canonicalize to
        # the same bytes. Reject genuine non-integer floats — see the
        # module docstring for the schema-design rationale.
        if not value.is_integer():
            raise ValueError(
                f"canonicalize: non-integer number {value} — "
                "cross-language byte-equivalence requires schema fields "
                "be integers or strings. Encode decimal values as strings."
            )
        return str(int(value))
    if isinstance(value, str):
        # json.dumps emits a fully-escaped RFC 8259 string. Matches
        # what V8's JSON.stringify does for ASCII + most Unicode.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise ValueError(
                    f"canonicalize: non-string key {k!r}"
                )
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(v)
            for k, v in items
        ) + "}"
    raise ValueError(f"canonicalize: unsupported type {type(value).__name__}")
