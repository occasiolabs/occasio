#!/usr/bin/env python3
"""
Independent walker for LocalFirst's pipeline-events.jsonl audit log.

Re-walks the SHA-256 hash chain without using any LocalFirst code, so the
audit-trail integrity claim does not depend on trusting LocalFirst's own
verifier. See docs/AUDIT.md for the row schema and the canonical-
serialization rules this script implements.

Usage:
    python3 audit_walker.py ~/.localfirst/pipeline-events.jsonl

Exit code 0 on success, 1 on first inconsistency or I/O error.
"""

import hashlib
import json
import sys

GENESIS = "0" * 64


def canonical_serialize(row_without_hash: dict) -> bytes:
    # Mirrors V8's JSON.stringify with default options:
    #   - no whitespace between tokens
    #   - non-ASCII characters emitted literally (ensure_ascii=False)
    #   - keys in insertion order (Python 3.7+ dict guarantees this)
    return json.dumps(
        row_without_hash,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


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
