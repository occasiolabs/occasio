#!/usr/bin/env python3
"""
LocalFirst LAO context scorer.
Usage: python lao_prep.py <task> <repo_path>
Output: JSON array [{path, score, est_tokens}] sorted by score desc.
No external dependencies — stdlib only.
"""
from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

IGNORE_DIRS: set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage", ".cache",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
}
IGNORE_EXT: set[str] = {
    ".lock", ".log", ".map", ".min.js", ".min.css",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".bin", ".exe", ".dll",
    ".pyc", ".pyo", ".so", ".dylib",
}
MAX_FILE_BYTES = 100_000
MAX_FILES = 300


def tokenize(text: str) -> list[str]:
    # Identifiers >= 3 chars only: reduces noise from short tokens
    return re.findall(r"[a-zA-Z_]\w{2,}", text.lower())


def scan_repo(repo_path: str) -> list[dict]:
    root = Path(repo_path).resolve()
    files: list[dict] = []
    try:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            if p.suffix.lower() in IGNORE_EXT:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(p.relative_to(root)).replace("\\", "/")
            path_tokens = set(tokenize(rel))
            content_tokens = set(tokenize(content))
            files.append({
                "path": rel,
                "token_set": content_tokens | path_tokens,
                "path_tokens": path_tokens,
                "est_tokens": max(1, size // 4),
            })
            if len(files) >= MAX_FILES:
                break
    except Exception:
        pass
    return files


def score_files(task: str, files: list[dict]) -> list[dict]:
    task_tokens = tokenize(task)
    if not task_tokens or not files:
        return []

    N = len(files)
    idf: dict[str, float] = {}
    for tok in set(task_tokens):
        df = sum(1 for f in files if tok in f["token_set"])
        idf[tok] = math.log((N + 1) / (df + 1)) + 1.0

    results: list[dict] = []
    for f in files:
        ts = f["token_set"]
        pt = f["path_tokens"]
        score = 0.0
        for tok in task_tokens:
            w = idf.get(tok, 0.0)
            if tok in pt:
                score += w * 3.0   # path match: strong signal
            elif tok in ts:
                score += w * 1.0   # content match
        score /= math.sqrt(max(len(ts), 1))
        results.append({
            "path": f["path"],
            "score": round(score, 5),
            "est_tokens": f["est_tokens"],
        })

    results.sort(key=lambda x: -x["score"])
    return results


def main() -> None:
    if len(sys.argv) < 3:
        print("[]")
        return
    task = sys.argv[1]
    repo_path = sys.argv[2]
    files = scan_repo(repo_path)
    results = score_files(task, files)
    print(json.dumps(results))


if __name__ == "__main__":
    main()
