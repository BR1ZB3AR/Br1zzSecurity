"""Scan history.

Each completed scan appends one JSON object to a line-delimited log, which keeps
appends atomic and lets the file be tailed or trimmed without a database.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .config import HISTORY_FILE, ensure_dirs
from .engine.verdict import ScanSummary

MAX_ENTRIES = 200


def record(summary: ScanSummary, kind: str = "manual") -> None:
    """Append one scan result to the history log."""
    ensure_dirs()
    entry = summary.to_dict()
    entry["kind"] = kind
    # Store only a bounded sample of threats so a badly-infected scan cannot
    # write a multi-megabyte history line.
    entry["threats"] = entry["threats"][:50]
    try:
        with open(HISTORY_FILE, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        os.chmod(HISTORY_FILE, 0o600)
    except OSError:
        return
    _trim()


def _trim(limit: int = MAX_ENTRIES) -> None:
    try:
        lines = HISTORY_FILE.read_text().splitlines()
    except OSError:
        return
    if len(lines) <= limit:
        return
    try:
        HISTORY_FILE.write_text("\n".join(lines[-limit:]) + "\n")
    except OSError:
        pass


def history(limit: int = 20) -> list[dict]:
    """Return the most recent scans, newest first."""
    if not Path(HISTORY_FILE).is_file():
        return []
    try:
        lines = HISTORY_FILE.read_text().splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out


def last_scan() -> dict | None:
    entries = history(limit=1)
    return entries[0] if entries else None


def clear() -> None:
    try:
        HISTORY_FILE.unlink(missing_ok=True)
    except OSError:
        pass
