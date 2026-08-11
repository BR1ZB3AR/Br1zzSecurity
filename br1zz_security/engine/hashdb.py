"""Hash-based signature matching.

The fastest and most precise layer: an exact content hash either is or is not a
known-bad sample, with no false positives. Digests for every file are computed
once here in a single streaming pass and reused by the rest of the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import BUILTIN_SIGNATURES, USER_SIGNATURES
from .verdict import Detection, Severity

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Digests:
    """All hashes for one file, computed in a single read."""

    sha256: str
    md5: str
    sha1: str
    size: int


def hash_bytes(data: bytes) -> Digests:
    """Digest an already-loaded buffer, so small files are read only once."""
    return Digests(
        hashlib.sha256(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        len(data),
    )


def hash_file(path: Path, max_bytes: int | None = None) -> Digests:
    """Stream a file once and return every digest the engines need."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    total = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            sha256.update(block)
            md5.update(block)
            sha1.update(block)
            total += len(block)
            if max_bytes is not None and total >= max_bytes:
                break
    return Digests(sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest(), total)


class HashDatabase:
    """Known-malware digests, merged from the built-in and user databases."""

    def __init__(self) -> None:
        self._by_hash: dict[str, dict] = {}
        self.sources: list[str] = []
        self.updated: str = ""
        # Feed-sourced hashes live in SQLite rather than this dict: the full
        # MalwareBazaar corpus is over a million entries.
        self.store = None
        self.feed_count = 0

    # ------------------------------------------------------------------ load

    def load(self) -> "HashDatabase":
        for source in (BUILTIN_SIGNATURES, USER_SIGNATURES):
            self._load_file(source)

        from ..feeds import SignatureStore
        store = SignatureStore()
        count = store.count()
        if count:
            self.store = store
            self.feed_count = count
            self.sources.append(f"{store.path} ({count} feed signatures)")
        return self

    def _load_file(self, path: Path) -> None:
        if not path.is_file():
            return
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return

        signatures = raw.get("signatures", raw)
        if not isinstance(signatures, dict):
            return

        for digest, meta in signatures.items():
            key = digest.strip().lower()
            if not key:
                continue
            if isinstance(meta, str):
                meta = {"name": meta}
            if not isinstance(meta, dict):
                continue
            self._by_hash[key] = {
                "name": meta.get("name", "Malware.Generic"),
                "severity": int(meta.get("severity", Severity.CRITICAL)),
                "description": meta.get("description", ""),
            }

        self.sources.append(str(path))
        updated = raw.get("meta", {}).get("updated", "") if isinstance(raw.get("meta"), dict) else ""
        if updated > self.updated:
            self.updated = updated

    # ------------------------------------------------------------------ query

    def __len__(self) -> int:
        return len(self._by_hash) + self.feed_count

    def lookup(self, digests: Digests) -> Detection | None:
        """Return a detection if any of the file's digests is known-bad."""
        candidates = (digests.sha256, digests.sha1, digests.md5)

        for digest in candidates:
            hit = self._by_hash.get(digest)
            if hit:
                return Detection(
                    name=hit["name"],
                    engine="hashdb",
                    severity=Severity.from_score(hit["severity"]),
                    description=hit["description"] or "Exact match against a known-malware signature.",
                    evidence=f"sha256:{digests.sha256[:32]}...",
                )

        if self.store is not None:
            found = self.store.lookup(list(candidates))
            if found:
                name, severity = found
                return Detection(
                    name=name,
                    engine="hashdb",
                    severity=Severity.from_score(severity),
                    description="Exact match against a signature from a threat-intelligence feed.",
                    evidence=f"sha256:{digests.sha256[:32]}...",
                )
        return None

    # ----------------------------------------------------------------- update

    def add(self, digest: str, name: str, severity: int = 100, description: str = "") -> None:
        """Add a signature to the user database and persist it."""
        digest = digest.strip().lower()
        entry = {"name": name, "severity": severity, "description": description}
        self._by_hash[digest] = entry

        existing: dict = {"meta": {}, "signatures": {}}
        if USER_SIGNATURES.is_file():
            try:
                existing = json.loads(USER_SIGNATURES.read_text())
            except (OSError, json.JSONDecodeError):
                pass
        existing.setdefault("signatures", {})[digest] = entry
        existing["meta"] = {
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(existing["signatures"]),
        }
        USER_SIGNATURES.parent.mkdir(parents=True, exist_ok=True)
        USER_SIGNATURES.write_text(json.dumps(existing, indent=2) + "\n")
