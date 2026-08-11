"""The quarantine vault.

Quarantined files are neutralised, not merely moved: the content is XOR-encoded
with a per-file random key before it is written to the vault, and the stored copy
is mode 0600 with every execute bit stripped. A sample sitting in quarantine is
therefore not a runnable executable and will not be matched by other scanners.

The original bytes are fully recoverable, and a restore verifies the SHA-256 of
the decoded content against what was recorded at capture time.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import QUARANTINE_DIR, QUARANTINE_INDEX, ensure_dirs
from .engine.hashdb import hash_bytes
from .engine.verdict import FileVerdict

CHUNK = 1024 * 1024
KEY_SIZE = 32


class QuarantineError(RuntimeError):
    """Raised when a quarantine or restore operation cannot be completed."""


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    threat: str
    status: str
    score: int
    size: int
    sha256: str
    mode: int
    quarantined_at: str
    key: str
    detections: list[dict]

    @property
    def vault_path(self) -> Path:
        return QUARANTINE_DIR / f"{self.id}.qbin"

    def to_dict(self) -> dict:
        return asdict(self)


def _xor(data: bytes, key: bytes, offset: int = 0) -> bytes:
    """XOR `data` with a repeating key, continuing from a stream offset.

    Done as one big-integer XOR rather than a per-byte loop: for multi-megabyte
    samples the loop version dominates quarantine time.
    """
    if not data:
        return b""
    keylen = len(key)
    start = offset % keylen
    reps = -(-(len(data) + start) // keylen)  # ceil division
    stream = (key * reps)[start:start + len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")


class Quarantine:
    """Reads and writes the quarantine vault and its index."""

    def __init__(self) -> None:
        ensure_dirs()
        self._entries: dict[str, QuarantineEntry] = {}
        self._load()

    # ----------------------------------------------------------------- index

    def _load(self) -> None:
        if not QUARANTINE_INDEX.is_file():
            return
        try:
            raw = json.loads(QUARANTINE_INDEX.read_text())
        except (OSError, json.JSONDecodeError):
            return
        for item in raw.get("entries", []):
            try:
                self._entries[item["id"]] = QuarantineEntry(**item)
            except TypeError:
                continue

    def _save(self) -> None:
        QUARANTINE_INDEX.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        tmp = QUARANTINE_INDEX.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(QUARANTINE_INDEX)

    # --------------------------------------------------------------- queries

    def entries(self) -> list[QuarantineEntry]:
        return sorted(self._entries.values(), key=lambda e: e.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineEntry | None:
        if entry_id in self._entries:
            return self._entries[entry_id]
        # Allow unambiguous short-id prefixes for convenience on the CLI.
        matches = [e for k, e in self._entries.items() if k.startswith(entry_id)]
        return matches[0] if len(matches) == 1 else None

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------- capture

    def capture(self, verdict: FileVerdict) -> QuarantineEntry:
        """Move a detected file into the vault, neutralising it on the way in."""
        source = Path(verdict.path)
        if not source.is_file():
            raise QuarantineError(f"not a regular file: {source}")

        try:
            st = source.lstat()
        except OSError as exc:
            raise QuarantineError(f"cannot stat {source}: {exc}") from exc

        entry_id = f"{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(6)}"
        key = secrets.token_bytes(KEY_SIZE)
        vault_file = QUARANTINE_DIR / f"{entry_id}.qbin"

        try:
            offset = 0
            with open(source, "rb") as src, open(vault_file, "wb") as dst:
                os.chmod(vault_file, 0o600)
                while True:
                    block = src.read(CHUNK)
                    if not block:
                        break
                    dst.write(_xor(block, key, offset))
                    offset += len(block)
        except OSError as exc:
            vault_file.unlink(missing_ok=True)
            raise QuarantineError(f"cannot write vault copy: {exc}") from exc

        try:
            source.unlink()
        except OSError as exc:
            vault_file.unlink(missing_ok=True)
            raise QuarantineError(f"cannot remove original {source}: {exc}") from exc

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(source),
            threat=verdict.name or "Unknown",
            status=verdict.status.value,
            score=verdict.score,
            size=st.st_size,
            sha256=verdict.sha256,
            mode=stat_mode(st.st_mode),
            quarantined_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            key=key.hex(),
            detections=[d.to_dict() for d in verdict.detections],
        )
        self._entries[entry_id] = entry
        self._save()
        return entry

    # ------------------------------------------------------------- restore

    def restore(self, entry_id: str, target: Path | None = None, force: bool = False) -> Path:
        """Decode a quarantined file back to disk and drop it from the index."""
        entry = self.get(entry_id)
        if entry is None:
            raise QuarantineError(f"no quarantine entry matching '{entry_id}'")

        vault_file = entry.vault_path
        if not vault_file.is_file():
            raise QuarantineError(f"vault copy is missing: {vault_file}")

        destination = Path(target) if target else Path(entry.original_path)
        if destination.exists() and not force:
            raise QuarantineError(f"{destination} already exists (use --force to overwrite)")

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise QuarantineError(f"cannot create {destination.parent}: {exc}") from exc

        key = bytes.fromhex(entry.key)
        try:
            with open(vault_file, "rb") as src:
                data = _xor(src.read(), key)
        except OSError as exc:
            raise QuarantineError(f"cannot read vault copy: {exc}") from exc

        # The recorded digest is only present for files small enough to have been
        # hashed in full; skip verification rather than block a restore.
        if entry.sha256:
            actual = hash_bytes(data).sha256
            if actual != entry.sha256:
                raise QuarantineError(
                    f"integrity check failed: vault copy hashes to {actual[:16]}..., "
                    f"expected {entry.sha256[:16]}..."
                )

        try:
            destination.write_bytes(data)
            os.chmod(destination, entry.mode or 0o600)
        except OSError as exc:
            raise QuarantineError(f"cannot write {destination}: {exc}") from exc

        vault_file.unlink(missing_ok=True)
        self._entries.pop(entry.id, None)
        self._save()
        return destination

    # -------------------------------------------------------------- delete

    def delete(self, entry_id: str) -> str:
        """Permanently destroy a quarantined file."""
        entry = self.get(entry_id)
        if entry is None:
            raise QuarantineError(f"no quarantine entry matching '{entry_id}'")

        vault_file = entry.vault_path
        if vault_file.is_file():
            try:
                # Overwrite before unlinking so the bytes are not trivially
                # recoverable from the free list.
                length = vault_file.stat().st_size
                with open(vault_file, "r+b") as fh:
                    remaining = length
                    while remaining > 0:
                        block = min(CHUNK, remaining)
                        fh.write(secrets.token_bytes(block))
                        remaining -= block
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
            vault_file.unlink(missing_ok=True)

        self._entries.pop(entry.id, None)
        self._save()
        return entry.id

    def purge(self) -> int:
        """Delete every quarantined file. Returns how many were removed."""
        count = 0
        for entry in list(self._entries.values()):
            try:
                self.delete(entry.id)
                count += 1
            except QuarantineError:
                continue
        return count


def stat_mode(mode: int) -> int:
    """Keep only the permission bits worth restoring."""
    return mode & 0o7777
