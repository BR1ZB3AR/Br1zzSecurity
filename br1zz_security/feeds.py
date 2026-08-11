"""Signature feed updates.

Pulls known-malware hashes from public threat-intelligence feeds into a local
SQLite database, which `HashDatabase` then queries alongside the built-in JSON
signatures.

Why SQLite rather than more JSON: the full MalwareBazaar export is over a
million hashes. Holding that in a Python dict costs hundreds of megabytes and
makes startup slow, whereas an indexed SQLite lookup is constant-time, uses
almost no memory, and is in the standard library - which matters on this system,
where there is no pip.

Networking is explicit and opt-in. Nothing here runs during a scan; it happens
only when the user asks for `br1zz-security update`.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import DATA_DIR, ensure_dirs

FEED_DB = DATA_DIR / "signatures.db"
USER_AGENT = "br1zz-security/1.0 (+https://github.com/)"

# Feeds are declared here rather than hardcoded at the call site so `br1zz
# update --list` can show exactly which hosts will be contacted before any
# request is made.
BUILTIN_FEEDS: list[dict] = [
    {
        "name": "malwarebazaar-recent",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "format": "malwarebazaar_csv",
        "description": "abuse.ch MalwareBazaar - samples seen in the last 48 hours",
        "enabled": True,
    },
    {
        "name": "malwarebazaar-full",
        "url": "https://bazaar.abuse.ch/export/txt/sha256/full/",
        "format": "sha256_lines",
        "description": "abuse.ch MalwareBazaar - complete SHA-256 corpus (~42 MB download)",
        "enabled": False,   # opt in with --full; it is a large download
    },
]


class FeedError(RuntimeError):
    """Raised when a feed cannot be fetched or parsed."""


@dataclass
class FeedResult:
    name: str
    added: int = 0
    updated: int = 0
    total_seen: int = 0
    bytes_downloaded: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


# --------------------------------------------------------------------- store

class SignatureStore:
    """SQLite-backed store for feed-sourced hashes.

    Connections are per-thread: the scanner queries this from a thread pool and
    a single sqlite3 connection is not safe to share across threads.
    """

    def __init__(self, path: Path = FEED_DB) -> None:
        self.path = path
        self._local = threading.local()

    def _connect(self, write: bool = False) -> sqlite3.Connection:
        if write:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if not self.path.is_file():
                raise FileNotFoundError(self.path)
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True,
                                   check_same_thread=False, timeout=10)
            self._local.conn = conn
        return conn

    def initialise(self) -> None:
        conn = self._connect(write=True)
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    digest   TEXT PRIMARY KEY,
                    name     TEXT NOT NULL,
                    severity INTEGER NOT NULL DEFAULT 100,
                    source   TEXT,
                    added    TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_state (
                    name     TEXT PRIMARY KEY,
                    updated  TEXT,
                    count    INTEGER
                )
            """)
        conn.close()

    def upsert_many(self, rows: list[tuple[str, str, int]], source: str) -> tuple[int, int]:
        """Insert or refresh signatures. Returns (added, updated)."""
        if not rows:
            return 0, 0
        self.initialise()
        conn = self._connect(write=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        before = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        with conn:
            conn.executemany(
                "INSERT INTO signatures (digest, name, severity, source, added) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(digest) DO UPDATE SET name=excluded.name, source=excluded.source",
                [(d.lower(), n, s, source, stamp) for d, n, s in rows],
            )
            conn.execute(
                "INSERT INTO feed_state (name, updated, count) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET updated=excluded.updated, count=excluded.count",
                (source, stamp, len(rows)),
            )
        after = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        conn.close()
        added = after - before
        return added, len(rows) - added

    def lookup(self, digests: list[str]) -> tuple[str, int] | None:
        """Return (name, severity) for the first digest that is known-bad."""
        try:
            conn = self._connect()
        except (FileNotFoundError, sqlite3.Error):
            return None
        try:
            placeholders = ",".join("?" * len(digests))
            row = conn.execute(
                f"SELECT name, severity FROM signatures WHERE digest IN ({placeholders}) LIMIT 1",
                [d.lower() for d in digests],
            ).fetchone()
        except sqlite3.Error:
            return None
        return (row[0], row[1]) if row else None

    def count(self) -> int:
        try:
            conn = self._connect()
            return conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        except (FileNotFoundError, sqlite3.Error):
            return 0

    def feed_state(self) -> list[dict]:
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT name, updated, count FROM feed_state ORDER BY name"
            ).fetchall()
        except (FileNotFoundError, sqlite3.Error):
            return []
        return [{"name": r[0], "updated": r[1], "count": r[2]} for r in rows]

    def clear(self) -> None:
        if self.path.is_file():
            self.path.unlink()
        for suffix in ("-wal", "-shm"):
            extra = self.path.with_name(self.path.name + suffix)
            extra.unlink(missing_ok=True)
        self._local = threading.local()


# ------------------------------------------------------------------ fetching

def fetch(url: str, timeout: int = 120) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{url} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"cannot reach {url}: {exc.reason}") from exc
    except OSError as exc:
        raise FeedError(f"cannot reach {url}: {exc}") from exc


def _maybe_unzip(payload: bytes) -> bytes:
    """Feeds are served as either plain text or a zip; handle both."""
    if payload[:2] != b"PK":
        return payload
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
            if not names:
                raise FeedError("feed archive is empty")
            return archive.read(names[0])
    except zipfile.BadZipFile as exc:
        raise FeedError(f"feed archive is corrupt: {exc}") from exc


# ------------------------------------------------------------------- parsers

def parse_malwarebazaar_csv(payload: bytes) -> list[tuple[str, str, int]]:
    """Parse the MalwareBazaar CSV export into (digest, name, severity) rows."""
    text = _maybe_unzip(payload).decode("utf-8", "replace")
    rows: list[tuple[str, str, int]] = []
    reader = csv.reader(
        (line for line in text.splitlines() if line and not line.startswith("#")),
        skipinitialspace=True,
    )
    for record in reader:
        if len(record) < 9:
            continue
        sha256, md5, sha1 = record[1].strip(), record[2].strip(), record[3].strip()
        family = (record[8] or "").strip()
        file_type = (record[6] or "").strip()
        if not family or family.lower() in ("n/a", "unknown", ""):
            name = f"Malware.{file_type.capitalize() or 'Generic'}.MalwareBazaar"
        else:
            name = f"Malware.{family}"
        for digest in (sha256, md5, sha1):
            if _is_hex_digest(digest):
                rows.append((digest, name, 100))
    return rows


def parse_sha256_lines(payload: bytes) -> list[tuple[str, str, int]]:
    """Parse a plain list of SHA-256 hashes, one per line."""
    text = _maybe_unzip(payload).decode("utf-8", "replace")
    rows: list[tuple[str, str, int]] = []
    for line in text.splitlines():
        digest = line.strip().strip('"')
        if digest.startswith("#") or not _is_hex_digest(digest):
            continue
        rows.append((digest, "Malware.MalwareBazaar", 100))
    return rows


PARSERS = {
    "malwarebazaar_csv": parse_malwarebazaar_csv,
    "sha256_lines": parse_sha256_lines,
}


def _is_hex_digest(value: str) -> bool:
    if len(value) not in (32, 40, 64):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


# -------------------------------------------------------------------- update

def load_feeds(config_feeds: list | None = None) -> list[dict]:
    """Merge the built-in feed list with any user overrides from config."""
    feeds = {f["name"]: dict(f) for f in BUILTIN_FEEDS}
    for entry in config_feeds or []:
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        feeds.setdefault(entry["name"], {}).update(entry)
    return list(feeds.values())


def update(feeds: list[dict], store: SignatureStore | None = None,
           on_progress=None) -> list[FeedResult]:
    """Fetch each enabled feed and merge it into the signature store."""
    ensure_dirs()
    store = store or SignatureStore()
    results: list[FeedResult] = []

    for feed in feeds:
        name = feed.get("name", "?")
        result = FeedResult(name=name)
        if on_progress:
            on_progress(name, "fetching")
        try:
            parser = PARSERS.get(feed.get("format", ""))
            if parser is None:
                raise FeedError(f"unknown feed format '{feed.get('format')}'")
            payload = fetch(feed["url"])
            result.bytes_downloaded = len(payload)
            if on_progress:
                on_progress(name, "parsing")
            rows = parser(payload)
            result.total_seen = len(rows)
            if on_progress:
                on_progress(name, "storing")
            result.added, result.updated = store.upsert_many(rows, name)
        except (FeedError, KeyError, ValueError, sqlite3.Error) as exc:
            result.error = str(exc)
        results.append(result)
    return results
