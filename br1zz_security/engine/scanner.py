"""Scan orchestration.

Walks the requested paths, reads each candidate file exactly once, feeds the
buffer to every enabled engine, and folds the resulting detections into a single
verdict per file.

Verdict policy - deliberately conservative, because a false positive that
quarantines a real user file is worse than a missed low-confidence signal:

    INFECTED    an exact hash match, or a CRITICAL-severity rule
    SUSPICIOUS  score at or above `heuristic_threshold` (default 50)
    CLEAN       anything below that, with weak signals still recorded
"""

from __future__ import annotations

import os
import stat
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..config import (CONFIG_DIR, Config, DATA_DIR, INSTALL_ROOT, PACKAGE_DIR,
                      PSEUDO_FS, QUARANTINE_DIR)
from .hashdb import HashDatabase, hash_bytes, hash_file
from .heuristics import TEXT_RULES, Heuristics, is_text
from .verdict import Detection, FileVerdict, ScanSummary, Severity, Status
from .yara_engine import YaraEngine

ProgressFn = Callable[[str, int, int], None]

# Non-regular files are never scanned: reading a fifo or device node blocks or
# has side effects.
_SKIP_MODES = (stat.S_ISFIFO, stat.S_ISSOCK, stat.S_ISCHR, stat.S_ISBLK)


class Scanner:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.load()
        self.hashdb = HashDatabase()
        self.yara = YaraEngine()
        self.heuristics = Heuristics()
        self._loaded = False
        self._cancel: threading.Event | None = None

    # ------------------------------------------------------------------ setup

    def load(self) -> "Scanner":
        """Load every enabled engine. Safe to call more than once."""
        if self._loaded:
            return self
        if self.config.enable_hashdb:
            self.hashdb.load()
        if self.config.enable_yara:
            self.yara.load()
        self._loaded = True
        return self

    @property
    def engine_status(self) -> dict:
        return {
            "hashdb": {
                "enabled": self.config.enable_hashdb,
                "signatures": len(self.hashdb),
                "feed_signatures": self.hashdb.feed_count,
                "updated": self.hashdb.updated,
            },
            "yara": {
                "enabled": self.config.enable_yara,
                "available": self.yara.available,
                "rules": self.yara.rule_count,
                "errors": self.yara.errors,
            },
            "heuristics": {
                "enabled": self.config.enable_heuristics,
                # text pattern rules plus the structural/context checks
                "checks": len(TEXT_RULES) + 8,
            },
        }

    # -------------------------------------------------------------- traversal

    def _excluded_roots(self) -> list[Path]:
        """Paths never scanned, including Br1zz Security's own files.

        A scanner that flags its own rule files, test samples and quarantine
        vault is worse than useless - it buries real findings under its own
        noise. Excluded:

          INSTALL_ROOT   the checkout: rules and tests carry malware patterns
                         and live EICAR samples on purpose
          DATA_DIR       quarantine vault, signature database, scan history
          CONFIG_DIR     settings and user-supplied YARA rules

        The trade-off is real: malware planted inside the installation
        directory would not be scanned. Self-exclusion is standard practice for
        antivirus software, and the alternative here is a permanent flood of
        self-detections.
        """
        roots = self.config.expanded_excludes()
        roots.extend((QUARANTINE_DIR, PACKAGE_DIR, INSTALL_ROOT, DATA_DIR, CONFIG_DIR))
        resolved: list[Path] = []
        for root in roots:
            if not root:
                continue
            try:
                resolved.append(root.resolve())
            except OSError:
                continue
        return resolved

    @staticmethod
    def _is_under(path: Path, roots: Sequence[Path]) -> bool:
        for root in roots:
            try:
                if path == root or root in path.parents:
                    return True
            except (OSError, ValueError):
                continue
        return False

    def enumerate(self, roots: Sequence[Path], cancel: threading.Event | None = None) -> Iterator[Path]:
        """Yield every regular file under `roots` that passes the filters."""
        excluded = self._excluded_roots()
        seen_dirs: set[tuple[int, int]] = set()

        for root in roots:
            # Resolved to an absolute path: exclusions are absolute, and a
            # relative root ("." or "tests/") yields relative entry paths whose
            # .parents can never match them - which silently defeated the
            # self-exclusion when scanning the project directory.
            try:
                root = Path(root).expanduser().resolve()
            except OSError:
                continue
            try:
                root_stat = root.stat()
            except OSError:
                continue

            if root.is_file():
                if not self._is_under(root.resolve(), excluded):
                    yield root
                continue

            root_dev = root_stat.st_dev
            stack = [root]
            while stack:
                if cancel is not None and cancel.is_set():
                    return
                current = stack.pop()
                try:
                    entries = list(os.scandir(current))
                except (PermissionError, OSError):
                    continue

                for entry in entries:
                    if cancel is not None and cancel.is_set():
                        return
                    path = Path(entry.path)
                    try:
                        if entry.is_symlink() and not self.config.follow_symlinks:
                            continue
                        if not self.config.scan_hidden and entry.name.startswith("."):
                            continue
                        if any(entry.path.startswith(p) for p in PSEUDO_FS):
                            continue
                        if self._is_under(path, excluded):
                            continue

                        if entry.is_dir(follow_symlinks=self.config.follow_symlinks):
                            st = entry.stat(follow_symlinks=self.config.follow_symlinks)
                            if not self.config.cross_filesystems and st.st_dev != root_dev:
                                continue
                            key = (st.st_dev, st.st_ino)
                            if key in seen_dirs:  # symlink/bind-mount loop guard
                                continue
                            seen_dirs.add(key)
                            stack.append(path)
                        elif entry.is_file(follow_symlinks=self.config.follow_symlinks):
                            yield path
                    except (PermissionError, OSError):
                        continue

    # ------------------------------------------------------------- file scan

    def scan_file(self, path: Path) -> FileVerdict:
        """Scan one file with every enabled engine."""
        path = Path(path)
        try:
            st = path.lstat()
        except OSError as exc:
            return FileVerdict(path, Status.ERROR, error=str(exc))

        if any(check(st.st_mode) for check in _SKIP_MODES):
            return FileVerdict(path, Status.SKIPPED, size=0)
        if stat.S_ISLNK(st.st_mode) and not self.config.follow_symlinks:
            return FileVerdict(path, Status.SKIPPED, size=0)
        if st.st_size == 0:
            return FileVerdict(path, Status.CLEAN, size=0)

        oversized = st.st_size > self.config.max_file_size
        try:
            if oversized:
                # Too big to hold in memory: hash it in a streaming pass and run
                # only the checks that work on a prefix.
                digests = hash_file(path)
                with open(path, "rb") as fh:
                    data = fh.read(self.config.max_file_size)
            else:
                with open(path, "rb") as fh:
                    data = fh.read()
                digests = hash_bytes(data)
        except (PermissionError, OSError) as exc:
            return FileVerdict(path, Status.ERROR, size=st.st_size, error=str(exc))

        detections: list[Detection] = []

        if self.config.enable_hashdb:
            hit = self.hashdb.lookup(digests)
            if hit:
                detections.append(hit)

        # Computed once and shared: both YARA scope selection and the heuristics
        # need to know whether this is text.
        text_file = is_text(data)

        if self.config.enable_yara and self.yara.rules is not None:
            detections.extend(self.yara.match(data, is_text=text_file, externals={
                "is_elf": int(data[:4] == b"\x7fELF"),
                "file_ext": path.suffix.lower(),
            }))

        if self.config.enable_heuristics:
            detections.extend(self.heuristics.analyze(path, data))

        status, score = self._classify(detections)
        return FileVerdict(
            path=path,
            status=status,
            score=score,
            detections=detections,
            size=st.st_size,
            sha256=digests.sha256,
        )

    def _classify(self, detections: list[Detection]) -> tuple[Status, int]:
        if not detections:
            return Status.CLEAN, 0

        by_engine: dict[str, list[Detection]] = {}
        for det in detections:
            by_engine.setdefault(det.engine, []).append(det)

        # An exact content hash match is conclusive.
        if by_engine.get("hashdb"):
            return Status.INFECTED, 100

        yara_hits = by_engine.get("yara", [])
        yara_score = 0
        if yara_hits:
            yara_score = max(int(d.severity) for d in yara_hits)
            yara_score = min(100, yara_score + 15 * (len(yara_hits) - 1))

        heur_hits = by_engine.get("heuristics", [])
        heur_score = 0
        if heur_hits:
            # Corroboration, not summation: three weak signals should not add up
            # to a confident verdict the way one strong signal does.
            heur_score = max(int(d.severity) for d in heur_hits)
            heur_score = min(100, heur_score + 15 * (len(heur_hits) - 1))
            # Heuristics alone may only reach INFECTED on a CRITICAL signal.
            # Otherwise a legitimate admin script that pipes curl into a shell
            # and clears its history would be auto-quarantined.
            if not any(d.severity is Severity.CRITICAL for d in heur_hits):
                heur_score = min(heur_score, self.config.heuristic_infected_threshold - 5)

        score = max(yara_score, heur_score)
        # Independent engines agreeing is stronger evidence than either alone.
        if yara_hits and heur_hits:
            score = min(100, score + 25)

        if any(d.severity is Severity.CRITICAL for d in yara_hits):
            return Status.INFECTED, 100
        if score >= self.config.heuristic_infected_threshold:
            return Status.INFECTED, score
        if score >= self.config.heuristic_threshold:
            return Status.SUSPICIOUS, score
        return Status.CLEAN, score

    # -------------------------------------------------------------- full scan

    def scan(
        self,
        roots: Sequence[Path | str],
        progress: ProgressFn | None = None,
        cancel: threading.Event | None = None,
        on_verdict: Callable[[FileVerdict], None] | None = None,
    ) -> ScanSummary:
        """Scan every path in `roots`, reporting progress as it goes."""
        self.load()
        summary = ScanSummary(
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            root_paths=[str(Path(r).expanduser()) for r in roots],
        )
        start = time.monotonic()

        paths = list(self.enumerate([Path(r).expanduser() for r in roots], cancel))
        total = len(paths)

        if cancel is not None and cancel.is_set():
            summary.duration = time.monotonic() - start
            return summary

        done = 0
        workers = max(1, int(self.config.workers))
        # Shared with the worker threads so that already-queued tasks return
        # immediately once the scan is cancelled, instead of running to the end.
        self._cancel = cancel

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for verdict in pool.map(self._safe_scan, paths):
                done += 1
                summary.record(verdict)
                if on_verdict is not None and verdict.status.is_threat:
                    on_verdict(verdict)
                if progress is not None:
                    progress(str(verdict.path), done, total)
                if cancel is not None and cancel.is_set():
                    break

        summary.duration = time.monotonic() - start
        return summary

    def _safe_scan(self, path: Path) -> FileVerdict:
        """Never let one unreadable file abort a whole scan."""
        if self._cancel is not None and self._cancel.is_set():
            return FileVerdict(path, Status.SKIPPED)
        try:
            return self.scan_file(path)
        except Exception as exc:  # noqa: BLE001 - engine robustness boundary
            return FileVerdict(path, Status.ERROR, error=f"{type(exc).__name__}: {exc}")
