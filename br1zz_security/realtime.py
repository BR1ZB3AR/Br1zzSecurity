"""Real-time (on-access) protection.

Watches directories with inotify and scans files as they land. This is
*post-hoc* detection: a file is examined right after it is written or moved in,
not intercepted before it can be opened. Blocking access at open() time needs
fanotify with CAP_SYS_ADMIN, which would mean running as root and risking a
system-wide I/O stall if the scanner ever hangs. Watching and reacting keeps the
whole tool unprivileged, which is the deliberate trade this design makes.

inotify is bound through ctypes rather than a third-party package, so real-time
protection has no dependencies beyond the standard library.

Two events matter:

    IN_CLOSE_WRITE  a file was written and closed - i.e. it is complete
    IN_MOVED_TO     a file was moved or renamed into a watched directory

Watching IN_CREATE instead would fire on an empty file the instant it is
created, before any content exists, and scan nothing.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .config import PSEUDO_FS, Config
from .engine.scanner import Scanner
from .engine.verdict import FileVerdict, Status

# inotify event masks (linux/inotify.h)
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000
IN_ONLYDIR = 0x01000000
IN_EXCL_UNLINK = 0x04000000

WATCH_MASK = (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF
              | IN_MOVE_SELF | IN_EXCL_UNLINK)

IN_NONBLOCK = 0x800
EVENT_HEADER = struct.Struct("iIII")   # wd, mask, cookie, len
READ_BUFFER = 64 * 1024

MAX_WATCHES_HINT = (
    "the kernel inotify watch limit was reached. Raise it with:\n"
    "    sudo sysctl fs.inotify.max_user_watches=524288"
)


class RealtimeError(RuntimeError):
    pass


@dataclass
class RealtimeStats:
    started_at: float = 0.0
    events: int = 0
    scanned: int = 0
    threats: int = 0
    quarantined: int = 0
    watches: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def uptime(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    def to_dict(self) -> dict:
        return {
            "uptime": round(self.uptime, 1),
            "events": self.events,
            "scanned": self.scanned,
            "threats": self.threats,
            "quarantined": self.quarantined,
            "watches": self.watches,
            "errors": self.errors[-5:],
        }


class _Inotify:
    """Thin ctypes binding over the inotify syscalls."""

    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c")
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._libc.inotify_init1.argtypes = [ctypes.c_int]
        self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]

        self.fd = self._libc.inotify_init1(IN_NONBLOCK)
        if self.fd < 0:
            raise RealtimeError(f"inotify_init1 failed: {os.strerror(ctypes.get_errno())}")

    def add_watch(self, path: Path, mask: int = WATCH_MASK) -> int:
        wd = self._libc.inotify_add_watch(self.fd, str(path).encode(), mask)
        if wd < 0:
            code = ctypes.get_errno()
            if code == errno.ENOSPC:
                raise RealtimeError(MAX_WATCHES_HINT)
            raise OSError(code, os.strerror(code), str(path))
        return wd

    def rm_watch(self, wd: int) -> None:
        self._libc.inotify_rm_watch(self.fd, wd)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class RealtimeMonitor:
    """Watches directories and scans files as they appear.

    Detected files are reported through `on_threat`; the monitor itself never
    deletes anything. Auto-quarantine, when enabled, applies only to INFECTED
    verdicts, matching the on-demand scanner's policy.
    """

    def __init__(self, config: Config | None = None,
                 on_threat: Callable[[FileVerdict], None] | None = None,
                 on_event: Callable[[str], None] | None = None) -> None:
        self.config = config or Config.load()
        self.on_threat = on_threat
        self.on_event = on_event
        self.scanner = Scanner(self.config)
        self.stats = RealtimeStats()

        self._inotify: _Inotify | None = None
        self._watches: dict[int, Path] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ paths

    def watch_paths(self) -> list[Path]:
        configured = getattr(self.config, "realtime_paths", None) or self.config.quick_paths
        out: list[Path] = []
        for entry in configured:
            path = Path(entry).expanduser()
            if path.is_dir():
                out.append(path)
        return out

    def _should_watch(self, path: Path) -> bool:
        text = str(path)
        if any(text.startswith(p) for p in PSEUDO_FS):
            return False
        # Share the scanner's exclusion list, so Br1zz's own installation,
        # data and quarantine directories are not watched either. Watching
        # the quarantine vault in particular would re-detect every file the
        # moment it was isolated.
        for excluded in self.scanner._excluded_roots():
            try:
                if path == excluded or excluded in path.parents:
                    return False
            except (OSError, ValueError):
                continue
        return True

    def _add_tree(self, root: Path) -> int:
        """Watch a directory and everything under it."""
        added = 0
        stack = [root]
        while stack:
            current = stack.pop()
            if not self._should_watch(current):
                continue
            try:
                wd = self._inotify.add_watch(current)
            except RealtimeError:
                raise
            except OSError:
                continue  # unreadable directory; skip it rather than abort
            self._watches[wd] = current
            added += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
            except (PermissionError, OSError):
                continue
        return added

    # ------------------------------------------------------------------ scan

    def _debounced(self, path: str, window: float = 1.0) -> bool:
        """True if this path was already handled a moment ago.

        Editors and downloaders commonly produce several close-write events for
        one logical save; scanning each would triple the work for no benefit.
        """
        now = time.monotonic()
        with self._lock:
            last = self._recent.get(path)
            self._recent[path] = now
            if len(self._recent) > 2048:  # bound the memory
                cutoff = now - 30
                self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        return last is not None and (now - last) < window

    def _handle(self, path: Path) -> None:
        if self._debounced(str(path)):
            return
        try:
            if not path.is_file():
                return
        except OSError:
            return

        verdict = self.scanner.scan_file(path)
        self.stats.scanned += 1

        if not verdict.status.is_threat:
            return

        self.stats.threats += 1
        if self.config.auto_quarantine and verdict.status is Status.INFECTED:
            from .quarantine import Quarantine, QuarantineError
            try:
                entry = Quarantine().capture(verdict)
                verdict.quarantined_id = entry.id
                self.stats.quarantined += 1
            except QuarantineError as exc:
                self.stats.errors.append(str(exc))

        if self.on_threat is not None:
            try:
                self.on_threat(verdict)
            except Exception as exc:  # noqa: BLE001 - a bad callback must not kill the watcher
                self.stats.errors.append(f"threat callback: {exc}")

    # ------------------------------------------------------------------- loop

    def _read_events(self) -> list[tuple[int, int, str]]:
        try:
            data = os.read(self._inotify.fd, READ_BUFFER)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return []
            raise

        events: list[tuple[int, int, str]] = []
        offset = 0
        while offset + EVENT_HEADER.size <= len(data):
            wd, mask, _cookie, length = EVENT_HEADER.unpack_from(data, offset)
            offset += EVENT_HEADER.size
            raw = data[offset:offset + length]
            offset += length
            name = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
            events.append((wd, mask, name))
        return events

    def _loop(self) -> None:
        import selectors

        selector = selectors.DefaultSelector()
        selector.register(self._inotify.fd, selectors.EVENT_READ)

        while not self._stop.is_set():
            if not selector.select(timeout=0.5):
                continue
            try:
                events = self._read_events()
            except OSError as exc:
                self.stats.errors.append(f"read: {exc}")
                break

            for wd, mask, name in events:
                self.stats.events += 1

                if mask & IN_Q_OVERFLOW:
                    # The kernel dropped events; anything written during the
                    # gap was missed, so say so rather than pretend otherwise.
                    self.stats.errors.append(
                        "inotify queue overflowed - some files were not scanned"
                    )
                    continue

                directory = self._watches.get(wd)
                if directory is None:
                    continue

                if mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF):
                    self._watches.pop(wd, None)
                    self.stats.watches = len(self._watches)
                    continue

                target = directory / name if name else directory

                if mask & IN_ISDIR:
                    # New subdirectory: start watching it, and sweep anything
                    # already inside (files can land before the watch exists).
                    if mask & (IN_CREATE | IN_MOVED_TO):
                        try:
                            self._add_tree(target)
                            self.stats.watches = len(self._watches)
                        except RealtimeError as exc:
                            self.stats.errors.append(str(exc))
                        for child in self._safe_iter(target):
                            self._handle(child)
                    continue

                if mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                    if self.on_event is not None:
                        try:
                            self.on_event(str(target))
                        except Exception:  # noqa: BLE001
                            pass
                    self._handle(target)

        selector.close()

    @staticmethod
    def _safe_iter(directory: Path):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):
                        yield Path(entry.path)
        except (PermissionError, OSError):
            return

    # ---------------------------------------------------------------- control

    def start(self) -> "RealtimeMonitor":
        if self._thread is not None and self._thread.is_alive():
            return self

        roots = self.watch_paths()
        if not roots:
            raise RealtimeError("no existing directories configured for real-time protection")

        self.scanner.load()
        self._inotify = _Inotify()
        self._stop.clear()
        self._watches.clear()

        for root in roots:
            try:
                self._add_tree(root)
            except RealtimeError as exc:
                self.stats.errors.append(str(exc))
                break
        self.stats.watches = len(self._watches)
        self.stats.started_at = time.time()

        self._thread = threading.Thread(target=self._loop, daemon=True, name="br1zz-realtime")
        self._thread.start()
        return self

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        if self._inotify is not None:
            for wd in list(self._watches):
                self._inotify.rm_watch(wd)
            self._inotify.close()
            self._inotify = None
        self._watches.clear()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def run_forever(self) -> None:
        """Blocking entry point for the CLI and the systemd service."""
        self.start()
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
