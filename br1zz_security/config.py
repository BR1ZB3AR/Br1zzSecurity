"""Configuration and filesystem layout for Br1zz Security.

Follows the XDG base directory spec so the tool stays a well-behaved
unprivileged user application:

    ~/.config/br1zz-security/config.json   settings
    ~/.config/br1zz-security/rules/        user-supplied YARA rules
    ~/.local/share/br1zz-security/         quarantine vault, scan history, signature cache
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
# The checkout or installation root. Excluded from scanning in full: it holds
# the YARA rules and the test suite, both of which contain malware patterns and
# live EICAR samples by design. Without this, Br1zz reliably detects itself.
INSTALL_ROOT = PACKAGE_DIR.parent
BUILTIN_RULES_DIR = PACKAGE_DIR / "rules"
# Rules are split by the kind of file they can possibly match. YARA runs every
# string pattern in a ruleset across the whole buffer *before* it evaluates any
# condition, so gating a text-only rule inside its condition does not stop a
# 10 MB shared library from paying for its regexes. Separate rulesets do.
RULES_ANY_DIR = BUILTIN_RULES_DIR / "any"      # cheap, literal - runs on everything
RULES_TEXT_DIR = BUILTIN_RULES_DIR / "text"    # regex-heavy - text/scripts only
BUILTIN_SIGNATURES = PACKAGE_DIR / "signatures" / "hashes.json"


def _xdg(env: str, default: str) -> Path:
    value = os.environ.get(env)
    return Path(value) if value else Path.home() / default


APP_DIRNAME = "br1zz-security"
LEGACY_DIRNAME = "br1zz"

CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config") / APP_DIRNAME
DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share") / APP_DIRNAME

LEGACY_CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config") / LEGACY_DIRNAME
LEGACY_DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share") / LEGACY_DIRNAME

CONFIG_FILE = CONFIG_DIR / "config.json"
USER_RULES_DIR = CONFIG_DIR / "rules"
QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_INDEX = DATA_DIR / "quarantine.json"
HISTORY_FILE = DATA_DIR / "history.jsonl"
USER_SIGNATURES = DATA_DIR / "signatures.json"

# Pseudo-filesystems and device trees that must never be walked: scanning them
# is meaningless and reading some entries blocks forever.
PSEUDO_FS = (
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/var/run", "/var/lock", "/sys/kernel", "/tmp/.X11-unix",
)

# Filesystem types that are never worth scanning even if mounted elsewhere.
PSEUDO_FSTYPES = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "debugfs", "tracefs", "configfs", "fusectl", "pstore", "bpf", "mqueue",
    "hugetlbfs", "autofs", "binfmt_misc", "rpc_pipefs", "nsfs", "squashfs",
})

QUICK_SCAN_PATHS = [
    "~/Downloads", "~/Desktop", "~/Documents", "/tmp", "/var/tmp",
    "~/.config/autostart", "~/.local/share/applications",
]

DEFAULT_EXCLUDES = [
    "~/.cache", "~/.local/share/Trash", "~/.local/share/br1zz-security/quarantine",
    "~/.mozilla/firefox/*/cache2", "~/.steam", "~/snap",
    "/var/lib/docker", "/var/cache", "/var/log",
]


@dataclass
class Config:
    """User-tunable scanner settings."""

    # Files larger than this are hashed but not deep-scanned. Most malware is
    # small; reading multi-gigabyte media files wastes the whole scan budget.
    max_file_size: int = 64 * 1024 * 1024

    # Heuristic score at or above which a file is reported as SUSPICIOUS.
    heuristic_threshold: int = 50

    # Score at or above which heuristics alone escalate to INFECTED.
    heuristic_infected_threshold: int = 100

    follow_symlinks: bool = False
    scan_hidden: bool = True
    cross_filesystems: bool = False
    auto_quarantine: bool = False
    workers: int = min(8, (os.cpu_count() or 4))

    quick_paths: list[str] = field(default_factory=lambda: list(QUICK_SCAN_PATHS))
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))

    enable_yara: bool = True
    enable_heuristics: bool = True
    enable_hashdb: bool = True

    # Extra or overriding signature feeds for `br1zz-security update`. Entries are
    # merged over the built-in list by name; see br1zz/feeds.py.
    signature_feeds: list = field(default_factory=list)

    # Real-time protection. Watches with inotify and scans files after they are
    # written, which is post-hoc detection rather than blocking access - see
    # realtime.py for why that trade is deliberate.
    realtime_enabled: bool = False
    realtime_paths: list[str] = field(default_factory=lambda: list(QUICK_SCAN_PATHS))
    realtime_notify: bool = True
    # What the window's close button does: "ask" shows a dialog offering to
    # minimise or quit, "background" always hides and keeps protection running,
    # "quit" always exits. Defaults to asking, because silently doing either
    # one surprises somebody.
    close_action: str = "ask"

    # Local AI assistant (Ollama). Deliberately points at localhost: detection
    # data describes the user's files and must not leave the machine. Pointing
    # `assistant_host` at a remote endpoint is possible but is opt-out of that
    # guarantee, and the CLI says so.
    assistant_enabled: bool = True
    assistant_host: str = "http://localhost:11434"
    assistant_model: str = "llama3.2:3b"
    assistant_timeout: int = 300
    # Generation cap. 700 truncated Gemma mid-section; the four-section answer
    # needs headroom, and models vary a lot in how tersely they write.
    assistant_max_tokens: int = 1400
    # Ollama ':cloud' model tags are served by the local daemon but answer
    # off-machine. Using one is refused unless this is explicitly turned on:
    # a privacy guarantee that is only announced, and not enforced, is not one.
    assistant_allow_cloud_model: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = path or CONFIG_FILE
        cfg = cls()
        if path.is_file():
            try:
                raw = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                return cfg  # corrupt config must never stop a scan
            known = {f for f in cls.__dataclass_fields__}
            for key, value in raw.items():
                if key in known:
                    setattr(cfg, key, value)
        return cfg

    def save(self, path: Path | None = None) -> Path:
        path = path or CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n")
        return path

    def expanded_excludes(self) -> list[Path]:
        out: list[Path] = []
        for item in self.excludes:
            expanded = Path(item).expanduser()
            if any(ch in item for ch in "*?["):
                # Glob patterns are resolved against / or ~ as appropriate.
                root = Path.home() if item.startswith("~") else Path("/")
                pattern = str(expanded.relative_to(root)) if expanded.is_absolute() else item
                try:
                    out.extend(root.glob(pattern))
                except (ValueError, OSError):
                    continue
            else:
                out.append(expanded)
        return out

    def expanded_quick_paths(self) -> list[Path]:
        return [p for p in (Path(q).expanduser() for q in self.quick_paths) if p.exists()]


def migrate_legacy_dirs() -> list[str]:
    """Move data from the old `br1zz` directories to `br1zz-security`.

    The application was renamed after release. Anyone upgrading has a populated
    quarantine vault and signature database under the old name, and silently
    ignoring them would look like data loss. Only moves when the new location
    does not yet exist, so it can never clobber current data.
    """
    moved: list[str] = []
    for legacy, current in ((LEGACY_CONFIG_DIR, CONFIG_DIR), (LEGACY_DATA_DIR, DATA_DIR)):
        try:
            if legacy.is_dir() and not current.exists():
                current.parent.mkdir(parents=True, exist_ok=True)
                legacy.rename(current)
                moved.append(f"{legacy} -> {current}")
        except OSError:
            continue  # a failed migration must never stop the program starting
    return moved


def ensure_dirs() -> None:
    """Create the runtime directory tree. Quarantine is owner-only."""
    migrate_legacy_dirs()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    USER_RULES_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(QUARANTINE_DIR, 0o700)
