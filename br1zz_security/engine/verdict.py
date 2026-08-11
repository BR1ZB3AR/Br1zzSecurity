"""Shared result types.

Every engine emits `Detection` objects; the scanner folds the detections for one
file into a single `FileVerdict`. Keeping the engines behind one result type is
what lets the CLI, GUI and JSON output share all their formatting logic.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Severity(enum.IntEnum):
    """How dangerous a single detection is, on a 0-100 scale."""

    INFO = 10
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        for level in (cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW):
            if score >= level:
                return level
        return cls.INFO


class Status(enum.Enum):
    """Final classification of a scanned file."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    INFECTED = "infected"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def is_threat(self) -> bool:
        return self in (Status.SUSPICIOUS, Status.INFECTED)


@dataclass(frozen=True)
class Detection:
    """One reason a file was flagged."""

    name: str              # e.g. "Trojan.Linux.ReverseShell" or "HEUR:HighEntropy"
    engine: str            # "hashdb" | "yara" | "heuristics"
    severity: Severity
    description: str = ""
    evidence: str = ""     # short excerpt / offset / matched string, already sanitised

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "engine": self.engine,
            "severity": int(self.severity),
            "severity_label": self.severity.name,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class FileVerdict:
    """The combined result for a single file."""

    path: Path
    status: Status
    score: int = 0
    detections: list[Detection] = field(default_factory=list)
    size: int = 0
    sha256: str = ""
    error: str = ""
    quarantined_id: str = ""

    @property
    def primary(self) -> Detection | None:
        """The detection that best characterises this file."""
        if not self.detections:
            return None
        return max(self.detections, key=lambda d: d.severity)

    @property
    def name(self) -> str:
        det = self.primary
        return det.name if det else ""

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "status": self.status.value,
            "score": self.score,
            "size": self.size,
            "sha256": self.sha256,
            "threat": self.name,
            "detections": [d.to_dict() for d in self.detections],
            "error": self.error,
            "quarantined_id": self.quarantined_id,
        }


@dataclass
class ScanSummary:
    """Aggregate statistics for one scan run."""

    scanned: int = 0
    clean: int = 0
    suspicious: int = 0
    infected: int = 0
    errors: int = 0
    skipped: int = 0
    bytes_read: int = 0
    duration: float = 0.0
    quarantined: int = 0
    threats: list[FileVerdict] = field(default_factory=list)
    started_at: str = ""
    root_paths: list[str] = field(default_factory=list)

    def record(self, verdict: FileVerdict) -> None:
        if verdict.status is Status.SKIPPED:
            self.skipped += 1
            return
        self.scanned += 1
        self.bytes_read += verdict.size
        if verdict.status is Status.CLEAN:
            self.clean += 1
        elif verdict.status is Status.SUSPICIOUS:
            self.suspicious += 1
            self.threats.append(verdict)
        elif verdict.status is Status.INFECTED:
            self.infected += 1
            self.threats.append(verdict)
        elif verdict.status is Status.ERROR:
            self.errors += 1

    @property
    def threat_count(self) -> int:
        return self.infected + self.suspicious

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "root_paths": self.root_paths,
            "scanned": self.scanned,
            "clean": self.clean,
            "suspicious": self.suspicious,
            "infected": self.infected,
            "errors": self.errors,
            "skipped": self.skipped,
            "quarantined": self.quarantined,
            "bytes_read": self.bytes_read,
            "duration": round(self.duration, 3),
            "threats": [t.to_dict() for t in self.threats],
        }
