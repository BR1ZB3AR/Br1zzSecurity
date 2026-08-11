"""Br1zz Security - an on-demand antivirus system for Linux."""

__version__ = "v2026.08.11.1711"
__appname__ = "Br1zz Security"

from .engine.verdict import Detection, FileVerdict, Severity, Status

__all__ = ["Detection", "FileVerdict", "Severity", "Status", "__version__", "__appname__"]
