"""Desktop notifications for real-time detections.

A background scanner that finds something and says nothing is useless, so the
watcher raises a desktop notification. Delivery is attempted in order of
fidelity and degrades quietly:

    1. GLib/Gio  - the proper session-bus route, used when the GUI is running
    2. notify-send - works for the headless systemd service
    3. stderr    - so a detection is never silently swallowed

Nothing here is allowed to raise: a missing notification daemon must not take
down real-time protection.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from .engine.verdict import FileVerdict, Status

APP_NAME = "Br1zz Security"
ICON_NAME = "br1zz-security"


def _via_gio(title: str, body: str, urgent: bool) -> bool:
    try:
        import gi
        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib
    except (ImportError, ValueError):
        return False

    try:
        app = Gio.Application.get_default()
        if app is None:
            return False
        note = Gio.Notification.new(title)
        note.set_body(body)
        note.set_priority(Gio.NotificationPriority.URGENT if urgent
                          else Gio.NotificationPriority.NORMAL)
        try:
            note.set_icon(Gio.ThemedIcon.new(ICON_NAME))
        except GLib.Error:
            pass
        app.send_notification(None, note)
        return True
    except Exception:  # noqa: BLE001 - notification must never be fatal
        return False


def _via_notify_send(title: str, body: str, urgent: bool) -> bool:
    binary = shutil.which("notify-send")
    if not binary:
        return False
    try:
        subprocess.run(
            [binary, "--app-name", APP_NAME, "--icon", ICON_NAME,
             "--urgency", "critical" if urgent else "normal", title, body],
            check=False, capture_output=True, timeout=10,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def notify(title: str, body: str, urgent: bool = False) -> bool:
    """Show a desktop notification. Returns True if something accepted it."""
    for backend in (_via_gio, _via_notify_send):
        if backend(title, body, urgent):
            return True
    print(f"[{APP_NAME}] {title}: {body}", file=sys.stderr)
    return False


def notify_threat(verdict: FileVerdict) -> bool:
    """Announce one real-time detection."""
    infected = verdict.status is Status.INFECTED
    title = "Threat blocked" if verdict.quarantined_id else (
        "Threat detected" if infected else "Suspicious file detected"
    )
    lines = [verdict.path.name, verdict.name or verdict.status.value]
    if verdict.quarantined_id:
        lines.append("Moved to quarantine.")
    else:
        lines.append(str(verdict.path.parent))
    return notify(title, "\n".join(lines), urgent=infected)
