"""Optional system tray indicator.

Uses a separate helper process (tray_helper.py) with GTK3 and AyatanaAppIndicator3/AppIndicator3
to display the system tray icon, avoiding conflicts with the main GTK4 process.
"""

from __future__ import annotations

import subprocess
import sys

ICON_NAME = "br1zz-security"
INSTALL_HINT = "sudo apt install gir1.2-ayatanaappindicator3-0.1"

def _check_tray_available() -> tuple[bool, str]:
    for lib in ("AyatanaAppIndicator3", "AppIndicator3"):
        try:
            res = subprocess.run(
                [sys.executable, "-c", f"import gi; gi.require_version('{lib}', '0.1')"],
                capture_output=True,
                text=True
            )
            if res.returncode == 0:
                return True, lib
        except Exception:
            pass
    return False, ""

AVAILABLE, _FLAVOUR = _check_tray_available()

def attach_tray(app):
    # Main GTK4 process does not attach a tray directly.
    # It will spawn tray_helper.py when hidden to the background.
    return None

def status_text() -> str:
    if AVAILABLE:
        return f"available ({_FLAVOUR})"
    return f"unavailable - install with: {INSTALL_HINT}"
