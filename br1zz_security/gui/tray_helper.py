import sys
import os
import signal
import subprocess
import gi

# We must require GTK 3.0 here to use AyatanaAppIndicator3
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

_INDICATOR = None
for _lib, _version in (("AyatanaAppIndicator3", "0.1"), ("AppIndicator3", "0.1")):
    try:
        gi.require_version(_lib, _version)
        _INDICATOR = __import__("gi.repository", fromlist=[_lib])
        _INDICATOR = getattr(_INDICATOR, _lib)
        break
    except (ImportError, ValueError, AttributeError):
        continue

if _INDICATOR is None:
    sys.exit(1)

ICON_NAME = "br1zz-security"

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    
    try:
        parent_pid = int(sys.argv[1])
    except ValueError:
        sys.exit(1)

    # Initialize the indicator
    local_icons = os.path.expanduser("~/.local/share/icons")
    indicator = _INDICATOR.Indicator.new(
        "br1zz-security", ICON_NAME,
        _INDICATOR.IndicatorCategory.APPLICATION_STATUS,
    )
    indicator.set_icon_theme_path(local_icons)
    indicator.set_status(_INDICATOR.IndicatorStatus.ACTIVE)
    indicator.set_title("Br1zz Security")

    # Set up the GTK3 Menu
    menu = Gtk.Menu()
    
    show_item = Gtk.MenuItem(label="Show Br1zz Security")
    def on_show(*_):
        try:
            # First try path-resolved binary
            subprocess.Popen(["br1zz-security", "gui"])
        except Exception:
            # Fall back to python module execution
            subprocess.Popen([sys.executable, "-m", "br1zz_security.cli", "gui"])
        Gtk.main_quit()

    show_item.connect("activate", on_show)
    menu.append(show_item)

    quit_item = Gtk.MenuItem(label="Quit")
    def on_quit(*_):
        try:
            os.kill(parent_pid, signal.SIGTERM)
        except Exception:
            pass
        Gtk.main_quit()

    quit_item.connect("activate", on_quit)
    menu.append(quit_item)

    menu.show_all()
    indicator.set_menu(menu)

    # Monitor parent PID to exit if the parent dies
    def check_parent():
        try:
            os.kill(parent_pid, 0)
        except OSError:
            # Parent is dead
            Gtk.main_quit()
            return False
        return True

    from gi.repository import GLib
    GLib.timeout_add(1000, check_parent)

    Gtk.main()

if __name__ == "__main__":
    main()
