"""Application entry point for the desktop GUI."""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from .. import __appname__, __version__  # noqa: E402
from ..notify import notify  # noqa: E402
from .tray import attach_tray, AVAILABLE as tray_available  # noqa: E402
from .window import Br1zzWindow  # noqa: E402

APP_ID = "org.br1zz.Security"
ICON_NAME = "br1zz-security"


class Br1zzApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.window: Br1zzWindow | None = None
        self._pending_paths: list[str] = []
        self._tray = None
        self._background_notified = False
        self.connect("command-line", self._on_command_line)

    def do_activate(self) -> None:  # noqa: N802 - GObject naming
        if self.window is None:
            self.window = Br1zzWindow(self)
            self.window.connect("close-request", self._on_close_request)
            self._add_actions()
            self._tray = attach_tray(self)
        self.window.present()
        self._kill_tray_helper()
        if self._pending_paths:
            paths, self._pending_paths = self._pending_paths, []
            self.window.start_scan([p for p in paths], kind="custom")
        elif getattr(self, "_pending_quick", False):
            # Launched from the desktop entry's "Quick Scan" action.
            self._pending_quick = False
            self.window._on_quick_scan(None)

    def _on_command_line(self, _app, command_line) -> int:
        argv = command_line.get_arguments()
        self._pending_paths = [a for a in argv[1:] if not a.startswith("-")]
        self._pending_quick = "--quick" in argv[1:]
        self.activate()
        return 0

    def _add_actions(self) -> None:
        for name, callback in (("about", self._on_about), ("quit", self._on_quit),
                               ("show", self._on_show_window)):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
        self.set_accels_for_action("app.quit", ["<Primary>q"])

    def _on_about(self, *_args) -> None:
        about = Adw.AboutWindow(
            transient_for=self.window,
            application_name=__appname__,
            application_icon=ICON_NAME,
            version=__version__,
            comments="On-demand antivirus scanner for Linux.\n"
                     "Hash signatures, YARA rules, and behavioural heuristics.",
            license_type=Gtk.License.MIT_X11,
            release_notes_version=__version__,
            release_notes="""<p>Version v2026.08.11.1711 contains the following changes:</p>
<ul>
  <li>Updated version schema and changelog list in About dialog to v2026.08.11.1711.</li>
</ul>
<p>Version v2026.08.11.1653 contains the following changes:</p>
<ul>
  <li>Fixed system tray/taskbar minimization on Linux using a secure GTK3 helper.</li>
  <li>Formatted application version schema as vYYYY.MM.DD.HHMM.</li>
  <li>Added release notes and changelog directly into the About dialog.</li>
</ul>""",
        )
        about.present()

    def _on_close_request(self, window) -> bool:
        """Offer to keep protecting in the background, or quit outright.

        Closing the window while real-time protection is on has two reasonable
        meanings, so the user picks rather than the app guessing. The choice can
        be remembered, and is changeable again in Settings.
        """
        action = getattr(window.config, "close_action", "ask")

        if action == "quit":
            window.shutdown()
            return False
        if action == "background":
            self._hide_to_background(window)
            return True

        self._ask_close(window)
        return True  # the dialog decides; never close now

    def _ask_close(self, window) -> None:
        monitor = getattr(window, "monitor", None)
        protecting = monitor is not None and monitor.running
        has_tray = tray_available

        if protecting:
            if has_tray:
                body = (f"Real-time protection is watching "
                        f"{monitor.stats.watches} directories.\n\n"
                        "Minimising keeps it running in the background. "
                        "Quitting stops protection until you open the app again.")
            else:
                body = (f"Real-time protection is watching "
                        f"{monitor.stats.watches} directories.\n\n"
                        "The system tray is unavailable. Minimising keeps it running in the background; "
                        "you can open the app again to show the window.\n\n"
                        "To show a taskbar icon, install the system tray bindings:\n"
                        "sudo apt install gir1.2-ayatanaappindicator3-0.1")
        else:
            if has_tray:
                body = ("Real-time protection is off.\n\n"
                        "Minimising keeps Br1zz Security available in the taskbar. "
                        "Quitting closes it completely.")
            else:
                body = ("Real-time protection is off.\n\n"
                        "The system tray is unavailable. Minimising runs the app in the background; "
                        "you can open the app again to show the window.\n\n"
                        "To show a taskbar icon, install the system tray bindings:\n"
                        "sudo apt install gir1.2-ayatanaappindicator3-0.1")

        dialog = Adw.MessageDialog(
            transient_for=window, modal=True,
            heading="Close Br1zz Security?", body=body,
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("background", "Minimise to Taskbar" if has_tray else "Run in Background")
        dialog.add_response("quit", "Quit")
        dialog.set_response_appearance("background", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_response_appearance(
            "quit",
            Adw.ResponseAppearance.DESTRUCTIVE if protecting
            else Adw.ResponseAppearance.DEFAULT,
        )
        dialog.set_default_response("background")
        dialog.set_close_response("cancel")

        remember = Gtk.CheckButton(label="Remember my choice", margin_top=6)
        dialog.set_extra_child(remember)

        dialog.connect("response", self._on_close_response, window, remember)
        dialog.present()

    def _on_close_response(self, _dialog, response: str, window, remember) -> None:
        if response == "cancel":
            return
        if remember.get_active() and response in ("background", "quit"):
            window.config.close_action = response
            window.config.save()

        if response == "background":
            self._hide_to_background(window)
        elif response == "quit":
            window.shutdown()
            self.quit()

    def _hide_to_background(self, window) -> None:
        window.set_visible(False)
        monitor = getattr(window, "monitor", None)
        if not self._background_notified:
            self._background_notified = True
            if monitor is not None and monitor.running:
                notify(
                    "Still protecting in the background",
                    "Real-time protection is running. Open Br1zz Security again to "
                    "show the window.",
                )
            else:
                notify(
                    "Running in the background",
                    "Open Br1zz Security again to show the window.",
                )
        if tray_available:
            self._start_tray_helper()

    def _start_tray_helper(self) -> None:
        self._kill_tray_helper()
        import subprocess
        import os
        import sys
        
        helper_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tray_helper.py")
        try:
            env = os.environ.copy()
            self._tray_helper = subprocess.Popen(
                [sys.executable, helper_path, str(os.getpid())],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            self._tray_helper = None

    def _kill_tray_helper(self) -> None:
        helper = getattr(self, "_tray_helper", None)
        if helper is not None:
            try:
                helper.terminate()
                helper.wait(timeout=1.0)
            except Exception:
                pass
            self._tray_helper = None

    def _on_show_window(self, *_args) -> None:
        if self.window is not None:
            self.window.set_visible(True)
            self.window.present()
        self._kill_tray_helper()

    def _on_quit(self, *_args) -> None:
        self._kill_tray_helper()
        if self.window is not None:
            self.window.shutdown()
        self.quit()


def run(argv: list[str] | None = None) -> int:
    Adw.init()
    # Names the window's icon for the shell, taskbar and alt-tab switcher.
    Gtk.Window.set_default_icon_name(ICON_NAME)
    app = Br1zzApplication()
    return app.run(argv if argv is not None else sys.argv)


if __name__ == "__main__":
    sys.exit(run())
