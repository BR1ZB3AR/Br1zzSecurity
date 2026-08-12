"""Main application window.

Scanning runs on a worker thread; every UI mutation is marshalled back onto the
GTK main loop with GLib.idle_add, so the window stays responsive during a full
filesystem scan and the Cancel button works immediately.
"""

from __future__ import annotations

import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import __appname__, scanlog  # noqa: E402
from ..assistant import Explainer, ExplainerError  # noqa: E402
from ..config import GLOB_CHARS, Config, ExceptionError  # noqa: E402
from ..notify import notify_threat  # noqa: E402
from ..realtime import RealtimeError, RealtimeMonitor  # noqa: E402
from ..engine.scanner import Scanner  # noqa: E402
from ..engine.verdict import FileVerdict, ScanSummary, Status  # noqa: E402
from ..quarantine import Quarantine, QuarantineError  # noqa: E402

CSS = b"""
.threat-card { background: alpha(@error_color, 0.08); border-radius: 12px; }
.verdict-clean { color: @success_color; }
.verdict-infected { color: @error_color; }
.verdict-suspicious { color: @warning_color; }
.big-number { font-size: 2.2rem; font-weight: 800; }
.mono { font-family: monospace; }
"""


class ExplanationDialog(Adw.Window):
    """Streams the local model's explanation of one detection.

    The request runs on a worker thread; chunks arrive on the main loop via
    GLib.idle_add so the text appears as it is generated and the window never
    blocks. Closing the dialog sets a cancel flag the worker checks.
    """

    def __init__(self, parent: Gtk.Window, verdict: FileVerdict, config: Config) -> None:
        super().__init__(
            transient_for=parent, modal=True, title="Explain detection",
            default_width=620, default_height=560,
        )
        self.verdict = verdict
        self.config = config
        self._cancelled = False
        self._text = ""

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())

        self.spinner = Gtk.Spinner(spinning=True, halign=Gtk.Align.CENTER, margin_top=8)

        # Not selectable: a selectable label takes initial focus and opens with
        # its whole contents highlighted.
        header = Gtk.Label(halign=Gtk.Align.START, wrap=True, xalign=0.0)
        header.set_markup(
            f"<b>{GLib.markup_escape_text(Path(verdict.path).name)}</b>\n"
            f"<small>{GLib.markup_escape_text(verdict.name)} · score {verdict.score}</small>"
        )

        self.body = Gtk.Label(
            label="", wrap=True, selectable=True, halign=Gtk.Align.START,
            xalign=0.0, valign=Gtk.Align.START,
        )
        self.body.add_css_class("body")

        content = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=14,
            margin_top=18, margin_bottom=18, margin_start=18, margin_end=18,
        )
        content.append(header)
        content.append(Gtk.Separator())
        content.append(self.spinner)
        content.append(self.body)

        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        scroller.set_child(Adw.Clamp(maximum_size=620, child=content))
        toolbar.set_content(scroller)
        self.set_content(toolbar)

        self.connect("close-request", self._on_close)
        threading.Thread(target=self._worker, daemon=True).start()

    def _on_close(self, *_args) -> bool:
        self._cancelled = True
        return False

    def _worker(self) -> None:
        try:
            for chunk in Explainer(self.config).explain(self.verdict):
                if self._cancelled:
                    return
                GLib.idle_add(self._append, chunk)
        except ExplainerError as exc:
            GLib.idle_add(self._fail, str(exc))
            return
        GLib.idle_add(self._finish)

    def _append(self, chunk: str) -> bool:
        self.spinner.set_visible(False)
        self._text += chunk
        self.body.set_text(self._text)
        return False

    def _fail(self, message: str) -> bool:
        self.spinner.set_visible(False)
        if "cloud-routed" in message:
            # The guard already refused; nothing was sent. Do not bury that.
            self.body.set_text(f"{message}\n\nNothing has been sent off your machine.")
        else:
            self.body.set_text(
                f"The assistant is unavailable.\n\n{message}\n\n"
                "The assistant runs a model on this machine through Ollama:\n"
                "    ollama serve\n"
                "    ollama pull llama3.2:3b"
            )
        return False

    def _finish(self) -> bool:
        self.spinner.set_visible(False)
        return False


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


class Br1zzWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(
            application=app,
            title=__appname__,
            default_width=940,
            default_height=700,
            # Adw.Breakpoint requires an explicit minimum size to resolve against.
            width_request=360,
            height_request=440,
        )
        self.config = Config.load()
        self.scanner = Scanner(self.config)
        self.quarantine = Quarantine()

        self._scan_thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._threat_rows: list[Gtk.Widget] = []
        self._threats: list[FileVerdict] = []
        self._assistant_status: dict | None = None
        self.monitor: RealtimeMonitor | None = None

        self._load_css()
        self._build_ui()
        self._refresh_quarantine()
        self._refresh_history()
        GLib.idle_add(self._load_engines_async)
        if self.config.realtime_enabled:
            # Restore protection that was on when the app last closed.
            GLib.idle_add(self._start_realtime)

    # ------------------------------------------------------------------ setup

    def _load_css(self) -> None:
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            self.get_display(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _load_engines_async(self) -> bool:
        threading.Thread(target=self._load_engines, daemon=True).start()
        return False

    def _load_engines(self) -> None:
        self.scanner.load()
        # Probing the model host does network I/O, so it belongs on this worker
        # thread alongside rule compilation, not on the main loop.
        self._assistant_status = Explainer(self.config).status()
        GLib.idle_add(self._update_engine_labels)

    def _build_ui(self) -> None:
        self.toast_overlay = Adw.ToastOverlay()
        toolbar = Adw.ToolbarView()

        self.stack = Adw.ViewStack()
        self.stack.add_titled_with_icon(self._build_scan_page(), "scan", "Scan", "system-search-symbolic")
        self.stack.add_titled_with_icon(self._build_quarantine_page(), "quarantine", "Quarantine", "security-medium-symbolic")
        self.stack.add_titled_with_icon(self._build_history_page(), "history", "History", "document-open-recent-symbolic")
        self.stack.add_titled_with_icon(self._build_settings_page(), "settings", "Settings", "preferences-system-symbolic")

        header = Adw.HeaderBar()
        switcher = Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)
        # Shown instead of the switcher once the window is too narrow for it.
        self.window_title = Adw.WindowTitle(title=__appname__)

        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic")
        menu = Gtk.PopoverMenu()
        from gi.repository import Gio
        model = Gio.Menu()
        model.append("About Br1zz Security", "app.about")
        model.append("Quit", "app.quit")
        menu.set_menu_model(model)
        menu_button.set_popover(menu)
        header.pack_end(menu_button)

        toolbar.add_top_bar(header)
        toolbar.set_content(self.stack)

        switcher_bar = Adw.ViewSwitcherBar(stack=self.stack)
        toolbar.add_bottom_bar(switcher_bar)

        breakpoint_ = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 620px"))
        breakpoint_.add_setter(switcher_bar, "reveal", True)
        breakpoint_.add_setter(header, "title-widget", self.window_title)
        self.add_breakpoint(breakpoint_)

        self.toast_overlay.set_child(toolbar)
        self.set_content(self.toast_overlay)

    # ------------------------------------------------------------- scan page

    def _build_scan_page(self) -> Gtk.Widget:
        outer = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=18,
            margin_top=24, margin_bottom=24, margin_start=18, margin_end=18,
        )
        clamp = Adw.Clamp(maximum_size=760)
        clamp.set_child(box)
        outer.set_child(clamp)

        # Status hero -------------------------------------------------------
        # The app's own mark when idle; state-specific stock icons take over
        # once a scan has produced a verdict.
        self.status_icon = Gtk.Image.new_from_icon_name("br1zz-security")
        # 104 so the logo resolves from the 128px PNG and scales down slightly,
        # which stays crisp; a detailed mark turns to mush much below this.
        self.status_icon.set_pixel_size(104)

        self.status_title = Gtk.Label(label="Ready to scan")
        self.status_title.add_css_class("title-1")

        self.status_subtitle = Gtk.Label(label="No scan has run yet.")
        self.status_subtitle.add_css_class("dim-label")
        self.status_subtitle.set_wrap(True)
        self.status_subtitle.set_justify(Gtk.Justification.CENTER)

        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        hero.append(self.status_icon)
        hero.append(self.status_title)
        hero.append(self.status_subtitle)
        box.append(hero)

        # Scan buttons ------------------------------------------------------
        self.button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, homogeneous=True)
        self.quick_button = Gtk.Button(label="Quick Scan")
        self.quick_button.add_css_class("suggested-action")
        self.quick_button.add_css_class("pill")
        self.quick_button.connect("clicked", self._on_quick_scan)

        self.full_button = Gtk.Button(label="Full Scan")
        self.full_button.add_css_class("pill")
        self.full_button.connect("clicked", self._on_full_scan)

        self.folder_button = Gtk.Button(label="Choose Folder…")
        self.folder_button.add_css_class("pill")
        self.folder_button.connect("clicked", self._on_choose_folder)

        for widget in (self.quick_button, self.full_button, self.folder_button):
            self.button_box.append(widget)
        box.append(self.button_box)

        # Progress ----------------------------------------------------------
        self.progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.progress_bar = Gtk.ProgressBar(show_text=True, text="Preparing…")
        self.progress_file = Gtk.Label(label="")
        self.progress_file.add_css_class("dim-label")
        self.progress_file.add_css_class("caption")
        self.progress_file.set_ellipsize(3)  # Pango.EllipsizeMode.END
        self.cancel_button = Gtk.Button(label="Cancel", halign=Gtk.Align.CENTER)
        self.cancel_button.add_css_class("destructive-action")
        self.cancel_button.add_css_class("pill")
        self.cancel_button.connect("clicked", lambda *_: self.cancel_scan())
        self.progress_box.append(self.progress_bar)
        self.progress_box.append(self.progress_file)
        self.progress_box.append(self.cancel_button)
        self.progress_box.set_visible(False)
        box.append(self.progress_box)

        # Stats -------------------------------------------------------------
        self.stats_group = Adw.PreferencesGroup(title="Last scan")
        self.stat_files = Adw.ActionRow(title="Files scanned", subtitle="—")
        self.stat_threats = Adw.ActionRow(title="Threats found", subtitle="—")
        self.stat_duration = Adw.ActionRow(title="Duration", subtitle="—")
        for row in (self.stat_files, self.stat_threats, self.stat_duration):
            self.stats_group.add(row)
        self.stats_group.set_visible(False)
        box.append(self.stats_group)

        # Threats -----------------------------------------------------------
        self.threats_group = Adw.PreferencesGroup(title="Detections")
        self.threats_group.set_visible(False)
        box.append(self.threats_group)

        self.quarantine_all_button = Gtk.Button(label="Quarantine all infected files", halign=Gtk.Align.CENTER)
        self.quarantine_all_button.add_css_class("destructive-action")
        self.quarantine_all_button.add_css_class("pill")
        self.quarantine_all_button.connect("clicked", self._on_quarantine_all)
        self.quarantine_all_button.set_visible(False)
        box.append(self.quarantine_all_button)

        # Engine status -----------------------------------------------------
        self.engine_group = Adw.PreferencesGroup(title="Engines")
        self.engine_hash = Adw.ActionRow(title="Hash database", subtitle="loading…")
        self.update_button = Gtk.Button(label="Update", valign=Gtk.Align.CENTER,
                                        tooltip_text="Download the latest malware signatures")
        self.update_button.connect("clicked", self._on_update_signatures)
        self.update_spinner = Gtk.Spinner(valign=Gtk.Align.CENTER)
        self.update_spinner.set_visible(False)
        update_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                             valign=Gtk.Align.CENTER)
        update_box.append(self.update_spinner)
        update_box.append(self.update_button)
        self.engine_hash.add_suffix(update_box)
        self.engine_yara = Adw.ActionRow(title="YARA rules", subtitle="loading…")
        self.engine_heur = Adw.ActionRow(title="Heuristics", subtitle="loading…")
        self.engine_ai = Adw.ActionRow(title="AI assistant", subtitle="loading…")

        self.engine_realtime = Adw.ActionRow(
            title="Real-time protection",
            subtitle="Off — files are only checked when you scan",
        )
        self.realtime_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.realtime_switch.set_active(self.config.realtime_enabled)
        self.realtime_switch.connect("notify::active", self._on_realtime_toggled)
        self.engine_realtime.add_suffix(self.realtime_switch)

        for row in (self.engine_realtime, self.engine_hash, self.engine_yara,
                    self.engine_heur, self.engine_ai):
            self.engine_group.add(row)
        box.append(self.engine_group)

        return outer

    def _update_engine_labels(self) -> bool:
        status = self.scanner.engine_status
        hashdb = status["hashdb"]
        if hashdb.get("feed_signatures"):
            self.engine_hash.set_subtitle(
                f"{hashdb['signatures']} signatures "
                f"({hashdb['feed_signatures']} from threat feeds)"
            )
        else:
            self.engine_hash.set_subtitle(
                f"{hashdb['signatures']} signatures — click Update for threat feeds"
            )

        yara_info = status["yara"]
        if not yara_info["available"]:
            self.engine_yara.set_subtitle("Not installed — run: sudo apt install python3-yara")
        elif not yara_info["enabled"]:
            self.engine_yara.set_subtitle("Disabled in settings")
        else:
            self.engine_yara.set_subtitle(f"{yara_info['rules']} rules compiled")

        self.engine_heur.set_subtitle(f"{status['heuristics']['checks']} checks active")

        info = self._assistant_status or {}
        if not info.get("enabled"):
            self.engine_ai.set_subtitle("Disabled in settings")
        elif not info.get("reachable"):
            self.engine_ai.set_subtitle("Ollama not reachable — run: ollama serve")
        elif info.get("cloud_model"):
            # Say this plainly: a ':cloud' model is served through the local
            # Ollama but answers off-machine.
            self.engine_ai.set_subtitle(f"{info['model']} — cloud-routed, not on-device")
        else:
            self.engine_ai.set_subtitle(f"{info['model']} — running on this machine")
        return False

    # ------------------------------------------------------- quarantine page

    def _build_quarantine_page(self) -> Gtk.Widget:
        outer = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=18,
            margin_top=24, margin_bottom=24, margin_start=18, margin_end=18,
        )
        clamp = Adw.Clamp(maximum_size=760)
        clamp.set_child(box)
        outer.set_child(clamp)

        self.quarantine_empty = Adw.StatusPage(
            icon_name="security-medium-symbolic",
            title="Quarantine is empty",
            description="Files you isolate are encoded and stored here so they cannot run.",
        )
        box.append(self.quarantine_empty)

        self.quarantine_group = Adw.PreferencesGroup(
            title="Isolated files",
            description="Stored XOR-encoded and non-executable. Restoring returns the original bytes.",
        )
        box.append(self.quarantine_group)

        self.purge_button = Gtk.Button(label="Delete all permanently", halign=Gtk.Align.CENTER)
        self.purge_button.add_css_class("destructive-action")
        self.purge_button.add_css_class("pill")
        self.purge_button.connect("clicked", self._on_purge)
        box.append(self.purge_button)

        self._quarantine_rows: list[Gtk.Widget] = []
        return outer

    def _refresh_quarantine(self) -> bool:
        for row in self._quarantine_rows:
            self.quarantine_group.remove(row)
        self._quarantine_rows.clear()

        entries = self.quarantine.entries()
        self.quarantine_empty.set_visible(not entries)
        self.quarantine_group.set_visible(bool(entries))
        self.purge_button.set_visible(bool(entries))

        for entry in entries:
            row = Adw.ExpanderRow(title=entry.threat, subtitle=entry.original_path)

            detail = Adw.ActionRow(
                title="Quarantined",
                subtitle=f"{entry.quarantined_at} · {human_size(entry.size)} · score {entry.score}",
            )
            row.add_row(detail)

            digest = Adw.ActionRow(title="SHA-256", subtitle=entry.sha256 or "—")
            digest.add_css_class("mono")
            row.add_row(digest)

            buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, valign=Gtk.Align.CENTER)
            restore = Gtk.Button(label="Restore")
            restore.connect("clicked", self._on_restore, entry.id)
            delete = Gtk.Button(label="Delete")
            delete.add_css_class("destructive-action")
            delete.connect("clicked", self._on_delete, entry.id)
            buttons.append(restore)
            buttons.append(delete)
            row.add_suffix(buttons)

            self.quarantine_group.add(row)
            self._quarantine_rows.append(row)
        return False

    # ---------------------------------------------------------- history page

    def _build_history_page(self) -> Gtk.Widget:
        outer = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=18,
            margin_top=24, margin_bottom=24, margin_start=18, margin_end=18,
        )
        clamp = Adw.Clamp(maximum_size=760)
        clamp.set_child(box)
        outer.set_child(clamp)

        self.history_empty = Adw.StatusPage(
            icon_name="document-open-recent-symbolic",
            title="No scans yet",
            description="Completed scans are recorded here.",
        )
        box.append(self.history_empty)

        self.history_group = Adw.PreferencesGroup(title="Recent scans")
        box.append(self.history_group)
        self._history_rows: list[Gtk.Widget] = []
        return outer

    def _refresh_history(self) -> bool:
        for row in self._history_rows:
            self.history_group.remove(row)
        self._history_rows.clear()

        entries = scanlog.history(limit=25)
        self.history_empty.set_visible(not entries)
        self.history_group.set_visible(bool(entries))

        for entry in entries:
            threats = entry.get("infected", 0) + entry.get("suspicious", 0)
            row = Adw.ActionRow(
                title=entry.get("started_at", "—"),
                subtitle=f"{entry.get('kind', 'manual')} · {entry.get('scanned', 0)} files · "
                         f"{entry.get('duration', 0):.1f}s",
            )
            badge = Gtk.Label(label=f"{threats} threats" if threats else "clean")
            badge.add_css_class("verdict-infected" if threats else "verdict-clean")
            row.add_suffix(badge)
            self.history_group.add(row)
            self._history_rows.append(row)
        return False

    # --------------------------------------------------------- settings page

    def _build_settings_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()

        engines = Adw.PreferencesGroup(
            title="Detection engines",
            description="Disable an engine only for troubleshooting — coverage drops sharply.",
        )
        self.sw_hashdb = Adw.SwitchRow(title="Hash signatures", subtitle="Exact matches against known malware")
        self.sw_hashdb.set_active(self.config.enable_hashdb)
        self.sw_hashdb.connect("notify::active", self._on_setting_changed, "enable_hashdb")

        self.sw_yara = Adw.SwitchRow(title="YARA rules", subtitle="Pattern rules for malware families")
        self.sw_yara.set_active(self.config.enable_yara)
        self.sw_yara.connect("notify::active", self._on_setting_changed, "enable_yara")

        self.sw_heur = Adw.SwitchRow(title="Heuristics", subtitle="Behavioural and structural analysis")
        self.sw_heur.set_active(self.config.enable_heuristics)
        self.sw_heur.connect("notify::active", self._on_setting_changed, "enable_heuristics")

        for row in (self.sw_hashdb, self.sw_yara, self.sw_heur):
            engines.add(row)
        page.add(engines)

        behaviour = Adw.PreferencesGroup(title="Scanning")

        self.sw_autoq = Adw.SwitchRow(
            title="Quarantine infected files automatically",
            subtitle="Applies to confirmed infections only, never to suspicious files",
        )
        self.sw_autoq.set_active(self.config.auto_quarantine)
        self.sw_autoq.connect("notify::active", self._on_setting_changed, "auto_quarantine")
        behaviour.add(self.sw_autoq)

        self.sw_hidden = Adw.SwitchRow(title="Scan hidden files", subtitle="Include dotfiles and dot-directories")
        self.sw_hidden.set_active(self.config.scan_hidden)
        self.sw_hidden.connect("notify::active", self._on_setting_changed, "scan_hidden")
        behaviour.add(self.sw_hidden)

        self.close_row = Adw.ComboRow(
            title="When the window is closed",
            subtitle="Minimising keeps real-time protection running",
            model=Gtk.StringList.new(["Ask me", "Minimise to taskbar", "Quit"]),
        )
        self.close_row.set_selected(
            {"ask": 0, "background": 1, "quit": 2}.get(
                getattr(self.config, "close_action", "ask"), 0)
        )
        self.close_row.connect("notify::selected", self._on_close_action_changed)
        behaviour.add(self.close_row)

        self.sw_symlinks = Adw.SwitchRow(title="Follow symbolic links", subtitle="Off by default to avoid rescanning")
        self.sw_symlinks.set_active(self.config.follow_symlinks)
        self.sw_symlinks.connect("notify::active", self._on_setting_changed, "follow_symlinks")
        behaviour.add(self.sw_symlinks)

        self.spin_threshold = Adw.SpinRow(
            title="Suspicion threshold",
            subtitle="Score at which a file is reported as suspicious (lower = more sensitive)",
            adjustment=Gtk.Adjustment(lower=10, upper=100, step_increment=5, page_increment=10,
                                      value=self.config.heuristic_threshold),
        )
        self.spin_threshold.connect("notify::value", self._on_spin_changed, "heuristic_threshold")
        behaviour.add(self.spin_threshold)

        self.spin_workers = Adw.SpinRow(
            title="Worker threads",
            subtitle="Parallel file readers",
            adjustment=Gtk.Adjustment(lower=1, upper=32, step_increment=1, page_increment=4,
                                      value=self.config.workers),
        )
        self.spin_workers.connect("notify::value", self._on_spin_changed, "workers")
        behaviour.add(self.spin_workers)

        page.add(behaviour)

        assistant = Adw.PreferencesGroup(
            title="AI assistant",
            description="Explains detections using a model running on this machine "
                        "through Ollama. Detection data is not sent anywhere else.",
        )
        self.sw_assistant = Adw.SwitchRow(
            title="Enable the assistant",
            subtitle="Adds an Explain button to each detection",
        )
        self.sw_assistant.set_active(self.config.assistant_enabled)
        self.sw_assistant.connect("notify::active", self._on_assistant_toggled)
        assistant.add(self.sw_assistant)

        self.entry_model = Adw.EntryRow(title="Model")
        self.entry_model.set_text(self.config.assistant_model)
        self.entry_model.connect("apply", self._on_model_changed)
        self.entry_model.set_show_apply_button(True)
        assistant.add(self.entry_model)

        self.entry_host = Adw.EntryRow(title="Ollama host")
        self.entry_host.set_text(self.config.assistant_host)
        self.entry_host.connect("apply", self._on_host_changed)
        self.entry_host.set_show_apply_button(True)
        assistant.add(self.entry_host)
        page.add(assistant)

        paths = Adw.PreferencesGroup(
            title="Quick scan locations",
            description="Directories checked by a quick scan.",
        )
        for entry in self.config.quick_paths:
            expanded = Path(entry).expanduser()
            row = Adw.ActionRow(title=entry, subtitle="exists" if expanded.exists() else "not present")
            if not expanded.exists():
                row.add_css_class("dim-label")
            paths.add(row)
        page.add(paths)

        self.exceptions_group = Adw.PreferencesGroup(
            title="Scan exceptions",
            description="Files and folders that are never scanned, by manual scans "
                        "or real-time protection. Anything excepted here is not read "
                        "at all, so nothing inside it can be detected.",
        )
        add_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        folder_button = Gtk.Button(label="Add Folder…")
        folder_button.connect("clicked", self._on_add_exception_folder)
        add_buttons.append(folder_button)
        pattern_button = Gtk.Button(label="Add Pattern…")
        pattern_button.connect("clicked", self._on_add_exception_pattern)
        add_buttons.append(pattern_button)
        self.exceptions_group.set_header_suffix(add_buttons)

        self._exception_rows: list[Gtk.Widget] = []
        page.add(self.exceptions_group)
        self._refresh_exceptions()

        return page

    # ---------------------------------------------------------- exceptions

    def _refresh_exceptions(self) -> None:
        """Rebuild the exception list from the config."""
        for row in self._exception_rows:
            self.exceptions_group.remove(row)
        self._exception_rows.clear()

        if not self.config.excludes:
            empty = Adw.ActionRow(
                title="No exceptions",
                subtitle="Everything in a scanned location is checked.",
            )
            empty.add_css_class("dim-label")
            self.exceptions_group.add(empty)
            self._exception_rows.append(empty)
            return

        for entry in list(self.config.excludes):
            row = Adw.ActionRow(
                title=GLib.markup_escape_text(entry),
                subtitle=self._exception_subtitle(entry),
            )
            row.add_css_class("mono")
            remove = Gtk.Button(
                icon_name="user-trash-symbolic",
                tooltip_text=f"Remove the exception for {entry}",
                valign=Gtk.Align.CENTER,
            )
            remove.add_css_class("flat")
            remove.connect("clicked", self._on_remove_exception, entry)
            row.add_suffix(remove)
            self.exceptions_group.add(row)
            self._exception_rows.append(row)

    def _exception_subtitle(self, entry: str) -> str:
        """Describe what an exception currently covers.

        A pattern matching nothing and a folder that does not exist are both
        harmless, but they look identical to a working entry without this.
        """
        if any(ch in entry for ch in GLOB_CHARS):
            matches = len(self.config.expand_exception(entry))
            return f"pattern · matches {matches} path(s) right now"
        expanded = Path(entry).expanduser()
        if not expanded.exists():
            return "not present — applies if it is created later"
        return "folder" if expanded.is_dir() else "file"

    def _on_add_exception_folder(self, _button) -> None:
        dialog = Gtk.FileDialog(title="Choose a folder to except from scanning")
        dialog.select_folder(self, None, self._on_exception_folder_selected)

    def _on_exception_folder_selected(self, dialog, result) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return  # user dismissed the chooser
        if folder is not None and folder.get_path():
            self._add_exception(folder.get_path())

    def _on_add_exception_pattern(self, _button) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Add a scan exception",
            body="Enter an absolute path to a file or folder, or a glob pattern "
                 "such as ~/Projects/*/node_modules. Use ~ for your home directory.",
        )
        entry = Gtk.Entry(placeholder_text="~/Projects/*/node_modules", activates_default=True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add Exception")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("add")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_exception_pattern_response, entry)
        dialog.present()

    def _on_exception_pattern_response(self, _dialog, response: str, entry: Gtk.Entry) -> None:
        if response == "add":
            self._add_exception(entry.get_text())

    def _add_exception(self, raw: str) -> bool:
        """Store one exception and report the outcome. Returns True if added."""
        try:
            stored = self.config.add_exception(raw)
        except ExceptionError as exc:
            self._toast(str(exc))
            return False
        self.config.save()
        self._refresh_exceptions()
        self._toast(f"Exception added — {stored} will be skipped.")
        return True

    def _on_remove_exception(self, _button, entry: str) -> None:
        if not self.config.remove_exception(entry):
            return
        self.config.save()
        self._refresh_exceptions()
        self._toast(f"Exception removed — {entry} will be scanned again.")

    def _on_setting_changed(self, row, _param, field: str) -> None:
        setattr(self.config, field, row.get_active())
        self.config.save()
        if field.startswith("enable_"):
            # Engine set changed: rebuild the scanner so the change takes effect.
            self.scanner = Scanner(self.config)
            threading.Thread(target=self._load_engines, daemon=True).start()

    def _on_assistant_toggled(self, row, _param) -> None:
        self.config.assistant_enabled = row.get_active()
        self.config.save()
        self._refresh_assistant_status()

    def _on_model_changed(self, row) -> None:
        self.config.assistant_model = row.get_text().strip()
        self.config.save()
        self._refresh_assistant_status()

    def _on_host_changed(self, row) -> None:
        self.config.assistant_host = row.get_text().strip()
        self.config.save()
        self._refresh_assistant_status()

    def _refresh_assistant_status(self) -> None:
        def probe():
            self._assistant_status = Explainer(self.config).status()
            GLib.idle_add(self._update_engine_labels)

        threading.Thread(target=probe, daemon=True).start()

    def _on_close_action_changed(self, row, _param) -> None:
        self.config.close_action = ("ask", "background", "quit")[row.get_selected()]
        self.config.save()

    def _on_spin_changed(self, row, _param, field: str) -> None:
        setattr(self.config, field, int(row.get_value()))
        self.config.save()

    # ------------------------------------------------------------- scanning

    # --------------------------------------------------- real-time protection

    def _on_realtime_toggled(self, switch, _param) -> None:
        if switch.get_active():
            self._start_realtime()
        else:
            self._stop_realtime()

    def _start_realtime(self) -> None:
        if self.monitor is not None and self.monitor.running:
            return
        monitor = RealtimeMonitor(self.config, on_threat=self._on_realtime_threat)
        try:
            monitor.start()
        except RealtimeError as exc:
            self._toast(str(exc))
            self.realtime_switch.set_active(False)
            self.engine_realtime.set_subtitle(f"Could not start: {exc}")
            return

        self.monitor = monitor
        self.config.realtime_enabled = True
        self.config.save()
        self._refresh_realtime_status()
        # Refresh the counters periodically while protection is on.
        self._realtime_tick = GLib.timeout_add_seconds(5, self._refresh_realtime_status)
        self._toast(f"Real-time protection on — watching {monitor.stats.watches} directories.")

    def _stop_realtime(self) -> None:
        tick = getattr(self, "_realtime_tick", None)
        if tick:
            GLib.source_remove(tick)
            self._realtime_tick = None
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        self.config.realtime_enabled = False
        self.config.save()
        self.engine_realtime.set_subtitle("Off — files are only checked when you scan")
        self._update_protection_hero()

    def _refresh_realtime_status(self) -> bool:
        if self.monitor is None or not self.monitor.running:
            self.engine_realtime.set_subtitle("Off — files are only checked when you scan")
            return False
        stats = self.monitor.stats
        detail = (f"On — {stats.watches} directories, "
                  f"{stats.scanned} files checked, {stats.threats} threats")
        if stats.errors:
            detail += f" · {stats.errors[-1][:60]}"
        self.engine_realtime.set_subtitle(detail)
        self._update_protection_hero()
        return True  # keep the timer running

    def _update_protection_hero(self) -> None:
        """Reflect protection state in the hero text when no scan is showing."""
        if self._scan_thread is not None and self._scan_thread.is_alive():
            return
        if self.stats_group.get_visible():
            return  # a finished scan's summary owns the hero
        if self.monitor is not None and self.monitor.running:
            self.status_title.set_label("Protected")
            self.status_subtitle.set_label(
                f"Real-time protection is watching {self.monitor.stats.watches} directories."
            )
        else:
            self.status_title.set_label("Ready to scan")
            self.status_subtitle.set_label("No scan has run yet.")

    def _on_realtime_threat(self, verdict: FileVerdict) -> None:
        # Called from the watcher thread.
        GLib.idle_add(self._present_realtime_threat, verdict)

    def _present_realtime_threat(self, verdict: FileVerdict) -> bool:
        if self.config.realtime_notify:
            notify_threat(verdict)
        self._on_threat(verdict)
        self.stats_group.set_visible(False)
        self.threats_group.set_visible(True)
        self.status_icon.set_from_icon_name("security-low-symbolic")
        self.status_icon.add_css_class("verdict-infected")
        self.status_title.set_label("Threat detected")
        self.status_subtitle.set_label(
            f"Real-time protection flagged {verdict.path.name}."
        )
        self._refresh_quarantine()
        return False

    # ------------------------------------------------- signature updates

    def _on_update_signatures(self, _button) -> None:
        """Fetch new signatures on a worker thread; network I/O must not block the UI."""
        self.update_button.set_sensitive(False)
        self.update_button.set_label("Updating…")
        self.update_spinner.set_visible(True)
        self.update_spinner.start()
        threading.Thread(target=self._update_signatures_worker, daemon=True).start()

    def _update_signatures_worker(self) -> None:
        from .. import feeds as feedmod

        try:
            selected = [f for f in feedmod.load_feeds(getattr(self.config, "signature_feeds", None))
                        if f.get("enabled")]
            if not selected:
                GLib.idle_add(self._on_update_done, [], "No signature feeds are enabled.")
                return
            results = feedmod.update(selected)
        except Exception as exc:  # noqa: BLE001 - surface any failure in the UI
            GLib.idle_add(self._on_update_done, [], str(exc))
            return
        GLib.idle_add(self._on_update_done, results, "")

    def _on_update_done(self, results, error: str) -> bool:
        self.update_spinner.stop()
        self.update_spinner.set_visible(False)
        self.update_button.set_sensitive(True)
        self.update_button.set_label("Update")

        if error:
            self._toast(error)
            return False

        added = sum(r.added for r in results if r.ok)
        failures = [r for r in results if not r.ok]
        if failures:
            self._toast(f"Update failed: {failures[0].error}")
        elif added:
            self._toast(f"Added {added} new signatures.")
        else:
            self._toast("Signatures are already up to date.")

        # Reload the database so the new signatures apply to the next scan
        # without needing a restart.
        self.scanner = Scanner(self.config)
        threading.Thread(target=self._load_engines, daemon=True).start()
        return False

    def _on_quick_scan(self, _button) -> None:
        roots = self.config.expanded_quick_paths()
        if not roots:
            self._toast("No quick-scan locations exist on this system.")
            return
        self.start_scan(roots, kind="quick")

    def _on_full_scan(self, _button) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Run a full system scan?",
            body="Every readable file on this filesystem will be scanned. "
                 "This can take a long time. You can cancel at any point.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("scan", "Start Full Scan")
        dialog.set_response_appearance("scan", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("cancel")
        dialog.connect("response", self._on_full_scan_response)
        dialog.present()

    def _on_full_scan_response(self, dialog, response: str) -> None:
        if response == "scan":
            self.start_scan([Path("/")], kind="full")

    def _on_choose_folder(self, _button) -> None:
        dialog = Gtk.FileDialog(title="Choose a folder to scan")
        dialog.select_folder(self, None, self._on_folder_selected)

    def _on_folder_selected(self, dialog, result) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return  # user dismissed the chooser
        if folder is not None and folder.get_path():
            self.start_scan([Path(folder.get_path())], kind="custom")

    def start_scan(self, roots: list, kind: str = "manual") -> None:
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._toast("A scan is already running.")
            return

        paths = [Path(r).expanduser() for r in roots]
        self._cancel.clear()
        self._clear_threats()
        self._threats = []

        self._set_scanning(True)
        self.status_title.set_label("Scanning…")
        self.status_subtitle.set_label(", ".join(str(p) for p in paths))
        self.status_icon.set_from_icon_name("system-search-symbolic")
        self.status_icon.remove_css_class("verdict-clean")
        self.status_icon.remove_css_class("verdict-infected")
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_text("Enumerating files…")

        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(paths, kind), daemon=True
        )
        self._scan_thread.start()

    def _scan_worker(self, paths: list[Path], kind: str) -> None:
        def progress(path: str, done: int, total: int) -> None:
            GLib.idle_add(self._on_progress, path, done, total)

        def on_verdict(verdict: FileVerdict) -> None:
            GLib.idle_add(self._on_threat, verdict)

        try:
            summary = self.scanner.scan(paths, progress=progress, cancel=self._cancel, on_verdict=on_verdict)
        except Exception as exc:  # noqa: BLE001 - surface any engine failure in the UI
            GLib.idle_add(self._on_scan_error, str(exc))
            return

        if self.config.auto_quarantine and not self._cancel.is_set():
            for verdict in summary.threats:
                if verdict.status is Status.INFECTED:
                    try:
                        entry = self.quarantine.capture(verdict)
                        verdict.quarantined_id = entry.id
                        summary.quarantined += 1
                    except QuarantineError:
                        continue

        scanlog.record(summary, kind=kind)
        GLib.idle_add(self._on_scan_finished, summary)

    def _on_progress(self, path: str, done: int, total: int) -> bool:
        fraction = (done / total) if total else 0.0
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"{done} / {total} files")
        self.progress_file.set_label(path)
        return False

    def _on_threat(self, verdict: FileVerdict) -> bool:
        self._threats.append(verdict)
        self.threats_group.set_visible(True)

        infected = verdict.status is Status.INFECTED
        row = Adw.ExpanderRow(
            title=GLib.markup_escape_text(verdict.path.name),
            subtitle=GLib.markup_escape_text(str(verdict.path.parent)),
        )

        badge = Gtk.Label(label="INFECTED" if infected else "SUSPICIOUS")
        badge.add_css_class("verdict-infected" if infected else "verdict-suspicious")
        badge.add_css_class("caption-heading")
        row.add_prefix(badge)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, valign=Gtk.Align.CENTER)

        # A text label rather than an icon: symbolic icon availability varies by
        # theme, and this action benefits from being unambiguous.
        explain = Gtk.Button(label="Explain", tooltip_text="Ask the local AI assistant about this detection")
        explain.add_css_class("flat")
        explain.connect("clicked", self._on_explain, verdict)
        actions.append(explain)

        except_button = Gtk.Button(
            label="Except",
            tooltip_text="Treat this as a false positive and never scan it again",
        )
        except_button.add_css_class("flat")
        except_button.connect("clicked", self._on_except_threat, verdict, row)
        actions.append(except_button)

        button = Gtk.Button(label="Quarantine")
        if infected:
            button.add_css_class("destructive-action")
        button.connect("clicked", self._on_quarantine_one, verdict, row)
        actions.append(button)
        row.add_suffix(actions)

        summary_row = Adw.ActionRow(
            title=GLib.markup_escape_text(verdict.name),
            subtitle=f"score {verdict.score} · {human_size(verdict.size)}",
        )
        row.add_row(summary_row)

        for det in verdict.detections:
            detail = Adw.ActionRow(
                title=GLib.markup_escape_text(f"[{det.engine}] {det.name}"),
                subtitle=GLib.markup_escape_text(det.description or det.evidence or ""),
            )
            detail.set_subtitle_lines(3)
            row.add_row(detail)

        self.threats_group.add(row)
        self._threat_rows.append(row)
        return False

    def _on_scan_error(self, message: str) -> bool:
        self._set_scanning(False)
        self.status_title.set_label("Scan failed")
        self.status_subtitle.set_label(message)
        self.status_icon.set_from_icon_name("dialog-error-symbolic")
        self.status_icon.add_css_class("verdict-infected")
        return False

    def _on_scan_finished(self, summary: ScanSummary) -> bool:
        self._set_scanning(False)
        self.stats_group.set_visible(True)
        self.stat_files.set_subtitle(f"{summary.scanned} ({human_size(summary.bytes_read)})")
        self.stat_threats.set_subtitle(
            f"{summary.infected} infected, {summary.suspicious} suspicious"
        )
        self.stat_duration.set_subtitle(f"{summary.duration:.1f} seconds")

        cancelled = self._cancel.is_set()
        if summary.threat_count == 0:
            self.status_icon.set_from_icon_name("security-high-symbolic")
            self.status_icon.add_css_class("verdict-clean")
            self.status_title.set_label("Cancelled" if cancelled else "No threats found")
            self.status_subtitle.set_label(
                f"Scanned {summary.scanned} files in {summary.duration:.1f}s."
            )
        else:
            self.status_icon.set_from_icon_name("security-low-symbolic")
            self.status_icon.add_css_class("verdict-infected")
            self.status_title.set_label(f"{summary.threat_count} threats found")
            self.status_subtitle.set_label(
                f"{summary.infected} infected and {summary.suspicious} suspicious "
                f"across {summary.scanned} files."
            )
            has_infected = any(v.status is Status.INFECTED and not v.quarantined_id
                               for v in summary.threats)
            self.quarantine_all_button.set_visible(has_infected)

        if summary.quarantined:
            self._toast(f"Quarantined {summary.quarantined} file(s).")

        self._refresh_quarantine()
        self._refresh_history()
        return False

    def cancel_scan(self) -> None:
        self._cancel.set()
        self.progress_bar.set_text("Cancelling…")

    def shutdown(self) -> None:
        """Release the watcher's inotify descriptors before the app exits."""
        self._cancel.set()
        self._stop_realtime()

    def _set_scanning(self, active: bool) -> None:
        self.progress_box.set_visible(active)
        for widget in (self.quick_button, self.full_button, self.folder_button):
            widget.set_sensitive(not active)
        if active:
            self.threats_group.set_visible(False)
            self.quarantine_all_button.set_visible(False)
            self.progress_file.set_label("")

    def _clear_threats(self) -> None:
        for row in self._threat_rows:
            self.threats_group.remove(row)
        self._threat_rows.clear()

    # ----------------------------------------------------- quarantine actions

    def _on_explain(self, _button, verdict: FileVerdict) -> None:
        ExplanationDialog(self, verdict, self.config).present()

    def _on_except_threat(self, button, verdict: FileVerdict, row) -> None:
        """Offer to add the flagged file to the exception list.

        Confirmed rather than immediate: this button sits next to Quarantine
        and does the opposite thing permanently, so a misclick must not be
        enough to stop a real detection being reported ever again.
        """
        path = str(verdict.path)
        covering = self.config.exception_for(path)
        if covering is not None:
            self._toast(f"Already covered by the exception '{covering}'.")
            return

        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Never scan this file again?",
            body=f"{path}\n\nBr1zz Security reported this as "
                 f"{'infected' if verdict.status is Status.INFECTED else 'suspicious'} "
                 f"({verdict.name}). Adding an exception means the file is skipped "
                 f"entirely from now on — it will not be read, and no future change "
                 f"to it will be detected. Only do this if you are sure it is safe.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add Exception")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_except_threat_response, verdict, button, row)
        dialog.present()

    def _on_except_threat_response(self, _dialog, response: str, verdict: FileVerdict,
                                   button, row) -> None:
        if response != "add" or not self._add_exception(str(verdict.path)):
            return
        # The result stays on screen: this scan did find the file, and hiding
        # the row would make it unclear what the exception was just applied to.
        button.set_sensitive(False)
        button.set_label("Excepted")
        row.set_subtitle(f"{verdict.path.parent} · excepted from future scans")
        row.add_css_class("dim-label")

    def _on_quarantine_one(self, button, verdict: FileVerdict, row) -> None:
        try:
            entry = self.quarantine.capture(verdict)
        except QuarantineError as exc:
            self._toast(str(exc))
            return
        verdict.quarantined_id = entry.id
        button.set_sensitive(False)
        button.set_label("Quarantined")
        row.set_subtitle("Isolated in quarantine")
        self._toast(f"Quarantined {Path(entry.original_path).name}")
        self._refresh_quarantine()

    def _on_quarantine_all(self, _button) -> None:
        count = 0
        for verdict in self._threats:
            if verdict.status is Status.INFECTED and not verdict.quarantined_id:
                try:
                    entry = self.quarantine.capture(verdict)
                    verdict.quarantined_id = entry.id
                    count += 1
                except QuarantineError:
                    continue
        self.quarantine_all_button.set_visible(False)
        self._toast(f"Quarantined {count} file(s).")
        self._refresh_quarantine()

    def _on_restore(self, _button, entry_id: str) -> None:
        try:
            path = self.quarantine.restore(entry_id)
        except QuarantineError as exc:
            self._toast(str(exc))
            return
        self._toast(f"Restored to {path}")
        self._refresh_quarantine()

    def _on_delete(self, _button, entry_id: str) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Delete permanently?",
            body="The file will be overwritten and removed. This cannot be undone.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_delete_response, entry_id)
        dialog.present()

    def _on_delete_response(self, _dialog, response: str, entry_id: str) -> None:
        if response != "delete":
            return
        try:
            self.quarantine.delete(entry_id)
        except QuarantineError as exc:
            self._toast(str(exc))
            return
        self._toast("File deleted.")
        self._refresh_quarantine()

    def _on_purge(self, _button) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Delete everything in quarantine?",
            body=f"All {len(self.quarantine)} isolated files will be permanently destroyed.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("purge", "Delete All")
        dialog.set_response_appearance("purge", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_purge_response)
        dialog.present()

    def _on_purge_response(self, _dialog, response: str) -> None:
        if response != "purge":
            return
        count = self.quarantine.purge()
        self._toast(f"Deleted {count} file(s).")
        self._refresh_quarantine()

    # ------------------------------------------------------------------ misc

    def _toast(self, message: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast(title=message, timeout=4))
