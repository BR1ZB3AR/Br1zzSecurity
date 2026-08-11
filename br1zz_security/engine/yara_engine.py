"""YARA rule matching.

yara-python is an optional dependency. When it is missing the engine reports
itself unavailable and the scanner runs on hashes plus heuristics alone, so the
tool is always usable even before `apt install python3-yara`.

Rules are compiled into two scopes, which is a performance decision with a
measured basis. YARA scans a buffer for *every* string in a ruleset before it
evaluates a single condition, so a text-only rule guarded by `is_text` in its
condition still costs full price on an 8 MB shared library. Measured on this
project's rules over 836 MB of /usr/lib:

    all rules in one set     13.0 MB/s
    hash + heuristics only  129.2 MB/s

Splitting the regex-heavy shell rules into a text-only scope means binaries -
which are the overwhelming majority of bytes on a Linux system - are matched
only against a handful of cheap literal-string rules.
"""

from __future__ import annotations

from pathlib import Path

from ..config import RULES_ANY_DIR, RULES_TEXT_DIR, USER_RULES_DIR
from .verdict import Detection, Severity

try:  # pragma: no cover - availability depends on the host
    import yara  # type: ignore
    YARA_AVAILABLE = True
    YARA_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover
    yara = None  # type: ignore
    YARA_AVAILABLE = False
    YARA_IMPORT_ERROR = str(exc)

INSTALL_HINT = "sudo apt install python3-yara"

# Externals describe the file to any rule that wants them. Scope gating is done
# by the ruleset split rather than by these, but user rules may still use them.
DEFAULT_EXTERNALS = {"is_text": 0, "is_elf": 0, "file_ext": ""}

_SEVERITY_WORDS = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class YaraEngine:
    """Compiles and applies the built-in and user rule sets."""

    def __init__(self) -> None:
        self.available = YARA_AVAILABLE
        self.rules_any = None      # applied to every file
        self.rules_text = None     # applied to text files only
        self.rule_count = 0
        self.rule_files: list[str] = []
        self.errors: list[str] = []
        # Per-file matching failures (timeouts on pathological inputs). Kept
        # separate from `errors`, which is about rule compilation.
        self.scan_errors: list[str] = []

    # ------------------------------------------------------------------- load

    def load(self) -> "YaraEngine":
        if not self.available:
            self.errors.append(f"yara-python not installed ({YARA_IMPORT_ERROR}); try: {INSTALL_HINT}")
            return self

        # User rules default to the 'any' scope so a dropped-in .yar file just
        # works; ~/.config/br1zz-security/rules/text/ opts into the text-only scope.
        self.rules_any = self._compile("any", [RULES_ANY_DIR, USER_RULES_DIR])
        self.rules_text = self._compile("text", [RULES_TEXT_DIR, USER_RULES_DIR / "text"])

        if self.rules_any is None and self.rules_text is None:
            self.errors.append("no YARA rules could be compiled")
        self.rule_count = sum(
            sum(1 for _ in rules) for rules in (self.rules_any, self.rules_text) if rules is not None
        )
        return self

    def _compile(self, scope: str, directories: list[Path]):
        sources: dict[str, str] = {}
        for directory in directories:
            if not directory.is_dir():
                continue
            for rule_file in sorted(directory.glob("*.yar")) + sorted(directory.glob("*.yara")):
                # One namespace per file so a broken rule set is isolated.
                sources[f"{scope}/{directory.name}/{rule_file.stem}"] = str(rule_file)

        if not sources:
            return None

        try:
            compiled = yara.compile(filepaths=sources, externals=DEFAULT_EXTERNALS)
            self.rule_files.extend(sources.values())
            return compiled
        except yara.Error as exc:
            # Fall back to compiling each file alone so one bad file does not
            # take the whole rule set offline.
            self.errors.append(f"{scope}: combined compile failed: {exc}")
            good = {}
            for namespace, path in sources.items():
                try:
                    yara.compile(filepath=path, externals=DEFAULT_EXTERNALS)
                    good[namespace] = path
                except yara.Error as file_exc:
                    self.errors.append(f"{Path(path).name}: {file_exc}")
            if not good:
                return None
            try:
                compiled = yara.compile(filepaths=good, externals=DEFAULT_EXTERNALS)
                self.rule_files.extend(good.values())
                return compiled
            except yara.Error as exc2:
                self.errors.append(f"{scope}: {exc2}")
                return None

    @property
    def rules(self):
        """Back-compat handle: truthy when any ruleset is loaded."""
        return self.rules_any or self.rules_text

    # ------------------------------------------------------------------ match

    def match(self, data: bytes, is_text: bool = False, externals: dict | None = None,
              timeout: int = 20) -> list[Detection]:
        values = dict(DEFAULT_EXTERNALS)
        values["is_text"] = int(is_text)
        if externals:
            values.update(externals)

        rulesets = [self.rules_any]
        if is_text:
            rulesets.append(self.rules_text)

        out: list[Detection] = []
        seen: set[str] = set()
        for rules in rulesets:
            if rules is None:
                continue
            try:
                matches = rules.match(data=data, externals=values, timeout=timeout)
            except Exception as exc:  # yara.TimeoutError, yara.Error
                # A scan failure is a diagnostic, never a detection. Emitting it
                # as one made an engine timeout look like corroborating evidence
                # and pushed clean files over the suspicion threshold.
                self.scan_errors.append(f"{type(exc).__name__}: {exc}")
                continue

            for match in matches:
                meta = match.meta or {}
                name = str(meta.get("name", match.rule))
                if name in seen:
                    continue
                seen.add(name)
                out.append(Detection(
                    name=name,
                    engine="yara",
                    severity=self._severity(meta),
                    description=str(meta.get("description", f"Matched YARA rule {match.rule}")),
                    evidence=self._evidence(match),
                ))
        return out

    @staticmethod
    def _severity(meta: dict) -> Severity:
        raw = meta.get("severity", meta.get("level"))
        if isinstance(raw, int):
            return Severity.from_score(raw)
        if isinstance(raw, str):
            if raw.lower() in _SEVERITY_WORDS:
                return _SEVERITY_WORDS[raw.lower()]
            if raw.isdigit():
                return Severity.from_score(int(raw))
        return Severity.MEDIUM

    @staticmethod
    def _evidence(match) -> str:
        """Summarise which strings hit, without dumping payload bytes."""
        parts: list[str] = []
        for string_match in getattr(match, "strings", [])[:4]:
            identifier = getattr(string_match, "identifier", None)
            if identifier is None:  # yara-python < 4.3 tuple form
                parts.append(str(string_match[1]))
                continue
            instances = getattr(string_match, "instances", [])
            offset = instances[0].offset if instances else 0
            parts.append(f"{identifier}@{offset}")
        return ", ".join(parts)
