"""Turns a scan verdict into a plain-language explanation.

Design constraints, in order of importance:

1. **Advisory only.** The assistant explains and recommends. It has no ability
   to quarantine, restore or delete anything - the user acts, never the model.

2. **Grounded.** The prompt carries the detection metadata the engines actually
   produced (rule name, severity, rule author's description, matched evidence).
   The model is told to reason only from that and to say when it cannot tell,
   because a confident invented explanation of a security finding is worse than
   no explanation.

3. **Bounded content.** Only a small, capped excerpt of the file is included,
   and only for text files. A binary's bytes are never shipped into a prompt.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..config import Config
from ..engine.heuristics import is_text
from ..engine.verdict import FileVerdict, Status
from .ollama import OllamaBackend, OllamaError

MAX_EXCERPT = 1500
MAX_EVIDENCE = 200

SYSTEM_PROMPT = """\
You are the security analyst built into Br1zz Security, an antivirus scanner for \
Linux. You explain a scan result to the person who owns the file, who may not be \
a security specialist.

Ground every statement in the detection data you are given. It comes from three \
engines: exact hash signatures, YARA rules, and behavioural heuristics. If the \
data does not tell you something, say so plainly rather than guessing - an \
invented explanation of a security finding is worse than admitting uncertainty.

Answer in exactly these four short sections, using these headings:

WHAT THIS FILE APPEARS TO BE
WHY IT WAS FLAGGED
HOW LIKELY THIS IS A FALSE ALARM
WHAT TO DO

Rules:
- Two or three sentences per section. No preamble, no sign-off.
- Be concrete about the mechanism: name the technique, say what it would let an \
attacker do.
- Be honest about false positives. Administration scripts, security tooling and \
developer utilities legitimately do many of the things these rules detect. If \
the file looks like one of those, say so clearly.
- For "WHAT TO DO", give the user a decision, not a lecture. Mention that Br1zz \
can quarantine the file (which encodes it so it cannot run, reversibly) when \
that is the right call.
- Never claim to have taken any action. You cannot act; you only advise.
"""


class ExplainerError(RuntimeError):
    pass


def _severity_line(detection) -> str:
    parts = [f"  - [{detection.engine}] {detection.name} (severity: {detection.severity.name.lower()})"]
    if detection.description:
        parts.append(f"      what the rule detects: {detection.description}")
    if detection.evidence:
        evidence = detection.evidence[:MAX_EVIDENCE]
        parts.append(f"      matched in this file: {evidence}")
    return "\n".join(parts)


def build_prompt(verdict: FileVerdict, excerpt: str | None = None) -> str:
    """Assemble the grounded user prompt for one verdict."""
    path = Path(verdict.path)
    lines = [
        "Explain this antivirus scan result.",
        "",
        "FILE",
        f"  name: {path.name}",
        f"  directory: {path.parent}",
        f"  size: {verdict.size} bytes",
        f"  sha256: {verdict.sha256 or 'not recorded'}",
        "",
        "VERDICT",
        f"  status: {verdict.status.value}",
        f"  score: {verdict.score} out of 100",
        "",
    ]

    if verdict.detections:
        lines.append("DETECTIONS")
        lines.extend(_severity_line(d) for d in verdict.detections)
    else:
        lines.append("DETECTIONS\n  none - the scanner found nothing wrong with this file.")

    if excerpt:
        lines += [
            "",
            "FILE CONTENT (truncated)",
            "```",
            excerpt,
            "```",
        ]

    lines += [
        "",
        "Explain this to the file's owner using the four required sections.",
    ]
    return "\n".join(lines)


def read_excerpt(path: Path, limit: int = MAX_EXCERPT) -> str | None:
    """Return a capped text excerpt, or None for binaries and unreadable files.

    Binary content is never included: it would be unreadable to the model and
    balloons the prompt for no benefit.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(limit * 2)
    except OSError:
        return None
    if not head or not is_text(head):
        return None
    text = head.decode("utf-8", "replace")
    if len(text) > limit:
        text = text[:limit] + "\n... (truncated)"
    return text


class Explainer:
    """Explains a verdict using a locally hosted model."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.load()
        self.backend = OllamaBackend(
            host=self.config.assistant_host,
            model=self.config.assistant_model,
            timeout=self.config.assistant_timeout,
        )

    @property
    def available(self) -> bool:
        return self.config.assistant_enabled and self.backend.available()

    def status(self) -> dict:
        """Describe the assistant's readiness, for `br1zz-security status` and the GUI."""
        info: dict = {
            "enabled": self.config.assistant_enabled,
            "host": self.config.assistant_host,
            "local": self.backend.is_local,
            "reachable": False,
            "model": None,
            "models": [],
            "error": "",
        }
        if not self.config.assistant_enabled:
            info["error"] = "disabled in settings"
            return info
        info["cloud_model"] = False
        try:
            models = self.backend.models()
            info["reachable"] = True
            info["models"] = [m.name for m in models]
            info["model"] = self.backend.resolve_model()
            # A ':cloud' tag is served locally but proxies to a hosted model, so
            # a local host is not by itself proof the data stays on the machine.
            info["cloud_model"] = any(
                m.is_cloud for m in models if m.name == info["model"]
            )
        except OllamaError as exc:
            info["error"] = str(exc)
        return info

    def _guard_cloud_model(self) -> None:
        """Refuse to send detection data to a model that answers off-machine.

        Warning the user while the request is already in flight gives them no
        say. The assistant is offered as on-device, so anything else is opt-in.
        """
        if self.config.assistant_allow_cloud_model:
            return
        info = self.status()
        if info.get("cloud_model"):
            raise ExplainerError(
                f"the selected model ({info['model']}) is cloud-routed: using it would send "
                "this detection data off your machine, which the assistant does not do by "
                "default.\n"
                "  Install an on-device model:  ollama pull llama3.2:3b\n"
                "  Or allow cloud models:       br1zz-security config set assistant_allow_cloud_model true"
            )

    def explain(self, verdict: FileVerdict, include_content: bool = True) -> Iterator[str]:
        """Stream an explanation for one verdict."""
        if not self.config.assistant_enabled:
            raise ExplainerError("the assistant is disabled (br1zz-security config set assistant_enabled true)")

        self._guard_cloud_model()

        excerpt = None
        if include_content and verdict.status is not Status.ERROR:
            excerpt = read_excerpt(Path(verdict.path))

        prompt = build_prompt(verdict, excerpt)
        try:
            yield from self.backend.chat(
                SYSTEM_PROMPT, prompt,
                max_tokens=getattr(self.config, "assistant_max_tokens", 1400),
            )
        except OllamaError as exc:
            raise ExplainerError(str(exc)) from exc
