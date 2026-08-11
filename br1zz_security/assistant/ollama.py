"""Minimal Ollama client built on the standard library.

No third-party HTTP dependency: this system's Python is externally managed and
has no pip, so `urllib` it is.

Privacy: `is_local` reports whether the configured host actually resolves to
this machine. The CLI and GUI surface that, because "the AI runs locally" is a
promise the user should be able to verify rather than take on trust.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", ""})

# Small models that suit this task, best first. Used to suggest a pull when the
# configured model is missing.
SUGGESTED_MODELS = ("llama3.2:3b", "qwen2.5:3b", "phi3.5:3.8b", "llama3.2:1b")


class OllamaError(RuntimeError):
    """Raised when the model host cannot be reached or refuses a request."""


@dataclass(frozen=True)
class ModelInfo:
    name: str
    size: int

    @property
    def is_cloud(self) -> bool:
        """Ollama's ':cloud' tags proxy to a hosted model rather than running here."""
        return self.name.endswith(":cloud") or self.size == 0


class OllamaBackend:
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.2:3b",
                 timeout: int = 120) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    # ------------------------------------------------------------- properties

    @property
    def is_local(self) -> bool:
        """True when the configured host is this machine."""
        try:
            hostname = urllib.parse.urlparse(self.host).hostname or ""
        except ValueError:
            return False
        return hostname in LOCAL_HOSTS

    # ---------------------------------------------------------------- helpers

    def _request(self, path: str, payload: dict | None = None, timeout: int | None = None):
        url = f"{self.host}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if data else "GET",
        )
        try:
            return urllib.request.urlopen(request, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise OllamaError(f"model host returned {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise OllamaError(
                f"cannot reach the model host at {self.host} ({exc.reason}). "
                "Is Ollama running? Start it with: ollama serve"
            ) from exc
        except OSError as exc:
            raise OllamaError(f"cannot reach the model host at {self.host}: {exc}") from exc

    # ------------------------------------------------------------------ probes

    def available(self) -> bool:
        try:
            self.models()
            return True
        except OllamaError:
            return False

    def models(self) -> list[ModelInfo]:
        with self._request("/api/tags", timeout=10) as response:
            payload = json.loads(response.read())
        return [
            ModelInfo(name=m.get("name", "?"), size=int(m.get("size", 0)))
            for m in payload.get("models", [])
        ]

    def resolve_model(self) -> str:
        """Pick a usable model, preferring the configured one.

        Falls back to any installed model so the assistant works out of the box
        rather than failing on a name the user never chose.
        """
        installed = self.models()
        if not installed:
            raise OllamaError(
                "no models are installed. Install a small local one with:\n"
                f"    ollama pull {SUGGESTED_MODELS[0]}"
            )

        names = {m.name for m in installed}
        if self.model in names:
            return self.model
        # Allow 'llama3.2' to match an installed 'llama3.2:3b'.
        for name in names:
            if name.split(":")[0] == self.model.split(":")[0]:
                return name
        for candidate in SUGGESTED_MODELS:
            if candidate in names:
                return candidate
        local_first = sorted(installed, key=lambda m: (m.is_cloud, m.name))
        return local_first[0].name

    # ------------------------------------------------------------------- chat

    def chat(self, system: str, user: str, temperature: float = 0.2,
             max_tokens: int = 1400) -> Iterator[str]:
        """Stream a reply, yielding text chunks as the model produces them."""
        model = self.resolve_model()
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }

        with self._request("/api/chat", payload) as response:
            for raw in response:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if chunk.get("error"):
                    raise OllamaError(str(chunk["error"]))
                content = chunk.get("message", {}).get("content", "")
                if content:
                    yield content
                if chunk.get("done"):
                    break
