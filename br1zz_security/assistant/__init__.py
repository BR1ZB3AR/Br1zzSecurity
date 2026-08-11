"""Local AI assistant: explains why a file was flagged.

Runs against a model hosted by Ollama on this machine. Detection data describes
the user's files, so it is never sent anywhere by default - see `ollama.py` for
how that constraint is enforced and reported.
"""

from .explain import Explainer, ExplainerError, build_prompt
from .ollama import OllamaBackend, OllamaError

__all__ = ["Explainer", "ExplainerError", "OllamaBackend", "OllamaError", "build_prompt"]
