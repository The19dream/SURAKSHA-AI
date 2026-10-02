"""
Chooses which ``LLMProvider`` the application uses.

To add a new backend (e.g. a custom Suraksha LLM):
    1. Create ``llm_providers/suraksha_provider.py`` with a class implementing ``LLMProvider``.
    2. Add it to ``_PROVIDERS`` below.
    3. Set ``LLM_PROVIDER=suraksha`` in the environment.
No agent, route, schema or database code needs to change.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Callable, Dict

import config

from .base import LLMConfigError, LLMProvider
from .gemini_provider import GeminiProvider

_PROVIDERS: Dict[str, Callable[[], LLMProvider]] = {
    "gemini": GeminiProvider,
}


@lru_cache(maxsize=None)
def _build(name: str) -> LLMProvider:
    return _PROVIDERS[name]()


def get_llm_provider(name: str | None = None) -> LLMProvider:
    """Return the shared provider instance for ``name`` (default: ``LLM_PROVIDER``)."""
    key = (name or config.LLM_PROVIDER or "gemini").strip().lower()
    if key not in _PROVIDERS:
        raise LLMConfigError(f"Unknown LLM provider '{key}'. Available: {', '.join(sorted(_PROVIDERS))}.")
    return _build(key)
