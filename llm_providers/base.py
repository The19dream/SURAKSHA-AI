"""
Provider-neutral LLM interface for Suraksha AI.

Agents depend ONLY on this module (via ``llm_providers``), never on a vendor SDK.
To plug in a different model (e.g. a fine-tuned Suraksha LLM), subclass
``LLMProvider``, implement ``generate()``, and register it in ``factory.py``.

This module is intentionally stdlib-only so it can be tested without any SDK.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Sequence


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
# Every message below is written to be SAFE to show to API users: it never
# contains keys, prompts, or stack traces. Details go to server logs only.

class LLMError(Exception):
    """Base class for all provider errors. ``str(exc)`` is safe to return to clients."""

    default_message = "The AI service encountered an unexpected error."

    def __init__(self, message: str | None = None):
        self.public_message = message or self.default_message
        super().__init__(self.public_message)


class LLMConfigError(LLMError):
    """Provider is missing/invalid configuration (e.g. no API key, unknown provider)."""

    default_message = "The AI service is not configured correctly."


class LLMProviderError(LLMError):
    """The provider's backend call failed (network, quota, rejected request...)."""

    default_message = "The AI service is temporarily unavailable. Please try again."


class LLMTimeoutError(LLMProviderError):
    """The provider did not answer within the configured timeout."""

    default_message = "The AI service took too long to respond. Please try again."


class LLMResponseError(LLMError):
    """The provider answered, but the answer was empty or not usable JSON."""

    default_message = "The AI service returned a response that could not be understood."

    def __init__(self, message: str | None = None, raw_text: str = ""):
        super().__init__(message)
        # Kept for agents that want to degrade gracefully (e.g. HotspotAgent).
        self.raw_text = raw_text or ""


# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ImagePart:
    """An image to send alongside the prompt (multimodal input)."""

    data: bytes
    mime_type: str = "image/jpeg"


@dataclass(frozen=True)
class LLMResponse:
    """Raw provider output. ``text`` is whatever the model produced."""

    text: str
    provider: str
    model: str


# --------------------------------------------------------------------------
# JSON parsing (provider-independent, so a custom LLM gets it for free)
# --------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*(.*?)\s*```\s*$", re.DOTALL)


def parse_json_response(text: str) -> Dict[str, Any]:
    """
    Parse a model reply into a JSON object.

    Accepts plain JSON, JSON wrapped in a markdown code fence, or JSON embedded
    in surrounding prose. Raises ``LLMResponseError`` if no JSON object is found.
    """
    raw = text or ""
    candidate = raw.strip()

    fenced = _FENCE_RE.match(candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    attempts = [candidate]
    start, end = candidate.find("{"), candidate.rfind("}")
    if start != -1 and end > start:
        attempts.append(candidate[start : end + 1])

    for attempt in attempts:
        try:
            parsed = json.loads(attempt)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed

    raise LLMResponseError(raw_text=raw)


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------

class LLMProvider(ABC):
    """What every LLM backend (Gemini today, Suraksha LLM later) must implement."""

    #: Short identifier used in logs/metadata, e.g. "gemini".
    name: str = "unknown"

    @abstractmethod
    async def generate(
        self, prompt: str, *, images: Sequence[ImagePart] = ()
    ) -> LLMResponse:
        """
        Send ``prompt`` (and optional images) to the model and return its raw text.

        Must raise only ``LLMError`` subclasses, with client-safe messages.
        """

    async def generate_json(
        self, prompt: str, *, images: Sequence[ImagePart] = ()
    ) -> Dict[str, Any]:
        """Convenience wrapper: ``generate()`` then parse the reply as a JSON object."""
        response = await self.generate(prompt, images=images)
        return parse_json_response(response.text)
