"""
Gemini implementation of ``LLMProvider``.

This is the ONLY module in the project that imports the Google Gemini SDK
(``google-genai``). Everything else talks to ``LLMProvider``.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional, Sequence, Tuple

import config

from .base import (
    ImagePart,
    LLMConfigError,
    LLMError,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
)

logger = logging.getLogger("suraksha.llm.gemini")


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        # Values fall back to config.py (which reads env vars / .env).
        # The key is stored privately and never logged or returned.
        self._api_key = (config.GEMINI_API_KEY if api_key is None else api_key) or ""
        self._api_key = self._api_key.strip()
        self._model = model or config.GEMINI_MODEL
        self._timeout = config.LLM_TIMEOUT_SECONDS if timeout is None else timeout
        self._client: Any = None  # created lazily on first use

    @property
    def model(self) -> str:
        return self._model

    # ------------------------------------------------------------------
    # SDK access (kept in small hooks so tests can stand in for the SDK)
    # ------------------------------------------------------------------
    @staticmethod
    def _load_sdk() -> Tuple[Any, Any]:
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            raise LLMConfigError(
                "The Gemini SDK (google-genai) is not installed on the server."
            ) from None
        return genai, types

    def _get_client(self) -> Any:
        """Create the SDK client on first use, so the app can start without a key."""
        if not self._api_key:
            raise LLMConfigError(
                "GEMINI_API_KEY is not configured on the server."
            )
        if self._client is None:
            genai, _ = self._load_sdk()
            try:
                self._client = genai.Client(api_key=self._api_key)
            except Exception as exc:  # SDK rejected the configuration
                self._log_failure("client initialisation", exc)
                raise LLMConfigError(
                    "The Gemini client could not be initialised. Check the server's API key configuration."
                ) from None
        return self._client

    def _build_contents(self, prompt: str, images: Sequence[ImagePart]) -> Any:
        if not images:
            return prompt  # identical to the original text-only call
        _, types = self._load_sdk()
        parts = [
            types.Part.from_bytes(data=img.data, mime_type=img.mime_type)
            for img in images
        ]
        return [prompt, *parts]

    # ------------------------------------------------------------------
    # LLMProvider
    # ------------------------------------------------------------------
    async def generate(
        self, prompt: str, *, images: Sequence[ImagePart] = ()
    ) -> LLMResponse:
        client = self._get_client()
        contents = self._build_contents(prompt, images)

        try:
            # The SDK call is synchronous; run it in a worker thread so it does
            # not block the event loop, and bound the wait with a timeout.
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    client.models.generate_content,
                    model=self._model,
                    contents=contents,
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            logger.error("Gemini call timed out after %ss (model=%s)", self._timeout, self._model)
            raise LLMTimeoutError() from None
        except LLMError:
            raise
        except Exception as exc:
            raise self._translate_error(exc) from None

        try:
            text = response.text
        except Exception as exc:  # some SDK versions raise when the reply was blocked
            self._log_failure("reading response text", exc)
            raise LLMResponseError() from None

        if not text or not text.strip():
            logger.error("Gemini returned an empty response (model=%s)", self._model)
            raise LLMResponseError()

        return LLMResponse(text=text, provider=self.name, model=self._model)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------
    def _redact(self, text: str) -> str:
        if self._api_key:
            text = text.replace(self._api_key, "[REDACTED]")
        return text[:300]

    def _log_failure(self, what: str, exc: Exception) -> None:
        logger.error("Gemini %s failed: %s: %s", what, type(exc).__name__, self._redact(str(exc)))

    def _translate_error(self, exc: Exception) -> LLMError:
        self._log_failure("call", exc)
        code = getattr(exc, "code", None)
        if isinstance(code, int):
            if code == 429:
                return LLMProviderError(
                    "The AI service is receiving too many requests. Please try again shortly."
                )
            if code in (400, 401, 403, 404):
                return LLMProviderError(
                    "The AI provider rejected the request. Check the server's API key and model configuration."
                )
        return LLMProviderError()
