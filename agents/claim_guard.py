"""Small shared helper for the Phase 5 intelligence agents (Fraud Intel, Voice).

The agents work only from user-provided text, so a model reply that asserts an external
lookup or a voice identification happened is treated as unusable (the agent raises
``LLMResponseError`` -> HTTP 502) instead of being passed on as fact.

This is a narrow regex check, not a fact-checker; the prompts are the main control.
A match is ignored when a negation or "unverified" appears EARLIER in the same sentence, so
honest statements such as "no database was checked" or "cannot be confirmed as listed in any
police records" are not rejected, while "Biometric verification confirmed the caller is not X"
still is (the negation comes after the claim).
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Iterator, List, Pattern

_NEGATION = re.compile(
    r"\b(?:no|not|never|cannot|can't|cant|unable|without|neither|nor|unverified|unconfirmed|"
    r"did\s+not|didn't|does\s+not|doesn't|was\s+not|wasn't|were\s+not|weren't|isn't|is\s+not)\b",
    re.I,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")


def iter_strings(obj: Any) -> Iterator[str]:
    """Yield every string found in a (possibly nested) list/dict/str."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v)


def asserts_forbidden_claim(texts: Iterable[str], patterns: List[Pattern]) -> bool:
    """True if any sentence contains a pattern match that is not preceded by a negation."""
    for text in texts:
        for sentence in _SENTENCE_SPLIT.split(text):
            if not sentence:
                continue
            for p in patterns:
                for m in p.finditer(sentence):
                    if not _NEGATION.search(sentence[: m.start()]):
                        return True
    return False


def clean_list(value: Any, max_items: int = 20, max_len: int = 500) -> list:
    """Coerce a model-supplied value to a bounded list of short strings / flat dicts."""
    if not isinstance(value, (list, tuple)):
        return []
    out: list = []
    for item in value[:max_items]:
        if isinstance(item, dict):
            out.append({str(k)[:50]: str(v)[:max_len] for k, v in item.items()})
        elif item is not None and str(item).strip():
            out.append(str(item).strip()[:max_len])
    return out
