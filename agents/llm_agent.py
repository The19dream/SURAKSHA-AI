"""
Shared base for agents that use an LLM.

Agents get their model through ``LLMProvider`` (never a vendor SDK), so the
backing model can be swapped via config without touching agent code.
"""
from typing import Any, Dict, Optional, Sequence

from llm_providers import LLMProvider, get_llm_provider

from .base_agent import AgentResult, BaseAgent, RiskLevel


class LLMAgent(BaseAgent):
    """BaseAgent + a lazily-resolved ``llm`` provider (injectable for tests)."""

    def __init__(self, llm: Optional[LLMProvider] = None):
        self._llm = llm

    @property
    def llm(self) -> LLMProvider:
        # Resolved lazily so the app can start even if no API key is configured.
        if self._llm is None:
            self._llm = get_llm_provider()
        return self._llm


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [v if isinstance(v, str) else str(v) for v in value]
    return [str(value)]


def build_agent_result(
    data: Dict[str, Any],
    agent_name: str,
    *,
    default_verdict: str = "Analysis unavailable",
    default_confidence: float = 0.0,
    default_next_steps: Sequence[str] = (),
) -> AgentResult:
    """Map the JSON object produced by an LLM onto the existing ``AgentResult``."""
    risk_value = str(data.get("risk_level", "NEEDS_REVIEW")).strip().upper()
    risk_level = RiskLevel[risk_value] if risk_value in RiskLevel.__members__ else RiskLevel.NEEDS_REVIEW

    try:
        confidence = float(data.get("confidence", default_confidence))
    except (TypeError, ValueError):
        confidence = default_confidence
    confidence = max(0.0, min(1.0, confidence))

    evidence = data.get("evidence")
    next_steps = _as_list(data.get("next_steps")) or list(default_next_steps)

    return AgentResult(
        verdict=str(data.get("verdict") or default_verdict),
        risk_level=risk_level,
        confidence=confidence,
        reasons=_as_list(data.get("reasons")),
        evidence=evidence if isinstance(evidence, dict) else {},
        next_steps=next_steps,
        agent_name=agent_name,
    )
