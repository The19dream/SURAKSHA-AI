"""Decision Engine: agent outputs -> one unified result.

Only data actually returned by the agents is used for verdict / reasons / evidence /
next_steps. The engine adds only: the numeric score, the unified level, the deterministic
prevention list, and (when it overrides a LOW rating) one clearly labelled reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from agents.base_agent import AgentResult

from . import risk_score
from .prevention import build_prevention
from .schemas import (
    EvidenceItem,
    FailedComponent,
    ScoreBreakdownItem,
    UnifiedAnalysisResult,
    UnifiedRiskLevel,
)

# Evidence keys never forwarded (raw, unparsed model text).
EXCLUDED_EVIDENCE_KEYS = {"raw_response"}


@dataclass
class AgentOutput:
    kind: str  # analysis kind that routed to this agent: "scam" | "note" | "hotspot" | ...
    result: AgentResult


def _dedupe(items: Sequence[str]) -> List[str]:
    seen, out = set(), []
    for s in items:
        s = s.strip() if isinstance(s, str) else str(s)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


class DecisionEngine:
    def decide(
        self,
        analysis_type: str,
        outputs: Sequence[AgentOutput],
        failures: Sequence[FailedComponent] = (),
    ) -> UnifiedAnalysisResult:
        if not outputs:
            raise ValueError("DecisionEngine needs at least one agent output.")

        breakdown: List[ScoreBreakdownItem] = []
        for o in outputs:
            score, level, note = risk_score.score_agent(o.result.risk_level.value, o.result.confidence)
            breakdown.append(
                ScoreBreakdownItem(
                    agent=o.result.agent_name,
                    analysis_type=o.kind,
                    agent_risk_level=o.result.risk_level.value,
                    confidence=o.result.confidence,
                    effective_risk_level=level,
                    score=score,
                    note=note,
                )
            )

        score, level, dominant_item = risk_score.combine(breakdown, has_failures=bool(failures))
        dominant = outputs[breakdown.index(dominant_item)].result

        reasons: List[str] = list(dominant.reasons)
        for o in outputs:
            if o.result is not dominant:
                reasons += o.result.reasons
        if level == UnifiedRiskLevel.NEEDS_REVIEW and dominant_item.note:
            reasons.append(f"[Decision Engine] {dominant_item.note}")
        elif level == UnifiedRiskLevel.NEEDS_REVIEW and failures:
            reasons.append("[Decision Engine] A component failed, so a LOW rating cannot be confirmed.")

        evidence = [
            EvidenceItem(agent=o.result.agent_name, field=str(k), value=v)
            for o in outputs
            for k, v in o.result.evidence.items()
            if k not in EXCLUDED_EVIDENCE_KEYS and v not in (None, "", [], {})
        ]

        prevention = build_prevention(
            [(o.kind, b.effective_risk_level, o.result.verdict, o.result.reasons) for o, b in zip(outputs, breakdown)]
        )

        return UnifiedAnalysisResult(
            analysis_type=analysis_type,
            status="partial" if failures else "complete",
            verdict=dominant.verdict,
            risk_level=level,
            risk_score=score,
            confidence=dominant.confidence,
            reasons=_dedupe(reasons),
            evidence=evidence,
            prevention=prevention,
            next_steps=_dedupe([s for o in outputs for s in o.result.next_steps]),
            contributing_agents=[o.result.agent_name for o in outputs],
            failed_components=list(failures),
            score_breakdown=breakdown,
        )
