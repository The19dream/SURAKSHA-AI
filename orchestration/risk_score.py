"""Transparent prototype risk score. All tunable numbers live in this file.

PROTOTYPE ONLY: not scientifically validated, not an official crime/fraud probability.

Per agent (confidence c in 0..1, from the agent's own output):
    agent LOW           score = 25 * (1 - c)      (more confident it is safe -> lower score)
    agent MEDIUM        score = 30 + 25 * c       (30..55)
    agent HIGH          score = 60 + 35 * c       (60..95)
    agent NEEDS_REVIEW  score = NEEDS_REVIEW_SCORE (neutral placeholder, not a measurement)
    agent LOW with c < LOW_MIN_CONFIDENCE is treated as NEEDS_REVIEW (a weak "looks fine"
    is not accepted as safe).

Score -> level bands:  <30 LOW | <60 MEDIUM | <90 HIGH | >=90 CRITICAL
Combining several agents: the highest score wins. If the winner is LOW but any agent was
NEEDS_REVIEW (or failed), the overall level becomes NEEDS_REVIEW: safety is never claimed
on partial information.
"""
from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .schemas import ScoreBreakdownItem, UnifiedRiskLevel

L = UnifiedRiskLevel

LOW_MIN_CONFIDENCE = 0.5
NEEDS_REVIEW_SCORE = 50
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 90


def _clamp_conf(c: float) -> float:
    try:
        return max(0.0, min(1.0, float(c)))
    except (TypeError, ValueError):
        return 0.0


def level_from_score(score: int) -> UnifiedRiskLevel:
    if score >= CRITICAL_THRESHOLD:
        return L.CRITICAL
    if score >= HIGH_THRESHOLD:
        return L.HIGH
    if score >= MEDIUM_THRESHOLD:
        return L.MEDIUM
    return L.LOW


def score_agent(agent_risk_level: str, confidence: float) -> Tuple[int, UnifiedRiskLevel, Optional[str]]:
    """Return (score, effective_level, note) for one agent's output."""
    level = str(agent_risk_level).upper()
    c = _clamp_conf(confidence)

    if level == "LOW":
        if c < LOW_MIN_CONFIDENCE:
            return (
                NEEDS_REVIEW_SCORE,
                L.NEEDS_REVIEW,
                f"Agent said LOW but confidence {c:.2f} is below {LOW_MIN_CONFIDENCE}; treated as NEEDS_REVIEW.",
            )
        score = round(25 * (1 - c))
    elif level == "MEDIUM":
        score = round(30 + 25 * c)
    elif level == "HIGH":
        score = round(60 + 35 * c)
    else:  # NEEDS_REVIEW or anything unrecognised
        return NEEDS_REVIEW_SCORE, L.NEEDS_REVIEW, None

    score = max(0, min(100, score))
    return score, level_from_score(score), None


def combine(items: Sequence[ScoreBreakdownItem], has_failures: bool = False) -> Tuple[int, UnifiedRiskLevel, ScoreBreakdownItem]:
    """Combine per-agent scores. Returns (score, level, dominant item)."""
    if not items:
        raise ValueError("No agent results to combine.")
    scored: List[ScoreBreakdownItem] = [i for i in items if i.effective_risk_level != L.NEEDS_REVIEW]
    if not scored:
        return NEEDS_REVIEW_SCORE, L.NEEDS_REVIEW, items[0]

    top = max(scored, key=lambda i: i.score)
    level = level_from_score(top.score)
    unresolved = has_failures or len(scored) < len(items)
    if level == L.LOW and unresolved:
        return NEEDS_REVIEW_SCORE, L.NEEDS_REVIEW, top
    return top.score, level, top
