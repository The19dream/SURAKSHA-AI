"""Request / response models for the unified analysis API (Phase 3)."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


class UnifiedRiskLevel(str, Enum):
    """Decision Engine risk levels. CRITICAL exists only here; agents still emit
    LOW / MEDIUM / HIGH / NEEDS_REVIEW (``agents.base_agent.RiskLevel`` is unchanged)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NEEDS_REVIEW = "NEEDS_REVIEW"


# ---------------------------------------------------------------- requests
class ScamInput(BaseModel):
    text: str = Field(..., max_length=10_000, description="Message / call transcript to scan")

    @field_validator("text")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("text must not be empty")
        return v


class HotspotInput(BaseModel):
    city: str = Field(..., min_length=1, max_length=200)
    type: str = Field("", max_length=200)
    description: str = Field("", max_length=5_000)
    date: str = Field("", max_length=100)


class FraudIntelInput(BaseModel):
    """User-supplied indicators. At least one must be non-empty. Nothing is looked up externally."""

    message: Optional[str] = Field(None, max_length=10_000, description="Scam message / text")
    phone_number: Optional[str] = Field(None, max_length=50)
    upi_id: Optional[str] = Field(None, max_length=256)
    email: Optional[str] = Field(None, max_length=320)
    url: Optional[str] = Field(None, max_length=2_048)
    transaction: Optional[str] = Field(None, max_length=2_000, description="Free-text transaction details")
    keywords: List[Annotated[str, Field(max_length=100)]] = Field(default_factory=list, max_length=50)
    other_indicators: List[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=20)

    @field_validator("message", "phone_number", "upi_id", "email", "url", "transaction")
    @classmethod
    def _strip_blank_to_none(cls, v: Optional[str]) -> Optional[str]:
        v = v.strip() if isinstance(v, str) else v
        return v or None

    @field_validator("keywords", "other_indicators")
    @classmethod
    def _drop_blank_items(cls, v: List[str]) -> List[str]:
        return [i.strip() for i in v if i and i.strip()]

    @model_validator(mode="after")
    def _at_least_one(self):
        if not any([self.message, self.phone_number, self.upi_id, self.email, self.url,
                    self.transaction, self.keywords, self.other_indicators]):
            raise ValueError("provide at least one non-empty indicator")
        return self


class ConversationTurn(BaseModel):
    speaker: str = Field("Speaker", max_length=50)
    text: str = Field(..., max_length=5_000)


class VoiceInput(BaseModel):
    """Call TRANSCRIPT text (not audio). Provide exactly one of transcript / conversation."""

    transcript: Optional[str] = Field(None, max_length=10_000)
    conversation: Optional[List[ConversationTurn]] = Field(None, max_length=200)

    @field_validator("transcript")
    @classmethod
    def _strip_blank_to_none(cls, v: Optional[str]) -> Optional[str]:
        v = v.strip() if isinstance(v, str) else v
        return v or None

    @model_validator(mode="after")
    def _exactly_one(self):
        convo = [t for t in (self.conversation or []) if t.text.strip()]
        if self.transcript and convo:
            raise ValueError("provide either transcript or conversation, not both")
        if not self.transcript and not convo:
            raise ValueError("provide a non-empty transcript or conversation")
        if convo and sum(len(t.text) + len(t.speaker) + 2 for t in convo) > 10_000:
            raise ValueError("conversation is too long (max 10000 characters in total)")
        return self


class ScamAnalysisRequest(BaseModel):
    analysis_type: Literal["scam"]
    input: ScamInput


class HotspotAnalysisRequest(BaseModel):
    analysis_type: Literal["hotspot"]
    input: HotspotInput


class FraudIntelAnalysisRequest(BaseModel):
    analysis_type: Literal["fraud_intel"]
    input: FraudIntelInput


class VoiceAnalysisRequest(BaseModel):
    analysis_type: Literal["voice"]
    input: VoiceInput


# Banknote images arrive as multipart on POST /api/analyze/note, so "note" is not in this union.
AnalyzeRequest = Annotated[
    Union[ScamAnalysisRequest, HotspotAnalysisRequest, FraudIntelAnalysisRequest, VoiceAnalysisRequest],
    Field(discriminator="analysis_type"),
]


# --------------------------------------------------------------- responses
class EvidenceItem(BaseModel):
    agent: str
    field: str
    value: Any


class ScoreBreakdownItem(BaseModel):
    agent: str
    analysis_type: str
    agent_risk_level: str
    confidence: float
    effective_risk_level: UnifiedRiskLevel
    score: int = Field(..., ge=0, le=100)
    note: Optional[str] = None


class FailedComponent(BaseModel):
    agent: str
    analysis_type: str
    error: str


PROTOTYPE_DISCLAIMER = (
    "Prototype risk score (0-100) computed by simple, documented rules from the agents' own "
    "risk level and confidence. It is not scientifically validated and is not an official "
    "crime or fraud probability."
)


class UnifiedAnalysisResult(BaseModel):
    analysis_type: str
    audit_id: Optional[str] = None  # set by the API after the audit row is written
    status: Literal["complete", "partial"] = "complete"
    verdict: str
    risk_level: UnifiedRiskLevel
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    contributing_agents: List[str] = Field(default_factory=list)
    failed_components: List[FailedComponent] = Field(default_factory=list)
    score_breakdown: List[ScoreBreakdownItem] = Field(default_factory=list)
    score_disclaimer: str = PROTOTYPE_DISCLAIMER
