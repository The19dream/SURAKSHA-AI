"""Models for the Report Agent / AI Guided Reporting (Phase 4). Keep stable: the Lovable
frontend will consume IncidentReport."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .schemas import EvidenceItem, FailedComponent, UnifiedAnalysisResult, UnifiedRiskLevel

NOT_PROVIDED = "Not provided"

REPORT_DISCLAIMER = (
    "This is an AI-generated analysis/assessment produced by Suraksha AI from the automated "
    "analysis result. It is NOT an official police report or FIR, it does not establish that a "
    "crime has legally occurred, and it must be verified by the reporter and the relevant authorities."
)

INFORMATION_TO_COLLECT = [
    "Date and time of the incident",
    "Where it happened (city / platform / channel)",
    "Phone numbers, UPI IDs, account numbers, links or email addresses involved",
    "Any amount lost and the transaction reference(s), if money was sent",
    "Screenshots or copies of the original message/call details",
]


class CaseDetails(BaseModel):
    """Facts the analysis does not contain. They are never filled in by the AI."""
    victim: str = NOT_PROVIDED
    suspect: str = NOT_PROVIDED
    location: str = NOT_PROVIDED
    incident_date: str = NOT_PROVIDED


class ReportRequest(BaseModel):
    analysis: UnifiedAnalysisResult
    audit_id: Optional[str] = Field(
        None, max_length=36, description="audit_id returned by /api/analyze*, to link the report to its audit record"
    )


class IncidentReport(BaseModel):
    report_id: str
    audit_id: Optional[str] = None
    analysis_type: str
    incident_type: str
    title: str
    summary: str
    verdict: str
    risk_level: UnifiedRiskLevel
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    contributing_agents: List[str] = Field(default_factory=list)
    analysis_status: str = "complete"
    failed_components: List[FailedComponent] = Field(default_factory=list)
    case_details: CaseDetails = Field(default_factory=CaseDetails)
    information_to_collect: List[str] = Field(default_factory=lambda: list(INFORMATION_TO_COLLECT))
    disclaimer: str = REPORT_DISCLAIMER
    generated_by: str = "Suraksha AI Report Agent"
    timestamp: datetime
