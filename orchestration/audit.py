"""Audit trail for the unified pipeline (Phase 4). Metadata only: never raw user text, images
or credentials. Write failures are logged and never turn a finished analysis into an error."""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from database import AnalysisAudit, GeneratedReport

from .report_schemas import IncidentReport
from .schemas import UnifiedAnalysisResult

logger = logging.getLogger("suraksha.audit")


def hash_input(analysis_type: str, input_data) -> str:
    """SHA-256 of the input (text, image bytes, or canonical JSON). The input is not stored."""
    if isinstance(input_data, (bytes, bytearray)):
        raw = bytes(input_data)
    elif isinstance(input_data, str):
        raw = input_data.strip().encode("utf-8")
    else:
        raw = json.dumps(input_data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def record_analysis(db: Session, result: UnifiedAnalysisResult, input_hash: str) -> Optional[str]:
    """Insert one audit row for a completed analysis. Returns its audit_id, or None if the write failed."""
    audit_id = str(uuid.uuid4())
    try:
        db.add(AnalysisAudit(
            audit_id=audit_id,
            analysis_type=result.analysis_type,
            status=result.status,
            verdict=result.verdict,
            risk_level=result.risk_level.value,
            risk_score=result.risk_score,
            confidence=result.confidence,
            contributing_agents=json.dumps(result.contributing_agents),
            failed_components=json.dumps([f.agent for f in result.failed_components]),
            input_hash=input_hash,
        ))
        db.commit()
        return audit_id
    except Exception:
        db.rollback()
        logger.exception("Failed to write analysis audit row")
        return None


def get_audit(db: Session, audit_id: str) -> Optional[AnalysisAudit]:
    return db.query(AnalysisAudit).filter(AnalysisAudit.audit_id == audit_id).first()


def record_report(db: Session, report: IncidentReport) -> bool:
    try:
        db.add(GeneratedReport(
            report_id=report.report_id,
            audit_id=report.audit_id,
            incident_type=report.incident_type,
            report_json=report.model_dump_json(),
        ))
        db.commit()
        return True
    except Exception:
        db.rollback()
        logger.exception("Failed to store generated report")
        return False


def list_audit(db: Session, limit: int = 50) -> List[dict]:
    rows = db.query(AnalysisAudit).order_by(AnalysisAudit.id.desc()).limit(limit).all()
    ids = [r.audit_id for r in rows]
    by_audit: dict = {}
    if ids:
        for rep in db.query(GeneratedReport).filter(GeneratedReport.audit_id.in_(ids)).order_by(GeneratedReport.id):
            by_audit.setdefault(rep.audit_id, []).append(rep.report_id)
    return [r.to_dict(by_audit.get(r.audit_id)) for r in rows]


def get_report(db: Session, report_id: str) -> Optional[IncidentReport]:
    row = db.query(GeneratedReport).filter(GeneratedReport.report_id == report_id).first()
    return IncidentReport.model_validate_json(row.report_json) if row else None
