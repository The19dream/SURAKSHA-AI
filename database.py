import json
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./suraksha_ai.db"

# Create engine with thread pool control for SQLite
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    input_hash = Column(String(64), index=True)  # MD5 or SHA-256 hash for anonymity & tracking
    verdict = Column(String(100))
    risk_level = Column(String(50))  # LOW, MEDIUM, HIGH, NEEDS_REVIEW
    confidence = Column(Float)
    reasons = Column(Text)  # JSON serialized list of strings
    input_text = Column(Text, nullable=True)  # Store truncated text for dashboard audit view

    def to_dict(self):
        try:
            parsed_reasons = json.loads(self.reasons) if self.reasons else []
        except Exception:
            parsed_reasons = [self.reasons] if self.reasons else []
            
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "input_hash": self.input_hash,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "confidence": round(self.confidence, 2) if self.confidence else 0.0,
            "reasons": parsed_reasons,
            "input_text": self.input_text
        }


class AnalysisAudit(Base):
    """Phase 4: one row per successful unified analysis (/api/analyze, /api/analyze/note).
    Stores metadata only: no raw user text, no image, no credentials."""
    __tablename__ = "analysis_audit"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(String(36), unique=True, index=True, nullable=False)  # public UUID
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    analysis_type = Column(String(50), index=True)
    status = Column(String(20))  # complete | partial
    verdict = Column(Text)
    risk_level = Column(String(50))
    risk_score = Column(Integer)
    confidence = Column(Float)
    contributing_agents = Column(Text)  # JSON list of agent names
    failed_components = Column(Text)  # JSON list of agent names that failed (partial runs)
    input_hash = Column(String(64), index=True)  # SHA-256 of the input, never the input itself

    def to_dict(self, report_ids=None):
        def _load(v):
            try:
                return json.loads(v) if v else []
            except Exception:
                return []

        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,  # UTC
            "analysis_type": self.analysis_type,
            "status": self.status,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 2) if self.confidence is not None else None,
            "contributing_agents": _load(self.contributing_agents),
            "failed_components": _load(self.failed_components),
            "input_hash": self.input_hash,
            "report_ids": list(report_ids or []),
        }


class GeneratedReport(Base):
    """Phase 4: a generated incident report, linked to its audit record by audit_id."""
    __tablename__ = "generated_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(36), unique=True, index=True, nullable=False)
    audit_id = Column(String(36), index=True, nullable=True)  # -> analysis_audit.audit_id
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    incident_type = Column(String(100))
    report_json = Column(Text)  # the IncidentReport as JSON


def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
