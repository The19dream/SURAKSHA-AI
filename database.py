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

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
