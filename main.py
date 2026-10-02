import os
import json
import hashlib
import logging
import traceback
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from database import init_db, get_db, AuditLog
from models import ScanRequest, StatsResponse
from agents.suraksha_agent import SurakshaAgent
from agents.vision_agent import VisionAgent
from agents.mock_vision_agent import MockVisionAgent
import config
from upload_validation import read_and_validate_image
from agents.hotspot_agent import HotspotAgent
from llm_providers import (
    LLMError,
    LLMConfigError,
    LLMTimeoutError,
)
from orchestration import AllAgentsFailedError, MasterAgent, UnifiedAnalysisResult
from orchestration.schemas import AnalyzeRequest
from orchestration.report_schemas import IncidentReport, ReportRequest
from orchestration import audit
from agents.report_agent import ReportAgent
from agents.fraud_intel_agent import FraudIntelAgent
from agents.voice_agent import VoiceAgent

app = FastAPI(title="Suraksha AI — Digital Public Safety Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database tables on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Instantiate our central Orchestrator pipeline
agent = SurakshaAgent()


def build_vision_agent():
    """Real Gemini-backed agent by default; the filename mock only if explicitly enabled."""
    if config.USE_MOCK_VISION:
        logging.getLogger("suraksha").warning(
            "USE_MOCK_VISION is enabled: /api/note/check returns FILENAME-BASED MOCK results, not real analysis."
        )
        return MockVisionAgent()
    return VisionAgent()


vision_agent = build_vision_agent()
hotspot_agent = HotspotAgent()


# Phase 3: Master Agent. Agents are resolved at request time (lambdas) so it always uses the
# same current instances as the legacy routes above.
master_agent = MasterAgent()
master_agent.register("scam", lambda: agent)
master_agent.register("hotspot", lambda: hotspot_agent)
master_agent.register("note", lambda: vision_agent)

# Phase 5: Fraud Intel + Voice agents (same LLMProvider; registered on the same Master Agent).
fraud_intel_agent = FraudIntelAgent()
voice_agent = VoiceAgent()
master_agent.register("fraud_intel", lambda: fraud_intel_agent)
master_agent.register("voice", lambda: voice_agent)

# Phase 4: Report Agent (same LLM provider abstraction; attached to the Master Agent).
report_agent = ReportAgent()
master_agent.set_report_agent(lambda: report_agent)


def llm_http_error(exc: LLMError) -> HTTPException:
    """Turn a provider failure into a clean HTTP error (message is client-safe)."""
    if isinstance(exc, LLMConfigError):
        status = 503
    elif isinstance(exc, LLMTimeoutError):
        status = 504
    else:
        status = 502
    return HTTPException(status_code=status, detail=str(exc))


def save_audit_log(
    db: Session,
    *,
    input_text: str,
    input_hash: str,
    verdict: str,
    risk_level: str,
    confidence: float,
):
    audit_entry = AuditLog(
        input_text=input_text,
        input_hash=input_hash,
        verdict=verdict,
        risk_level=risk_level,
        confidence=confidence,
    )
    try:
        db.add(audit_entry)
        db.commit()
    except Exception:
        db.rollback()
        traceback.print_exc()

# --------------------------------------------------------
# STATIC ROUTE MAPPINGS (Root Level Serving)
# --------------------------------------------------------
@app.get("/")
@app.get("/index.html")
def read_index():
    return FileResponse("static/index.html")

@app.get("/scam.html")
def read_scam():
    return FileResponse("static/scam.html")

@app.get("/note.html")
def read_note():
    return FileResponse("static/note.html")

@app.get("/map.html")
def read_map():
    return FileResponse("static/map.html")

@app.get("/report.html")
def read_report():
    return FileResponse("static/report.html")

@app.get("/audit.html")
def read_audit_page():
    return FileResponse("static/audit.html")

# Direct mapping for static assets to avoid directory resolution errors
@app.get("/app.js")
def read_app_js():
    return FileResponse("static/app.js")

@app.get("/style.css")
def read_style_css():
    return FileResponse("static/style.css")

# --------------------------------------------------------
# API ENDPOINTS

from sqlalchemy.orm import Session

@app.post("/api/scam/check")
async def check_scam_message(
    payload: ScanRequest,
    db: Session = Depends(get_db)
):
    try:
        result = await agent.run({
            "text": payload.text
        })

        save_audit_log(
            db,
            input_text=payload.text,
            input_hash=hashlib.sha256(payload.text.encode("utf-8")).hexdigest(),
            verdict=result.verdict,
            risk_level=result.risk_level.value,
            confidence=result.confidence,
        )

        print(type(result))
        print(result)

        return {
            "final_verdict": result.verdict,
            "risk_level": result.risk_level.value,
            "confidence": result.confidence,
            "reasons": result.reasons,
            "evidence": result.evidence,
            "next_steps": result.next_steps,
            "pipeline_steps": {
            "reporting_complete": True
            }
        }
             

    except LLMError as exc:
        raise llm_http_error(exc)
    except Exception:
        traceback.print_exc()
        raise

    
@app.post("/api/note/check")
async def check_banknote(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Validates type, size and real content; the image stays in memory (no temp file,
    # and the client-supplied filename never touches the filesystem).
    image = await read_and_validate_image(file, config.MAX_UPLOAD_BYTES)

    try:
        result = await vision_agent.run({
            "image_bytes": image.data,
            "mime_type": image.mime_type,
            "filename": image.safe_filename,
        })
    except LLMError as exc:
        raise llm_http_error(exc)
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Banknote analysis failed unexpectedly.")

    save_audit_log(
        db,
        input_text=image.safe_filename,
        input_hash=hashlib.sha256(image.data).hexdigest(),
        verdict=result.verdict,
        risk_level=result.risk_level.value,
        confidence=result.confidence,
    )

    return {
        "verdict": result.verdict,
        "risk_level": result.risk_level.value,
        "confidence": result.confidence,
        "reasons": result.reasons,
        "evidence": result.evidence,
        "next_steps": result.next_steps
    }

@app.get("/api/hotspots")
def get_hotspots():
    """
    Fetches geo-tagged cybercrime hotspots in India.
    """
    try:
        with open("data/mock_hotspots.json", "r") as f:
            data = json.load(f)
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read hotspots database: {str(e)}")

@app.post("/api/hotspot/analyze")
async def analyze_hotspot(payload: dict):
    """
    AI analysis of a selected hotspot.
    Receives hotspot data from the frontend and returns
    a Gemini-generated risk assessment.
    """
    try:
        result = await hotspot_agent.run(payload)

        return {
            "verdict": result.verdict,
            "risk_level": result.risk_level.value,
            "confidence": result.confidence,
            "reasons": result.reasons,
            "evidence": result.evidence,
            "next_steps": result.next_steps
        }

    except LLMError as exc:
        raise llm_http_error(exc)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    

# --------------------------------------------------------
# PHASE 3: UNIFIED ANALYSIS (Master Agent -> agents -> Decision Engine). Additive.
# --------------------------------------------------------
def analysis_http_error(exc: AllAgentsFailedError) -> HTTPException:
    """Controlled error naming the failed component(s); no fake result is ever returned."""
    first = exc.failures[0].exc
    if isinstance(first, LLMError):
        status = llm_http_error(first).status_code
    elif isinstance(first, ValueError):
        status = 422
    else:
        status = 500
    return HTTPException(
        status_code=status,
        detail={
            "message": "Analysis failed.",
            "failed_components": [f.as_component().model_dump() for f in exc.failures],
        },
    )


@app.post("/api/analyze", response_model=UnifiedAnalysisResult)
async def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """Unified analysis for JSON inputs: analysis_type 'scam', 'hotspot', 'fraud_intel' or 'voice'."""
    input_data = payload.input.model_dump()
    try:
        result = await master_agent.analyze(payload.analysis_type, input_data)
    except AllAgentsFailedError as exc:
        raise analysis_http_error(exc)  # failed analyses are not audited as results
    hashed = input_data["text"] if payload.analysis_type == "scam" else input_data
    result.audit_id = audit.record_analysis(db, result, audit.hash_input(payload.analysis_type, hashed))
    return result


@app.post("/api/analyze/note", response_model=UnifiedAnalysisResult)
async def analyze_note(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Unified analysis for a banknote image (same upload validation as /api/note/check)."""
    image = await read_and_validate_image(file, config.MAX_UPLOAD_BYTES)
    try:
        result = await master_agent.analyze(
            "note",
            {"image_bytes": image.data, "mime_type": image.mime_type, "filename": image.safe_filename},
        )
    except AllAgentsFailedError as exc:
        raise analysis_http_error(exc)
    result.audit_id = audit.record_analysis(db, result, audit.hash_input("note", image.data))
    return result


# --------------------------------------------------------
# PHASE 4: REPORT AGENT + AUDIT TRAIL (additive)
# --------------------------------------------------------
@app.post("/api/report", response_model=IncidentReport)
async def create_report(payload: ReportRequest, db: Session = Depends(get_db)):
    """AI-guided incident report from an existing unified analysis (optionally linked by audit_id)."""
    a = payload.analysis
    if payload.audit_id:
        rec = audit.get_audit(db, payload.audit_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="Unknown audit_id.")
        if (rec.analysis_type, rec.verdict, rec.risk_level, rec.risk_score) != (
            a.analysis_type, a.verdict, a.risk_level.value, a.risk_score
        ):
            raise HTTPException(status_code=409, detail="The analysis does not match the audit record.")
    try:
        report = await master_agent.generate_report(a, payload.audit_id)
    except LLMError as exc:
        raise HTTPException(
            status_code=llm_http_error(exc).status_code,
            detail={
                "message": "Report generation failed.",
                "failed_components": [
                    {"agent": report_agent.name, "analysis_type": a.analysis_type, "error": str(exc)}
                ],
            },
        )
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Report generation failed unexpectedly.")
    audit.record_report(db, report)
    return report


@app.get("/api/reports/{report_id}", response_model=IncidentReport)
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = audit.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@app.get("/api/audit-trail")
def unified_audit_trail(limit: int = 50, db: Session = Depends(get_db)):
    """Unified-analysis audit entries (newest first), each with the ids of reports generated from it."""
    return audit.list_audit(db, max(1, min(limit, 200)))


@app.get("/api/sample-messages")
def get_sample_messages():
    """
    Exposes demo message files for quick dropdown loading.
    """
    try:
        with open("data/sample_messages.json", "r") as f:
            data = json.load(f)
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read sample files: {str(e)}")

@app.get("/api/audit-log")
def get_audit_trail(db: Session = Depends(get_db)):
    """
    Retrieves the last 50 audit records sorted by descending timestamp.
    """
    try:
    
        # Retrieve the results
        logs_list = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
        return [log.to_dict() for log in logs_list]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query audit trail: {str(e)}")

@app.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Computes total assessed counts and risk aggregates.
    Includes historical mock baseline so the dashboard is instantly active.
    """
    try:
        # DB queries
        real_total = db.query(AuditLog).count()
        real_high = db.query(AuditLog).filter(AuditLog.risk_level == "HIGH").count()
        real_medium = db.query(AuditLog).filter(AuditLog.risk_level == "MEDIUM").count()
        real_low = db.query(AuditLog).filter(AuditLog.risk_level == "LOW").count()
        real_review = db.query(AuditLog).filter(AuditLog.risk_level == "NEEDS_REVIEW").count()
        
        # Calculate banknote notes checked (identified by mock prefix or image file logs)
        real_notes = db.query(AuditLog).filter(AuditLog.input_text.like("[%Banknote%")).count()

        # Hackathon Demo baseline counters
        stats_response = {
            "total_scans": real_total + 184,
            "high_risk_count": real_high + 42,
            "medium_risk_count": real_medium + 64,
            "low_risk_count": real_low + 71,
            "needs_review_count": real_review + 7,
            "notes_checked": real_notes + 52
        }
        return JSONResponse(content=stats_response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Statistics aggregation failure: {str(e)}")

@app.get("/api/health")
def health_check():
    return {"status": "ok", "app": "Suraksha AI"}
