import os
import json
import shutil
import hashlib
import traceback
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from database import init_db, get_db, AuditLog
from models import ScanRequest, StatsResponse
from agents.suraksha_agent import SurakshaAgent
from agents.vision_agent import VisionAgent
from agents.hotspot_agent import HotspotAgent

app = FastAPI(title="Suraksha AI — Digital Public Safety Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database tables on startup
@app.on_event("startup")
def startup_event():
    init_db()
    # Ensure a local directory exists for temporary upload assets
    os.makedirs("./temp_uploads", exist_ok=True)

# Instantiate our central Orchestrator pipeline
agent = SurakshaAgent()
vision_agent = VisionAgent()
hotspot_agent = HotspotAgent()


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
             
             
             
    except Exception:
        traceback.print_exc()
        raise

    
@app.post("/api/note/check")
async def check_banknote(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    try:

        temp_path = f"./temp_uploads/{file.filename}"

        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = await vision_agent.run({
            "image_path": temp_path
        })

        try:
            with open(temp_path, "rb") as image_file:
                image_bytes = image_file.read()

            save_audit_log(
                db,
                input_text=file.filename or "uploaded_banknote_image",
                input_hash=hashlib.sha256(image_bytes).hexdigest(),
                verdict=result.verdict,
                risk_level=result.risk_level.value,
                confidence=result.confidence,
            )
        except Exception:
            traceback.print_exc()

        if os.path.exists(temp_path):
            os.remove(temp_path)

        return {
            "verdict": result.verdict,
            "risk_level": result.risk_level.value,
            "confidence": result.confidence,
            "reasons": result.reasons,
            "evidence": result.evidence,
            "next_steps": result.next_steps
        }

    except Exception as e:

        if os.path.exists(temp_path):
            os.remove(temp_path)

        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

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

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    

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
