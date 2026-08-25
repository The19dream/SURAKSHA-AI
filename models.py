from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

# Scan request for incoming scam messages
class ScanRequest(BaseModel):
    text: str = Field(..., description="The body of the message or call transcript to scan")

# Hotspot Model (just for typing/API responses if needed)
class HotspotRecord(BaseModel):
    id: int
    city: str
    lat: float
    lng: float
    type: str  # UPI Fraud, Digital Arrest, Counterfeit, etc.
    date: str
    description: str

# Stats Response
class StatsResponse(BaseModel):
    total_scans: int
    high_risk_count: int
    notes_checked: int
    low_risk_count: int
    medium_risk_count: int
    needs_review_count: int
