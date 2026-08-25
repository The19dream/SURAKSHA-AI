import os
import json
import importlib

from google import genai

from .base_agent import BaseAgent, AgentResult, RiskLevel

try:
    load_dotenv = importlib.import_module("dotenv").load_dotenv
except Exception:
    # Fallback keeps the agent functional even if dotenv is unavailable.
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv()


class HotspotAgent(BaseAgent):

    def __init__(self):
        self.client = genai.Client(
            api_key=os.getenv("GEMINI_API_KEY")
        )

    @property
    def name(self) -> str:
        return "Hotspot AI"

    async def run(self, input_data: dict) -> AgentResult:

        city = input_data.get("city", "")
        crime_type = input_data.get("type", "")
        description = input_data.get("description", "")
        date = input_data.get("date", "")

        prompt = f"""
You are Suraksha AI's Cybercrime Hotspot Analysis Agent.

Analyze the following hotspot.

City:
{city}

Crime Type:
{crime_type}

Incident Date:
{date}

Description:
{description}

Return ONLY valid JSON.

Do not include markdown.

Return exactly in this format:

{{
    "verdict": "",
    "risk_level": "LOW | MEDIUM | HIGH | NEEDS_REVIEW",
    "confidence": 0.0,
    "reasons": [],
    "evidence": {{
        "city": "{city}",
        "crime_type": "{crime_type}"
    }},
    "next_steps": []
}}
"""

        response = self.client.models.generate_content(
            model="models/gemini-3.1-flash-lite",
            contents=prompt
        )

        raw_text = response.text or ""
        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            result = {
                "verdict": "Unable to parse hotspot analysis response",
                "risk_level": "NEEDS_REVIEW",
                "confidence": 0.0,
                "reasons": ["Model returned non-JSON output; manual review recommended."],
                "evidence": {
                    "city": city,
                    "crime_type": crime_type,
                    "raw_response": raw_text[:1000]
                },
                "next_steps": [
                    "Re-run the hotspot analysis.",
                    "Escalate to manual review if the issue persists."
                ]
            }

        risk_value = str(result.get("risk_level", "NEEDS_REVIEW")).upper()
        risk_level = RiskLevel[risk_value] if risk_value in RiskLevel.__members__ else RiskLevel.NEEDS_REVIEW

        return AgentResult(
            verdict=str(result.get("verdict", "Analysis unavailable")),
            risk_level=risk_level,
            confidence=float(result.get("confidence", 0.0)),
            reasons=list(result.get("reasons", [])),
            evidence=dict(result.get("evidence", {})),
            next_steps=list(result.get("next_steps", [])),
            agent_name=self.name
        )