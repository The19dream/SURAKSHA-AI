import os
import json

from dotenv import load_dotenv
from google import genai

from .base_agent import BaseAgent, AgentResult, RiskLevel

load_dotenv()


class SurakshaAgent(BaseAgent):

    def __init__(self):
        self.client = genai.Client(
            api_key=os.getenv("GEMINI_API_KEY")
        )

    @property
    def name(self):
        return "Suraksha AI"

    async def run(self, input_data: dict):

        message = input_data.get("text", "").strip()

        if not message:
            raise ValueError("No message provided.")

        prompt = f"""
You are Suraksha AI.

You are an expert in detecting:

1. Digital arrest scams
2. UPI fraud
3. Banking fraud
4. OTP scams
5. Fake police scams
6. Fake courier scams
7. Phishing attacks

Analyze the following message carefully.

MESSAGE:
{message}

Return ONLY valid JSON.

Do not include markdown.
Do not include explanation.
Return only the JSON object.

Format:

{{
    "verdict": "",
    "risk_level": "LOW | MEDIUM | HIGH | NEEDS_REVIEW",
    "confidence": 0.0,
    "reasons": [],
    "evidence": {{}},
    "next_steps": []
}}
"""

        response = self.client.models.generate_content(
            model="models/gemini-3.1-flash-lite",
            contents=prompt
        )

        result = json.loads(response.text)

        return AgentResult(
            verdict=result["verdict"],
            risk_level=RiskLevel[result["risk_level"]],
            confidence=result["confidence"],
            reasons=result["reasons"],
            evidence=result["evidence"],
            next_steps=result["next_steps"],
            agent_name=self.name
        )