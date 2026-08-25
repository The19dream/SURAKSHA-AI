import os
import json
from datetime import datetime

from dotenv import load_dotenv
from google import genai

from .base_agent import BaseAgent, AgentResult, RiskLevel

load_dotenv()


class VisionAgent(BaseAgent):

    def __init__(self):
        self.client = genai.Client(
            api_key=os.getenv("GEMINI_API_KEY")
        )

    @property
    def name(self):
        return "Vision AI"

    async def run(self, input_data: dict):

        image_path = input_data.get("image_path")

        if not image_path:
            raise ValueError("No image path provided.")

        if not os.path.exists(image_path):
            raise FileNotFoundError(image_path)

        with open(image_path, "rb") as f:
            image_bytes = f.read()

        prompt = """
You are Suraksha Vision AI.

You are an RBI banknote verification expert.

Analyze the uploaded Indian currency note carefully.

Check the following:

1. Security thread
2. Watermark
3. Microlettering
4. Serial number
5. Latent image
6. See-through register
7. Print quality
8. Color consistency
9. Signs of tampering
10. Overall authenticity

Return ONLY valid JSON.

No markdown.

No explanation.

Format:

{
    "verdict":"",
    "risk_level":"LOW",
    "confidence":0.95,
    "reasons":[],
    "evidence":{
        "security_thread":"",
        "watermark":"",
        "serial_number":"",
        "microlettering":"",
        "print_quality":"",
        "overall_condition":""
    },
    "next_steps":[]
}
"""
        response = self.client.models.generate_content(
            model="models/gemini-3.1-flash-lite",
            contents=[
                prompt,
                {
                    "mime_type": "image/jpeg",
                    "data": image_bytes
                }
            ]
        )

        result = json.loads(response.text)
        risk = result.get("risk_level", "NEEDS_REVIEW").upper()

        if risk not in RiskLevel.__members__:
            risk = "NEEDS_REVIEW"

        return AgentResult(
            verdict=result.get(
                "verdict",
                "Unable to determine authenticity."
            ),
            risk_level=RiskLevel[risk],
            confidence=float(result.get("confidence", 0.5)),
            reasons=result.get(
                "reasons",
                []
            ),
            evidence=result.get(
                "evidence",
                {}
            ),
            next_steps=result.get(
                "next_steps",
                [
                    "Please consult your nearest bank for manual verification."
                ]
            ),
            agent_name=self.name,
            timestamp=datetime.utcnow()
        )