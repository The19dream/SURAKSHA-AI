from llm_providers import LLMResponseError

from .base_agent import AgentResult
from .llm_agent import LLMAgent, build_agent_result


class HotspotAgent(LLMAgent):

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

        try:
            result = await self.llm.generate_json(prompt)
        except LLMResponseError as exc:
            raw_text = exc.raw_text
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

        return build_agent_result(result, self.name)
