from .llm_agent import LLMAgent, build_agent_result


class SurakshaAgent(LLMAgent):

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

        result = await self.llm.generate_json(prompt)

        return build_agent_result(result, self.name)
