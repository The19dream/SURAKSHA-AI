"""
Agent tests using a fake LLMProvider (no network, no API key).
Requires pydantic (already a project dependency); skipped if unavailable.
Run from the project root:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pydantic  # noqa: F401
    HAVE_PYDANTIC = True
except ImportError:
    HAVE_PYDANTIC = False

from llm_providers import (  # noqa: E402
    LLMConfigError,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    LLMResponseError,
)


def run(coro):
    return asyncio.run(coro)


class FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, text=None, exc=None):
        self.text, self.exc, self.calls = text, exc, []

    async def generate(self, prompt, *, images=()):
        self.calls.append({"prompt": prompt, "images": list(images)})
        if self.exc:
            raise self.exc
        return LLMResponse(text=self.text, provider="fake", model="fake-1")


GOOD = (
    '{"verdict": "Digital Arrest Scam", "risk_level": "HIGH", "confidence": 0.97,'
    ' "reasons": ["Impersonates CBI"], "evidence": {"keywords": ["warrant"]},'
    ' "next_steps": ["Hang up"]}'
)


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic not installed")
class SurakshaAgentTests(unittest.TestCase):
    def setUp(self):
        from agents.suraksha_agent import SurakshaAgent
        self.Agent = SurakshaAgent

    def test_maps_provider_json_to_agent_result(self):
        fake = FakeProvider(GOOD)
        r = run(self.Agent(llm=fake).run({"text": "You have a warrant"}))
        self.assertEqual(r.verdict, "Digital Arrest Scam")
        self.assertEqual(r.risk_level.value, "HIGH")
        self.assertEqual(r.confidence, 0.97)
        self.assertEqual(r.reasons, ["Impersonates CBI"])
        self.assertEqual(r.evidence, {"keywords": ["warrant"]})
        self.assertEqual(r.next_steps, ["Hang up"])
        self.assertEqual(r.agent_name, "Suraksha AI")
        self.assertIn("You have a warrant", fake.calls[0]["prompt"])

    def test_tolerates_fenced_json_and_lowercase_risk(self):
        text = '```json\n{"verdict": "v", "risk_level": "medium", "confidence": 0.5}\n```'
        r = run(self.Agent(llm=FakeProvider(text)).run({"text": "x"}))
        self.assertEqual(r.risk_level.value, "MEDIUM")
        self.assertEqual(r.reasons, [])

    def test_unknown_risk_level_becomes_needs_review_and_confidence_clamped(self):
        text = '{"verdict": "v", "risk_level": "CRITICAL", "confidence": 7}'
        r = run(self.Agent(llm=FakeProvider(text)).run({"text": "x"}))
        self.assertEqual(r.risk_level.value, "NEEDS_REVIEW")
        self.assertEqual(r.confidence, 1.0)

    def test_empty_message_still_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(self.Agent(llm=FakeProvider(GOOD)).run({"text": "   "}))

    def test_malformed_reply_propagates_clean_error(self):
        with self.assertRaises(LLMResponseError):
            run(self.Agent(llm=FakeProvider("sorry, cannot help")).run({"text": "x"}))

    def test_provider_errors_propagate(self):
        for exc in (LLMConfigError(), LLMProviderError()):
            with self.assertRaises(type(exc)):
                run(self.Agent(llm=FakeProvider(exc=exc)).run({"text": "x"}))

    def test_no_key_at_construction_time(self):
        self.Agent()  # must not need a provider/key until run()


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic not installed")
class HotspotAgentTests(unittest.TestCase):
    def setUp(self):
        from agents.hotspot_agent import HotspotAgent
        self.Agent = HotspotAgent
        self.payload = {"city": "Jamtara", "type": "UPI Fraud", "date": "2026-07-14", "description": "d"}

    def test_success(self):
        r = run(self.Agent(llm=FakeProvider(GOOD)).run(self.payload))
        self.assertEqual(r.agent_name, "Hotspot AI")
        self.assertEqual(r.risk_level.value, "HIGH")

    def test_malformed_reply_keeps_existing_needs_review_fallback(self):
        r = run(self.Agent(llm=FakeProvider("garbage")).run(self.payload))
        self.assertEqual(r.risk_level.value, "NEEDS_REVIEW")
        self.assertEqual(r.confidence, 0.0)
        self.assertEqual(r.verdict, "Unable to parse hotspot analysis response")
        self.assertEqual(r.evidence["raw_response"], "garbage")
        self.assertEqual(r.evidence["city"], "Jamtara")
        self.assertEqual(len(r.next_steps), 2)

    def test_provider_failure_is_not_swallowed(self):
        with self.assertRaises(LLMProviderError):
            run(self.Agent(llm=FakeProvider(exc=LLMProviderError())).run(self.payload))


VISION_GOOD = (
    '{"verdict": "Likely genuine", "risk_level": "low", "confidence": 1.4,'
    ' "reasons": ["Thread present"], "evidence": {"serial_number": "1AB123456"},'
    ' "next_steps": ["Still verify at a bank"]}'
)


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic not installed")
class VisionAgentTests(unittest.TestCase):
    def setUp(self):
        from agents.vision_agent import VisionAgent
        self.Agent = VisionAgent

    def test_sends_image_part_and_maps_result(self):
        fake = FakeProvider(VISION_GOOD)
        r = run(self.Agent(llm=fake).run({"image_bytes": b"\x89PNGdata", "mime_type": "image/png"}))
        img = fake.calls[0]["images"][0]
        self.assertEqual((img.data, img.mime_type), (b"\x89PNGdata", "image/png"))
        self.assertEqual(r.risk_level.value, "LOW")        # case-insensitive
        self.assertEqual(r.confidence, 1.0)                # clamped
        self.assertEqual(r.evidence["serial_number"], "1AB123456")

    def test_unknown_risk_level_becomes_needs_review(self):
        fake = FakeProvider('{"verdict": "x", "risk_level": "bogus"}')
        r = run(self.Agent(llm=fake).run({"image_bytes": b"d", "mime_type": "image/jpeg"}))
        self.assertEqual(r.risk_level.value, "NEEDS_REVIEW")
        self.assertEqual(r.next_steps, ["Please consult your nearest bank for manual verification."])

    def test_json_without_verdict_or_risk_is_malformed(self):
        for text in ("{}", '{"reasons": ["x"]}', '{"verdict": "x"}'):
            with self.assertRaises(LLMResponseError):
                run(self.Agent(llm=FakeProvider(text)).run({"image_bytes": b"d", "mime_type": "image/png"}))

    def test_non_json_reply_raises_response_error(self):
        with self.assertRaises(LLMResponseError):
            run(self.Agent(llm=FakeProvider("sorry, cannot help")).run({"image_bytes": b"d", "mime_type": "image/png"}))

    def test_rejects_missing_data_and_bad_mime(self):
        agent = self.Agent(llm=FakeProvider(VISION_GOOD))
        with self.assertRaises(ValueError):
            run(agent.run({"mime_type": "image/png"}))
        with self.assertRaises(ValueError):
            run(agent.run({"image_bytes": b"d", "mime_type": "text/html"}))

    def test_provider_error_propagates(self):
        with self.assertRaises(LLMProviderError):
            run(self.Agent(llm=FakeProvider(exc=LLMProviderError())).run({"image_bytes": b"d", "mime_type": "image/png"}))

    def test_no_filesystem_or_sdk_use_in_agent_module(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents", "vision_agent.py")).read()
        self.assertNotIn("google", src)
        self.assertNotIn("open(", src)


if __name__ == "__main__":
    unittest.main()
