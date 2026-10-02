"""Phase 3 tests: Master Agent, Decision Engine, risk score, prevention, /api/analyze*.
All AI is faked (no Gemini, no network, no key). These verify logic and wiring, not model quality.
Run from the project root:  python -m unittest discover -s tests -v
"""
import asyncio
import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    from PIL import Image
    HAVE_API_DEPS = True
except ImportError:
    HAVE_API_DEPS = False

from agents.base_agent import AgentResult, BaseAgent, RiskLevel  # noqa: E402
from llm_providers import LLMConfigError, LLMProvider, LLMResponse, LLMTimeoutError  # noqa: E402
from orchestration import (  # noqa: E402
    AgentOutput, AllAgentsFailedError, DecisionEngine, MasterAgent, UnifiedRiskLevel, UnknownAnalysisType,
)
from orchestration import prevention, risk_score  # noqa: E402
from orchestration.schemas import FailedComponent  # noqa: E402

L = UnifiedRiskLevel


def run(coro):
    return asyncio.run(coro)


def result(level="HIGH", conf=0.9, verdict="V", reasons=("r1",), evidence=None, steps=("s1",), name="Agent"):
    return AgentResult(
        verdict=verdict, risk_level=RiskLevel[level], confidence=conf, reasons=list(reasons),
        evidence=evidence or {}, next_steps=list(steps), agent_name=name,
    )


class StubAgent(BaseAgent):
    def __init__(self, name, res=None, exc=None):
        self._name, self.res, self.exc, self.inputs = name, res, exc, []

    @property
    def name(self):
        return self._name

    async def run(self, input_data):
        self.inputs.append(input_data)
        if self.exc:
            raise self.exc
        return self.res


# ------------------------------------------------------------------ risk score
class RiskScoreTests(unittest.TestCase):
    def test_agent_score_values(self):
        self.assertEqual(risk_score.score_agent("LOW", 1.0)[0], 0)
        self.assertEqual(risk_score.score_agent("LOW", 0.5)[0], 12)
        self.assertEqual(risk_score.score_agent("MEDIUM", 0.0)[0], 30)
        self.assertEqual(risk_score.score_agent("MEDIUM", 1.0)[0], 55)
        self.assertEqual(risk_score.score_agent("HIGH", 0.0)[0], 60)
        self.assertEqual(risk_score.score_agent("HIGH", 0.5)[0], 78)
        self.assertEqual(risk_score.score_agent("HIGH", 1.0)[0], 95)
        self.assertEqual(risk_score.score_agent("NEEDS_REVIEW", 0.9)[0], risk_score.NEEDS_REVIEW_SCORE)

    def test_levels(self):
        cases = [("LOW", 1.0, L.LOW), ("LOW", 0.5, L.LOW), ("MEDIUM", 0.0, L.MEDIUM), ("MEDIUM", 1.0, L.MEDIUM),
                 ("HIGH", 0.0, L.HIGH), ("HIGH", 0.7, L.HIGH), ("HIGH", 0.9, L.CRITICAL), ("HIGH", 1.0, L.CRITICAL),
                 ("NEEDS_REVIEW", 0.9, L.NEEDS_REVIEW)]
        for lvl, c, expected in cases:
            self.assertEqual(risk_score.score_agent(lvl, c)[1], expected, (lvl, c))

    def test_level_bands(self):
        self.assertEqual(risk_score.level_from_score(29), L.LOW)
        self.assertEqual(risk_score.level_from_score(30), L.MEDIUM)
        self.assertEqual(risk_score.level_from_score(59), L.MEDIUM)
        self.assertEqual(risk_score.level_from_score(60), L.HIGH)
        self.assertEqual(risk_score.level_from_score(89), L.HIGH)
        self.assertEqual(risk_score.level_from_score(90), L.CRITICAL)

    def test_weak_low_is_needs_review(self):
        score, level, note = risk_score.score_agent("LOW", 0.3)
        self.assertEqual(level, L.NEEDS_REVIEW)
        self.assertIsNotNone(note)

    def test_bad_confidence_clamped(self):
        self.assertEqual(risk_score.score_agent("HIGH", 5)[0], 95)
        self.assertEqual(risk_score.score_agent("HIGH", -1)[0], 60)

    def test_score_always_in_range(self):
        for lvl in ("LOW", "MEDIUM", "HIGH", "NEEDS_REVIEW"):
            for c in (0, 0.25, 0.5, 0.75, 1):
                self.assertTrue(0 <= risk_score.score_agent(lvl, c)[0] <= 100)


# ------------------------------------------------------------------ prevention
class PreventionTests(unittest.TestCase):
    def joined(self, *a):
        return " ".join(prevention.advice_for(*a))

    def test_scam_high(self):
        text = self.joined("scam", L.HIGH, "Digital Arrest Scam", ["Claims a warrant"])
        for needle in ("Do not transfer money", "OTP", "bank", "Report"):
            self.assertIn(needle, text)
        self.assertIn("hang up", text)  # topic tip triggered by the agent's own words

    def test_topic_tip_only_when_mentioned(self):
        text = self.joined("scam", L.HIGH, "Phishing link", ["Fake bank site"])
        self.assertNotIn("hang up", text)
        self.assertNotIn("UPI", text)

    def test_scam_low_does_not_tell_to_report(self):
        text = self.joined("scam", L.LOW, "Looks genuine", [])
        self.assertNotIn("Report", text)
        self.assertNotIn("Do not transfer", text)

    def test_note_always_requires_physical_check(self):
        for lvl in (L.LOW, L.MEDIUM, L.HIGH, L.CRITICAL, L.NEEDS_REVIEW):
            self.assertIn("Do not rely only on an uploaded image", self.joined("note", lvl, "v", []))

    def test_note_elevated_vs_low(self):
        self.assertIn("counterfeit", self.joined("note", L.HIGH, "v", []))
        self.assertNotIn("counterfeit", self.joined("note", L.LOW, "v", []))

    def test_hotspot_high(self):
        text = self.joined("hotspot", L.HIGH, "v", [])
        self.assertIn("additional caution", text)
        self.assertIn("personal information", text)

    def test_unknown_kind_gives_nothing(self):
        self.assertEqual(prevention.advice_for("not_a_real_kind", L.HIGH, "v", []), [])

    def test_merge_dedupes(self):
        out = prevention.build_prevention([("scam", L.HIGH, "v", []), ("scam", L.HIGH, "v", [])])
        self.assertEqual(len(out), len(set(out)))


# --------------------------------------------------------------- decision engine
class DecisionEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = DecisionEngine()

    def test_single_agent_output_shape(self):
        r = result("HIGH", 0.97, "Digital Arrest Scam", ["Impersonates CBI"], {"keywords": ["warrant"], "empty": ""}, ["Hang up"], "Suraksha AI")
        out = self.engine.decide("scam", [AgentOutput("scam", r)])
        self.assertEqual(out.verdict, "Digital Arrest Scam")
        self.assertEqual(out.risk_level, L.CRITICAL)
        self.assertEqual(out.risk_score, 94)
        self.assertEqual(out.confidence, 0.97)
        self.assertEqual(out.reasons, ["Impersonates CBI"])
        self.assertEqual(out.next_steps, ["Hang up"])
        self.assertEqual(out.contributing_agents, ["Suraksha AI"])
        self.assertEqual(out.status, "complete")
        self.assertEqual([(e.agent, e.field, e.value) for e in out.evidence], [("Suraksha AI", "keywords", ["warrant"])])
        self.assertTrue(out.prevention)
        self.assertIn("not scientifically validated", out.score_disclaimer)

    def test_no_invented_evidence(self):
        out = self.engine.decide("scam", [AgentOutput("scam", result("MEDIUM", 0.6, evidence={}))])
        self.assertEqual(out.evidence, [])

    def test_raw_response_not_forwarded(self):
        r = result("NEEDS_REVIEW", 0.0, evidence={"city": "Delhi", "raw_response": "garbage"})
        out = self.engine.decide("hotspot", [AgentOutput("hotspot", r)])
        self.assertEqual([e.field for e in out.evidence], ["city"])

    def test_needs_review_passthrough(self):
        out = self.engine.decide("note", [AgentOutput("note", result("NEEDS_REVIEW", 0.2))])
        self.assertEqual(out.risk_level, L.NEEDS_REVIEW)
        self.assertEqual(out.risk_score, 50)

    def test_weak_low_overridden_with_labelled_reason(self):
        out = self.engine.decide("note", [AgentOutput("note", result("LOW", 0.3, reasons=["Thread visible"]))])
        self.assertEqual(out.risk_level, L.NEEDS_REVIEW)
        self.assertTrue(any(r.startswith("[Decision Engine]") for r in out.reasons))
        self.assertIn("Thread visible", out.reasons)

    def test_strong_low_stays_low(self):
        out = self.engine.decide("scam", [AgentOutput("scam", result("LOW", 0.9))])
        self.assertEqual(out.risk_level, L.LOW)
        self.assertEqual(out.risk_score, 2)  # round(25 * 0.1) -> 2

    def test_multi_agent_highest_wins(self):
        a = result("LOW", 0.9, "Fine", ["a"], name="A")
        b = result("HIGH", 0.8, "Bad", ["b"], name="B")
        out = self.engine.decide("x", [AgentOutput("scam", a), AgentOutput("hotspot", b)])
        self.assertEqual(out.verdict, "Bad")
        self.assertEqual(out.risk_level, L.HIGH)
        self.assertEqual(sorted(out.contributing_agents), ["A", "B"])
        self.assertEqual(set(out.reasons), {"a", "b"})
        self.assertEqual(len(out.score_breakdown), 2)

    def test_low_plus_needs_review_is_needs_review(self):
        a = result("LOW", 0.9, name="A")
        b = result("NEEDS_REVIEW", 0.0, name="B")
        out = self.engine.decide("x", [AgentOutput("scam", a), AgentOutput("hotspot", b)])
        self.assertEqual(out.risk_level, L.NEEDS_REVIEW)

    def test_medium_plus_needs_review_stays_medium(self):
        a = result("MEDIUM", 0.5, name="A")
        b = result("NEEDS_REVIEW", 0.0, name="B")
        out = self.engine.decide("x", [AgentOutput("scam", a), AgentOutput("hotspot", b)])
        self.assertEqual(out.risk_level, L.MEDIUM)

    def test_failure_makes_partial_and_blocks_low(self):
        fail = FailedComponent(agent="B", analysis_type="x", error="down")
        out = self.engine.decide("x", [AgentOutput("scam", result("LOW", 0.9))], [fail])
        self.assertEqual(out.status, "partial")
        self.assertEqual(out.risk_level, L.NEEDS_REVIEW)
        self.assertEqual(out.failed_components[0].agent, "B")

    def test_failure_does_not_downgrade_high(self):
        fail = FailedComponent(agent="B", analysis_type="x", error="down")
        out = self.engine.decide("x", [AgentOutput("scam", result("HIGH", 0.8))], [fail])
        self.assertEqual(out.risk_level, L.HIGH)
        self.assertEqual(out.status, "partial")

    def test_empty_outputs_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.decide("x", [])


# ------------------------------------------------------------------ master agent
class MasterAgentTests(unittest.TestCase):
    def test_routes_to_registered_agent_only(self):
        scam, vis, hot = (StubAgent(n, result(name=n)) for n in ("Scam", "Vision", "Hotspot"))
        m = MasterAgent()
        m.register("scam", scam); m.register("note", vis); m.register("hotspot", hot)
        out = run(m.analyze("scam", {"text": "hi"}))
        self.assertEqual(out.contributing_agents, ["Scam"])
        self.assertEqual(scam.inputs, [{"text": "hi"}])
        self.assertEqual((vis.inputs, hot.inputs), ([], []))
        run(m.analyze("note", {"image_bytes": b"x"})); run(m.analyze("hotspot", {"city": "X"}))
        self.assertEqual(len(vis.inputs), 1)
        self.assertEqual(len(hot.inputs), 1)

    def test_unknown_type(self):
        with self.assertRaises(UnknownAnalysisType):
            run(MasterAgent().analyze("voice", {}))

    def test_supported_types_and_callable_registration(self):
        m = MasterAgent()
        holder = {"a": StubAgent("One", result(name="One"))}
        m.register("scam", lambda: holder["a"])
        self.assertEqual(m.supported_types, ["scam"])
        holder["a"] = StubAgent("Two", result(name="Two"))
        self.assertEqual(run(m.analyze("scam", {})).contributing_agents, ["Two"])

    def test_all_fail_raises_and_names_component(self):
        m = MasterAgent()
        m.register("scam", StubAgent("Scam", exc=LLMTimeoutError()))
        with self.assertRaises(AllAgentsFailedError) as cm:
            run(m.analyze("scam", {}))
        f = cm.exception.failures[0]
        self.assertEqual((f.agent_name, f.analysis_type), ("Scam", "scam"))

    def test_unexpected_error_message_is_generic(self):
        m = MasterAgent()
        m.register("scam", StubAgent("Scam", exc=RuntimeError("secret internal detail")))
        with self.assertRaises(AllAgentsFailedError) as cm:
            run(m.analyze("scam", {}))
        self.assertNotIn("secret", cm.exception.failures[0].message)

    def test_partial_result_when_one_of_two_fails(self):
        m = MasterAgent()
        m.register("scam", [StubAgent("Good", result("HIGH", 0.8, name="Good")), StubAgent("Bad", exc=LLMTimeoutError())])
        out = run(m.analyze("scam", {}))
        self.assertEqual(out.status, "partial")
        self.assertEqual(out.contributing_agents, ["Good"])
        self.assertEqual([f.agent for f in out.failed_components], ["Bad"])


# ------------------------------------------------------------------------- API
GOOD = (
    '{"verdict": "Digital Arrest Scam", "risk_level": "HIGH", "confidence": 0.97,'
    ' "reasons": ["Impersonates CBI"], "evidence": {"k": 1}, "next_steps": ["s1"]}'
)
UNIFIED_KEYS = {
    "analysis_type", "audit_id", "status", "verdict", "risk_level", "risk_score", "confidence", "reasons", "evidence",
    "prevention", "next_steps", "contributing_agents", "failed_components", "score_breakdown", "score_disclaimer",
}


class FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, text=GOOD, exc=None):
        self.text, self.exc, self.calls = text, exc, []

    async def generate(self, prompt, *, images=()):
        self.calls.append(list(images))
        if self.exc:
            raise self.exc
        return LLMResponse(text=self.text, provider="fake", model="fake-1")


@unittest.skipUnless(HAVE_API_DEPS, "fastapi/httpx/pillow not installed")
class UnifiedApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(ROOT)
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        import main
        from database import Base

        cls.tmp = tempfile.TemporaryDirectory()
        engine = create_engine(f"sqlite:///{cls.tmp.name}/test.db", connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)

        def override_get_db():
            db = Session()
            try:
                yield db
            finally:
                db.close()

        main.app.dependency_overrides[main.get_db] = override_get_db
        cls.main = main
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        cls.main.app.dependency_overrides.clear()
        cls.tmp.cleanup()

    def setUp(self):
        self._orig_vision = self.main.vision_agent
        self.main.vision_agent = self.main.build_vision_agent()

    def tearDown(self):
        self.main.vision_agent = self._orig_vision

    def use(self, provider):
        self.main.agent._llm = provider
        self.main.hotspot_agent._llm = provider
        self.main.vision_agent._llm = provider
        return provider

    @staticmethod
    def png():
        buf = io.BytesIO()
        Image.new("RGB", (32, 20), (200, 120, 40)).save(buf, "PNG")
        return buf.getvalue()

    def post_note(self, data=None, name="n.png", ctype="image/png"):
        return self.client.post("/api/analyze/note", files={"file": (name, data or self.png(), ctype)})

    # --- routing + schema
    def test_scam_routing_and_schema(self):
        self.use(FakeProvider())
        r = self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": "You have a warrant"}})
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual(set(b), UNIFIED_KEYS)
        self.assertEqual(b["analysis_type"], "scam")
        self.assertEqual(b["verdict"], "Digital Arrest Scam")
        self.assertEqual(b["risk_level"], "CRITICAL")
        self.assertEqual(b["contributing_agents"], ["Suraksha AI"])
        self.assertEqual(b["evidence"], [{"agent": "Suraksha AI", "field": "k", "value": 1}])
        self.assertTrue(any("Do not transfer money" in p for p in b["prevention"]))
        self.assertEqual(b["next_steps"], ["s1"])
        self.assertEqual(b["status"], "complete")

    def test_hotspot_routing(self):
        self.use(FakeProvider('{"verdict":"Elevated","risk_level":"MEDIUM","confidence":0.6,"reasons":["x"],"evidence":{"city":"Delhi"},"next_steps":[]}'))
        r = self.client.post("/api/analyze", json={"analysis_type": "hotspot", "input": {"city": "Delhi", "type": "UPI Fraud"}})
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["analysis_type"], b["risk_level"], b["contributing_agents"]), ("hotspot", "MEDIUM", ["Hotspot AI"]))

    def test_vision_routing_sends_image(self):
        fake = self.use(FakeProvider('{"verdict":"Looks fine","risk_level":"LOW","confidence":0.8,"reasons":["thread"],"evidence":{"denomination":"500"},"next_steps":[]}'))
        r = self.post_note()
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["analysis_type"], b["risk_level"], b["contributing_agents"]), ("note", "LOW", ["Vision AI"]))
        self.assertEqual(len(fake.calls[0]), 1)  # the image reached the provider
        self.assertTrue(any("Do not rely only on an uploaded image" in p for p in b["prevention"]))

    # --- request validation
    def test_validation_errors(self):
        self.use(FakeProvider())
        bad = [
            {"analysis_type": "voice", "input": {}},
            {"analysis_type": "note", "input": {}},
            {"analysis_type": "scam", "input": {"text": "   "}},
            {"analysis_type": "scam", "input": {}},
            {"analysis_type": "hotspot", "input": {"type": "x"}},
            {"input": {"text": "x"}},
        ]
        for body in bad:
            self.assertEqual(self.client.post("/api/analyze", json=body).status_code, 422, body)

    def test_note_upload_validation_preserved(self):
        self.use(FakeProvider())
        self.assertEqual(self.post_note(b"%PDF-1.4", "x.pdf", "application/pdf").status_code, 415)
        self.assertEqual(self.post_note(b"not an image", "x.png", "image/png").status_code, 415)
        self.assertEqual(self.client.post("/api/analyze/note").status_code, 422)

    # --- failure handling
    def test_provider_failures_are_controlled_and_name_component(self):
        cases = [(LLMConfigError("GEMINI_API_KEY is not configured on the server."), 503), (LLMTimeoutError(), 504)]
        for exc, status in cases:
            self.use(FakeProvider(exc=exc))
            r = self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": "x"}})
            self.assertEqual(r.status_code, status)
            d = r.json()["detail"]
            self.assertEqual(d["failed_components"][0]["agent"], "Suraksha AI")
            self.assertEqual(d["failed_components"][0]["error"], str(exc))

    def test_malformed_model_reply_is_502_not_fake_result(self):
        self.use(FakeProvider(text="not json"))
        r = self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": "x"}})
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("verdict", r.json())
        r = self.post_note()
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.json()["detail"]["failed_components"][0]["agent"], "Vision AI")

    def test_unexpected_error_hides_internals(self):
        self.use(FakeProvider(exc=RuntimeError("secret internal detail")))
        r = self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": "x"}})
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret", r.text)
        self.assertNotIn("Traceback", r.text)

    # --- existing endpoints untouched
    def test_legacy_endpoints_unchanged(self):
        self.use(FakeProvider())
        r = self.client.post("/api/scam/check", json={"text": "x"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            set(r.json()),
            {"final_verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps", "pipeline_steps"},
        )
        self.assertEqual(r.json()["risk_level"], "HIGH")  # legacy route does not use the unified scale
        r = self.client.post("/api/hotspot/analyze", json={"city": "X"})
        self.assertEqual(set(r.json()), {"verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps"})
        r = self.client.post("/api/note/check", files={"file": ("n.png", self.png(), "image/png")})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), {"verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps"})
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_openapi_lists_new_routes(self):
        paths = self.client.get("/openapi.json").json()["paths"]
        self.assertIn("/api/analyze", paths)
        self.assertIn("/api/analyze/note", paths)


if __name__ == "__main__":
    unittest.main()
