"""Phase 4 tests: Report Agent, POST /api/report, unified audit trail.
All AI is faked (no Gemini, no network, no key); these verify logic and wiring, not model quality.
Run from the project root:  python -m unittest discover -s tests -v
"""
import asyncio
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    from PIL import Image
    HAVE_API_DEPS = True
except ImportError:
    HAVE_API_DEPS = False

from pydantic import ValidationError  # noqa: E402

from agents.report_agent import ReportAgent  # noqa: E402
from llm_providers import (  # noqa: E402
    LLMConfigError, LLMProvider, LLMResponse, LLMResponseError, LLMTimeoutError,
)
from orchestration import MasterAgent  # noqa: E402
from orchestration.report_schemas import NOT_PROVIDED  # noqa: E402
from orchestration.schemas import UnifiedAnalysisResult  # noqa: E402


def run(coro):
    return asyncio.run(coro)


REPORT_OK = '{"title": "Suspected digital arrest scam", "summary": "The analysis indicates a likely scam message."}'
SCAM_OK = (
    '{"verdict": "Digital Arrest Scam", "risk_level": "HIGH", "confidence": 0.97,'
    ' "reasons": ["Impersonates CBI"], "evidence": {"k": 1}, "next_steps": ["s1"]}'
)
NOTE_OK = (
    '{"verdict": "Looks consistent", "risk_level": "LOW", "confidence": 0.8, "reasons": ["thread"],'
    ' "evidence": {"denomination": "500"}, "next_steps": []}'
)
HOT_OK = '{"verdict": "Elevated", "risk_level": "MEDIUM", "confidence": 0.6, "reasons": ["x"], "evidence": {"city": "Delhi"}, "next_steps": []}'


class FakeProvider(LLMProvider):
    """Returns `report` for Report Agent prompts and `analysis` for everything else."""
    name = "fake"

    def __init__(self, analysis=SCAM_OK, report=REPORT_OK, exc=None, report_exc=None):
        self.analysis, self.report, self.exc, self.report_exc = analysis, report, exc, report_exc
        self.prompts = []

    async def generate(self, prompt, *, images=()):
        self.prompts.append(prompt)
        is_report = "Report Agent of Suraksha AI" in prompt
        exc = self.report_exc if is_report else self.exc
        if exc:
            raise exc
        return LLMResponse(text=self.report if is_report else self.analysis, provider="fake", model="fake-1")


def make_analysis(**over):
    base = dict(
        analysis_type="scam", verdict="Digital Arrest Scam", risk_level="CRITICAL", risk_score=94,
        confidence=0.97, reasons=["Impersonates CBI"],
        evidence=[{"agent": "Suraksha AI", "field": "keywords", "value": ["warrant"]}],
        prevention=["Do not transfer money."], next_steps=["Hang up"], contributing_agents=["Suraksha AI"],
    )
    base.update(over)
    return UnifiedAnalysisResult(**base)


# ------------------------------------------------------------------ Report Agent
class ReportAgentTests(unittest.TestCase):
    def agent(self, **kw):
        return ReportAgent(llm=FakeProvider(**kw))

    def gen(self, analysis=None, **kw):
        return run(self.agent(**kw).run({"analysis": analysis or make_analysis(), "audit_id": "aud-1"}))

    def test_valid_report(self):
        r = self.gen()
        self.assertEqual(r.title, "Suspected digital arrest scam")
        self.assertIn("likely scam", r.summary)
        self.assertEqual(r.incident_type, "Suspected scam / fraud message")
        self.assertEqual((r.verdict, r.risk_level.value, r.risk_score, r.confidence), ("Digital Arrest Scam", "CRITICAL", 94, 0.97))
        self.assertEqual(r.reasons, ["Impersonates CBI"])
        self.assertEqual(r.prevention, ["Do not transfer money."])
        self.assertEqual(r.recommended_actions, ["Hang up"])
        self.assertEqual(r.contributing_agents, ["Suraksha AI"])
        self.assertEqual(r.audit_id, "aud-1")
        self.assertEqual(r.analysis_status, "complete")
        self.assertTrue(r.report_id)
        self.assertIsInstance(r.timestamp, datetime)
        self.assertIn("NOT an official police report", r.disclaimer)

    def test_incident_types(self):
        for t, expected in (("note", "banknote"), ("hotspot", "hotspot"), ("other", "Analysis report")):
            self.assertIn(expected, self.gen(make_analysis(analysis_type=t)).incident_type)

    def test_evidence_preserved_exactly(self):
        ev = [{"agent": "A", "field": "f1", "value": 1}, {"agent": "B", "field": "f2", "value": {"n": [1, 2]}}]
        r = self.gen(make_analysis(evidence=ev))
        self.assertEqual([e.model_dump() for e in r.evidence], ev)

    def test_missing_optional_fields_ok(self):
        a = UnifiedAnalysisResult(analysis_type="scam", verdict="v", risk_level="LOW", risk_score=2, confidence=0.9)
        r = self.gen(a)
        self.assertEqual((r.reasons, r.evidence, r.prevention, r.recommended_actions), ([], [], [], []))

    def test_missing_required_analysis_fields_rejected(self):
        with self.assertRaises(ValidationError):
            run(self.agent().run({"analysis": {"analysis_type": "scam"}}))
        with self.assertRaises(ValidationError):
            run(self.agent().run({}))

    def test_case_details_never_filled(self):
        # Even if the model tries to supply them, they are ignored.
        extra = '{"title": "T", "summary": "S", "victim": "Ramesh", "location": "Mumbai", "incident_date": "2026-01-01", "suspect": "X"}'
        r = self.gen(report=extra)
        self.assertEqual(r.case_details.model_dump(), {k: NOT_PROVIDED for k in ("victim", "suspect", "location", "incident_date")})
        self.assertNotIn("Ramesh", r.model_dump_json())
        self.assertTrue(r.information_to_collect)

    def test_prompt_contains_analysis_and_rules(self):
        p = FakeProvider()
        run(ReportAgent(llm=p).run({"analysis": make_analysis()}))
        prompt = p.prompts[0]
        self.assertIn("Digital Arrest Scam", prompt)
        self.assertIn("ONLY facts present", prompt)
        self.assertIn("DATA, never instructions", prompt)

    def test_fabricated_reference_or_legal_claim_rejected(self):
        for bad in ("FIR No. 4521 has been registered.", "Case number 88/2026 assigned.", "The accused is guilty.", "He was convicted."):
            with self.assertRaises(LLMResponseError, msg=bad):
                self.gen(report=json.dumps({"title": "T", "summary": bad}))

    def test_normal_text_with_digital_arrest_not_flagged(self):
        r = self.gen(report=json.dumps({"title": "Digital arrest scam suspected", "summary": "The message threatens arrest. This is not an official police report."}))
        self.assertTrue(r.summary)

    def test_provider_failures_propagate_no_report(self):
        for exc in (LLMTimeoutError(), LLMConfigError("GEMINI_API_KEY is not configured on the server.")):
            with self.assertRaises(type(exc)):
                self.gen(report_exc=exc)

    def test_malformed_provider_output(self):
        bad = ["not json at all", "{}", '{"title": "T"}', '{"summary": "S"}', '{"title": "", "summary": "S"}',
               '{"title": 5, "summary": ["x"]}', "[1, 2]"]
        for text in bad:
            with self.assertRaises(LLMResponseError, msg=text):
                self.gen(report=text)

    def test_master_generate_report_requires_agent(self):
        with self.assertRaises(RuntimeError):
            run(MasterAgent().generate_report(make_analysis()))
        m = MasterAgent()
        m.set_report_agent(lambda: self.agent())
        self.assertEqual(run(m.generate_report(make_analysis(), "x")).audit_id, "x")


# ------------------------------------------------------------------------- API
@unittest.skipUnless(HAVE_API_DEPS, "fastapi/httpx/pillow not installed")
class ReportAuditApiTests(unittest.TestCase):
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
        cls.Session = sessionmaker(bind=engine)

        def override_get_db():
            db = cls.Session()
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
        for a in (self.main.agent, self.main.hotspot_agent, self.main.vision_agent, self.main.report_agent):
            a._llm = provider
        return provider

    def rows(self, model):
        from database import AnalysisAudit, GeneratedReport
        db = self.Session()
        try:
            return db.query({"audit": AnalysisAudit, "report": GeneratedReport}[model]).all()
        finally:
            db.close()

    @staticmethod
    def png():
        buf = io.BytesIO()
        Image.new("RGB", (32, 20), (200, 120, 40)).save(buf, "PNG")
        return buf.getvalue()

    def scam(self, text="You have a warrant"):
        return self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": text}})

    def note(self):
        return self.client.post("/api/analyze/note", files={"file": ("n.png", self.png(), "image/png")})

    # ---------------- audit trail
    def test_scam_analysis_creates_audit_entry(self):
        self.use(FakeProvider())
        before = len(self.rows("audit"))
        r = self.scam()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        rows = self.rows("audit")
        self.assertEqual(len(rows), before + 1)
        row = next(x for x in rows if x.audit_id == body["audit_id"])
        self.assertEqual(row.analysis_type, "scam")
        self.assertEqual(row.verdict, "Digital Arrest Scam")
        self.assertEqual(row.risk_level, "CRITICAL")
        self.assertEqual(row.risk_score, 94)
        self.assertEqual(row.confidence, 0.97)
        self.assertEqual(row.status, "complete")
        self.assertEqual(json.loads(row.contributing_agents), ["Suraksha AI"])
        self.assertIsNotNone(row.timestamp)
        self.assertEqual(len(row.input_hash), 64)

    def test_note_analysis_creates_audit_entry(self):
        self.use(FakeProvider(analysis=NOTE_OK))
        before = len(self.rows("audit"))
        r = self.note()
        self.assertEqual(r.status_code, 200, r.text)
        row = next(x for x in self.rows("audit") if x.audit_id == r.json()["audit_id"])
        self.assertEqual(len(self.rows("audit")), before + 1)
        self.assertEqual((row.analysis_type, row.risk_level, row.risk_score), ("note", "LOW", r.json()["risk_score"]))
        self.assertEqual(json.loads(row.contributing_agents), ["Vision AI"])

    def test_hotspot_analysis_creates_audit_entry(self):
        self.use(FakeProvider(analysis=HOT_OK))
        r = self.client.post("/api/analyze", json={"analysis_type": "hotspot", "input": {"city": "Delhi"}})
        row = next(x for x in self.rows("audit") if x.audit_id == r.json()["audit_id"])
        self.assertEqual((row.analysis_type, row.risk_level), ("hotspot", "MEDIUM"))

    def test_failed_analysis_creates_no_audit_entry(self):
        before = len(self.rows("audit"))
        for provider in (FakeProvider(exc=LLMTimeoutError()), FakeProvider(exc=LLMConfigError("no key")),
                         FakeProvider(analysis="not json"), FakeProvider(exc=RuntimeError("boom"))):
            self.use(provider)
            self.assertGreaterEqual(self.scam().status_code, 500)
            self.assertGreaterEqual(self.note().status_code, 500)
        # validation failures too
        self.assertEqual(self.client.post("/api/analyze", json={"analysis_type": "scam", "input": {"text": " "}}).status_code, 422)
        self.assertEqual(self.client.post("/api/analyze/note", files={"file": ("x.pdf", b"%PDF", "application/pdf")}).status_code, 415)
        self.assertEqual(len(self.rows("audit")), before)

    def test_no_secrets_or_raw_input_stored(self):
        import config
        old = config.GEMINI_API_KEY
        config.GEMINI_API_KEY = "SENTINEL-API-KEY-12345"
        try:
            self.use(FakeProvider())
            self.assertEqual(self.scam("UNIQUE-USER-TEXT-98765 please pay").status_code, 200)
            self.report_for(self.scam("UNIQUE-USER-TEXT-98765 again").json())
            dump = ""
            for model in ("audit", "report"):
                for row in self.rows(model):
                    dump += " ".join(str(getattr(row, c.name)) for c in row.__table__.columns)
            self.assertNotIn("SENTINEL-API-KEY", dump)
            self.assertNotIn("UNIQUE-USER-TEXT", dump)
            self.assertNotIn("GEMINI_API_KEY", dump)
        finally:
            config.GEMINI_API_KEY = old

    def test_same_input_same_hash_different_input_different(self):
        self.use(FakeProvider())
        a = self.scam("hash me").json()["audit_id"]
        b = self.scam("hash me").json()["audit_id"]
        c = self.scam("different").json()["audit_id"]
        h = {x.audit_id: x.input_hash for x in self.rows("audit")}
        self.assertEqual(h[a], h[b])
        self.assertNotEqual(h[a], h[c])

    def test_audit_write_failure_does_not_fail_analysis(self):
        from orchestration import audit

        class BadDb:
            def add(self, *_): pass
            def commit(self): raise RuntimeError("disk full")
            def rollback(self): pass

        self.assertIsNone(audit.record_analysis(BadDb(), make_analysis(), "h" * 64))

    def test_partial_status_recorded(self):
        from orchestration import audit
        from orchestration.schemas import FailedComponent
        res = make_analysis(status="partial", failed_components=[FailedComponent(agent="Bad", analysis_type="scam", error="down")])
        db = self.Session()
        aid = audit.record_analysis(db, res, "h" * 64)
        db.close()
        row = next(x for x in self.rows("audit") if x.audit_id == aid)
        self.assertEqual(row.status, "partial")
        self.assertEqual(json.loads(row.failed_components), ["Bad"])

    def test_audit_trail_endpoint(self):
        self.use(FakeProvider())
        aid = self.scam("trail").json()["audit_id"]
        r = self.client.get("/api/audit-trail")
        self.assertEqual(r.status_code, 200)
        first = r.json()[0]
        self.assertEqual(first["audit_id"], aid)
        self.assertEqual(
            set(first),
            {"audit_id", "timestamp", "analysis_type", "status", "verdict", "risk_level", "risk_score",
             "confidence", "contributing_agents", "failed_components", "input_hash", "report_ids"},
        )
        self.assertTrue(first["timestamp"].endswith("Z"))
        self.assertEqual(len(self.client.get("/api/audit-trail?limit=1").json()), 1)

    def test_legacy_audit_log_untouched_by_unified_analysis(self):
        self.use(FakeProvider())
        before = len(self.client.get("/api/audit-log").json())
        self.scam("legacy check")
        self.assertEqual(len(self.client.get("/api/audit-log").json()), before)

    # ---------------- reports
    def report_for(self, analysis_response, **extra):
        body = {"analysis": analysis_response, "audit_id": analysis_response.get("audit_id")}
        body.update(extra)
        return self.client.post("/api/report", json=body)

    def test_report_end_to_end_and_relationship(self):
        self.use(FakeProvider())
        analysis = self.scam().json()
        r = self.report_for(analysis)
        self.assertEqual(r.status_code, 200, r.text)
        rep = r.json()
        self.assertEqual(
            set(rep),
            {"report_id", "audit_id", "analysis_type", "incident_type", "title", "summary", "verdict", "risk_level",
             "risk_score", "confidence", "reasons", "evidence", "prevention", "recommended_actions",
             "contributing_agents", "analysis_status", "failed_components", "case_details",
             "information_to_collect", "disclaimer", "generated_by", "timestamp"},
        )
        self.assertEqual(rep["audit_id"], analysis["audit_id"])
        self.assertEqual(rep["evidence"], analysis["evidence"])
        self.assertEqual(rep["recommended_actions"], analysis["next_steps"])
        self.assertEqual(rep["case_details"]["victim"], "Not provided")
        # stored + retrievable
        got = self.client.get(f"/api/reports/{rep['report_id']}")
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.json()["report_id"], rep["report_id"])
        # Analysis -> audit -> report
        entry = next(e for e in self.client.get("/api/audit-trail").json() if e["audit_id"] == analysis["audit_id"])
        self.assertEqual(entry["report_ids"], [rep["report_id"]])

    def test_report_without_audit_id(self):
        self.use(FakeProvider())
        analysis = self.scam().json()
        r = self.client.post("/api/report", json={"analysis": analysis})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["audit_id"])

    def test_report_note_analysis_has_physical_verification_advice(self):
        self.use(FakeProvider(analysis=NOTE_OK))
        analysis = self.note().json()
        rep = self.report_for(analysis).json()
        self.assertEqual(rep["incident_type"], "Suspected counterfeit banknote")
        self.assertTrue(any("uploaded image" in p for p in rep["prevention"]))

    def test_invalid_report_requests(self):
        self.use(FakeProvider())
        good = make_analysis().model_dump(mode="json")
        bad_bodies = [
            {},
            {"audit_id": "x"},
            {"analysis": {}},
            {"analysis": {**good, "risk_score": 150}},
            {"analysis": {**good, "confidence": 2}},
            {"analysis": {**good, "risk_level": "SUPER"}},
            {"analysis": {k: v for k, v in good.items() if k != "verdict"}},
            {"analysis": good, "audit_id": "x" * 100},
        ]
        for b in bad_bodies:
            self.assertEqual(self.client.post("/api/report", json=b).status_code, 422, b)

    def test_unknown_and_mismatched_audit_id(self):
        self.use(FakeProvider())
        analysis = self.scam().json()
        r = self.client.post("/api/report", json={"analysis": analysis, "audit_id": "00000000-0000-0000-0000-000000000000"})
        self.assertEqual(r.status_code, 404)
        tampered = {**analysis, "risk_score": 1, "risk_level": "LOW"}
        r = self.client.post("/api/report", json={"analysis": tampered, "audit_id": analysis["audit_id"]})
        self.assertEqual(r.status_code, 409)

    def test_report_provider_failures_controlled_and_nothing_stored(self):
        before = len(self.rows("report"))
        analysis = None
        cases = [(LLMConfigError("GEMINI_API_KEY is not configured on the server."), 503), (LLMTimeoutError(), 504)]
        for exc, status in cases:
            self.use(FakeProvider())
            analysis = analysis or self.scam().json()
            self.use(FakeProvider(report_exc=exc))
            r = self.report_for(analysis)
            self.assertEqual(r.status_code, status)
            d = r.json()["detail"]
            self.assertEqual(d["failed_components"][0]["agent"], "Report AI")
            self.assertEqual(d["failed_components"][0]["error"], str(exc))
            self.assertNotIn("title", r.json())
        self.assertEqual(len(self.rows("report")), before)

    def test_report_malformed_and_unexpected_errors(self):
        self.use(FakeProvider())
        analysis = self.scam().json()
        before = len(self.rows("report"))
        self.use(FakeProvider(report="not json"))
        self.assertEqual(self.report_for(analysis).status_code, 502)
        self.use(FakeProvider(report='{"title": "T"}'))
        self.assertEqual(self.report_for(analysis).status_code, 502)
        self.use(FakeProvider(report_exc=RuntimeError("secret internal detail")))
        r = self.report_for(analysis)
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret", r.text)
        self.assertEqual(len(self.rows("report")), before)

    def test_get_unknown_report_404(self):
        self.assertEqual(self.client.get("/api/reports/does-not-exist").status_code, 404)

    # ---------------- compatibility
    def test_legacy_endpoints_still_work(self):
        self.use(FakeProvider())
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        r = self.client.post("/api/scam/check", json={"text": "x"})
        self.assertEqual(set(r.json()), {"final_verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps", "pipeline_steps"})
        self.assertEqual(self.client.post("/api/hotspot/analyze", json={"city": "X"}).status_code, 200)
        self.use(FakeProvider(analysis=NOTE_OK))
        self.assertEqual(self.client.post("/api/note/check", files={"file": ("n.png", self.png(), "image/png")}).status_code, 200)

    def test_openapi_lists_new_routes(self):
        paths = self.client.get("/openapi.json").json()["paths"]
        for p in ("/api/report", "/api/reports/{report_id}", "/api/audit-trail"):
            self.assertIn(p, paths)


if __name__ == "__main__":
    unittest.main()
