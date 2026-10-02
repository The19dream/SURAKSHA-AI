"""
API contract tests for the AI endpoints, with a fake LLM provider injected.
Requires fastapi + httpx (httpx is only needed for these tests, not by the app);
skipped automatically if either is missing. Uses a throw-away SQLite file, so the
project's real suraksha_ai.db is not modified.
Run from the project root:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    HAVE_DEPS = True
except ImportError:
    HAVE_DEPS = False

from llm_providers import LLMConfigError, LLMProvider, LLMResponse, LLMTimeoutError  # noqa: E402

GOOD = (
    '{"verdict": "Digital Arrest Scam", "risk_level": "HIGH", "confidence": 0.97,'
    ' "reasons": ["r1"], "evidence": {"k": 1}, "next_steps": ["s1"]}'
)


class FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, text=GOOD, exc=None):
        self.text, self.exc = text, exc

    async def generate(self, prompt, *, images=()):
        if self.exc:
            raise self.exc
        return LLMResponse(text=self.text, provider="fake", model="fake-1")


@unittest.skipUnless(HAVE_DEPS, "fastapi/httpx not installed")
class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(ROOT)  # main.py uses relative paths (static/, data/)
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        import main
        from database import Base

        cls.tmp = tempfile.TemporaryDirectory()
        engine = create_engine(
            f"sqlite:///{cls.tmp.name}/test.db", connect_args={"check_same_thread": False}
        )
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
        cls.client = TestClient(main.app)  # no `with`: startup hook (real DB init) not run

    @classmethod
    def tearDownClass(cls):
        cls.main.app.dependency_overrides.clear()
        cls.tmp.cleanup()

    def _set_llm(self, provider):
        self.main.agent._llm = provider
        self.main.hotspot_agent._llm = provider

    def test_scam_check_contract_unchanged(self):
        self._set_llm(FakeProvider())
        r = self.client.post("/api/scam/check", json={"text": "You have a warrant"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.json(),
            {
                "final_verdict": "Digital Arrest Scam",
                "risk_level": "HIGH",
                "confidence": 0.97,
                "reasons": ["r1"],
                "evidence": {"k": 1},
                "next_steps": ["s1"],
                "pipeline_steps": {"reporting_complete": True},
            },
        )

    def test_hotspot_analyze_contract_unchanged(self):
        self._set_llm(FakeProvider())
        r = self.client.post("/api/hotspot/analyze", json={"city": "X", "type": "UPI Fraud"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            set(r.json()),
            {"verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps"},
        )

    def test_missing_key_gives_clean_503(self):
        self._set_llm(FakeProvider(exc=LLMConfigError("GEMINI_API_KEY is not configured on the server.")))
        for path, body in (("/api/scam/check", {"text": "x"}), ("/api/hotspot/analyze", {"city": "X"})):
            r = self.client.post(path, json=body)
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.json()["detail"], "GEMINI_API_KEY is not configured on the server.")

    def test_timeout_gives_504(self):
        self._set_llm(FakeProvider(exc=LLMTimeoutError()))
        r = self.client.post("/api/scam/check", json={"text": "x"})
        self.assertEqual(r.status_code, 504)

    def test_malformed_model_reply_gives_502_for_scam(self):
        self._set_llm(FakeProvider(text="not json"))
        r = self.client.post("/api/scam/check", json={"text": "x"})
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("Traceback", r.text)

    def test_unrelated_endpoints_still_work(self):
        self.assertEqual(self.client.get("/api/health").json(), {"status": "ok", "app": "Suraksha AI"})
        self.assertEqual(self.client.get("/api/hotspots").status_code, 200)
        self.assertEqual(self.client.get("/api/sample-messages").status_code, 200)


if __name__ == "__main__":
    unittest.main()
