"""
Tests for POST /api/note/check (Phase 2). A fake LLMProvider stands in for Gemini, so
these verify wiring, validation and error mapping -- NOT real Gemini behaviour.
Needs fastapi + httpx + pillow; skipped if missing. Uses a throw-away SQLite file.
"""
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
    HAVE_DEPS = True
except ImportError:
    HAVE_DEPS = False

from llm_providers import (  # noqa: E402
    LLMConfigError, LLMProvider, LLMProviderError, LLMResponse, LLMTimeoutError,
)

GOOD = (
    '{"verdict": "Likely genuine", "risk_level": "LOW", "confidence": 0.8,'
    ' "reasons": ["Thread visible"], "evidence": {"serial_number": "1AB123456"},'
    ' "next_steps": ["Verify at a bank"]}'
)
KEYS = {"verdict", "risk_level", "confidence", "reasons", "evidence", "next_steps"}


class FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, text=GOOD, exc=None):
        self.text, self.exc, self.calls = text, exc, []

    async def generate(self, prompt, *, images=()):
        self.calls.append(list(images))
        if self.exc:
            raise self.exc
        return LLMResponse(text=self.text, provider="fake", model="fake-1")


def make_image(fmt="PNG", size=(32, 20)):
    buf = io.BytesIO()
    Image.new("RGB", size, (200, 120, 40)).save(buf, fmt)
    return buf.getvalue()


@unittest.skipUnless(HAVE_DEPS, "fastapi/httpx/pillow not installed")
class NoteCheckTests(unittest.TestCase):
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
        self.fake = FakeProvider()
        self.main.vision_agent = self.main.build_vision_agent()
        self.main.vision_agent._llm = self.fake

    def post(self, data=None, name="note.png", ctype="image/png"):
        data = make_image() if data is None else data
        return self.client.post("/api/note/check", files={"file": (name, data, ctype)})

    # --- success -------------------------------------------------------
    def test_valid_image_returns_unchanged_contract(self):
        r = self.post()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(set(body), KEYS)
        self.assertEqual(body["verdict"], "Likely genuine")
        self.assertEqual(body["risk_level"], "LOW")
        self.assertEqual(body["evidence"]["serial_number"], "1AB123456")

    def test_image_reaches_provider_with_sniffed_mime(self):
        jpeg = make_image("JPEG")
        # client lies about nothing here, but mime must come from content
        self.assertEqual(self.post(jpeg, "n.jpg", "image/jpeg").status_code, 200)
        img = self.fake.calls[0][0]
        self.assertEqual(img.mime_type, "image/jpeg")
        self.assertEqual(img.data, jpeg)

    def test_webp_accepted(self):
        self.assertEqual(self.post(make_image("WEBP"), "n.webp", "image/webp").status_code, 200)

    def test_audit_row_written_with_sanitised_name(self):
        from database import AuditLog
        self.post(name="my note.png")
        db = self.Session()
        try:
            row = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            self.assertEqual(row.input_text, "my note.png")
            self.assertEqual(len(row.input_hash), 64)
        finally:
            db.close()

    # --- validation ----------------------------------------------------
    def test_invalid_file_type_rejected(self):
        r = self.post(b"%PDF-1.4 fake", "doc.pdf", "application/pdf")
        self.assertEqual(r.status_code, 415)
        self.assertEqual(self.fake.calls, [])

    def test_wrong_content_with_image_headers_rejected(self):
        r = self.post(b"<html>not an image</html>", "x.png", "image/png")
        self.assertEqual(r.status_code, 415)
        self.assertEqual(self.fake.calls, [])

    def test_extension_must_match_allowed_list(self):
        self.assertEqual(self.post(make_image(), "x.exe", "image/png").status_code, 415)

    def test_corrupt_image_rejected(self):
        truncated = make_image()[:40]
        self.assertEqual(self.post(truncated).status_code, 400)

    def test_empty_file_rejected(self):
        self.assertEqual(self.post(b"").status_code, 400)

    def test_oversized_upload_rejected(self):
        import config
        old = config.MAX_UPLOAD_BYTES
        config.MAX_UPLOAD_BYTES = 1024
        try:
            r = self.post(make_image(size=(400, 400)))
        finally:
            config.MAX_UPLOAD_BYTES = old
        self.assertEqual(r.status_code, 413)
        self.assertEqual(self.fake.calls, [])

    def test_missing_file_field_is_422(self):
        self.assertEqual(self.client.post("/api/note/check").status_code, 422)

    # --- filename / path handling -------------------------------------
    def test_path_traversal_filename_never_touches_filesystem(self):
        from database import AuditLog
        before = set(os.listdir(ROOT))
        r = self.post(name="../../../etc/passwd.png")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(os.listdir(ROOT)), before)
        self.assertFalse(os.path.exists("/etc/passwd.png"))
        db = self.Session()
        try:
            row = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            self.assertEqual(row.input_text, "passwd.png")
        finally:
            db.close()

    def test_sanitize_filename_cases(self):
        from upload_validation import DEFAULT_FILENAME, sanitize_filename as sf
        self.assertEqual(sf("..\\..\\win\\evil.png"), "evil.png")
        self.assertEqual(sf("/abs/path/a.jpg"), "a.jpg")
        self.assertEqual(sf("a\x00b\n<script>.png"), "ab__script_.png")
        self.assertEqual(sf(None), DEFAULT_FILENAME)
        self.assertEqual(sf(""), DEFAULT_FILENAME)
        self.assertEqual(sf(".."), DEFAULT_FILENAME)
        self.assertEqual(sf("///"), DEFAULT_FILENAME)
        long = sf("a" * 500 + ".png")
        self.assertLessEqual(len(long), 100)
        self.assertTrue(long.endswith(".png"))

    def test_no_temp_upload_files_left_behind(self):
        self.post()
        self.assertFalse(os.path.isdir(os.path.join(ROOT, "temp_uploads")) and os.listdir(os.path.join(ROOT, "temp_uploads")))

    # --- provider failures --------------------------------------------
    def test_missing_gemini_configuration_gives_503(self):
        self.fake.exc = LLMConfigError("GEMINI_API_KEY is not configured on the server.")
        r = self.post()
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["detail"], "GEMINI_API_KEY is not configured on the server.")

    def test_real_provider_without_key_gives_503(self):
        """No fake: the real GeminiProvider with an empty key, never reaching the network."""
        from llm_providers.gemini_provider import GeminiProvider
        self.main.vision_agent._llm = GeminiProvider(api_key="")
        r = self.post()
        self.assertEqual(r.status_code, 503)

    def test_provider_failure_gives_502(self):
        self.fake.exc = LLMProviderError()
        self.assertEqual(self.post().status_code, 502)

    def test_timeout_gives_504(self):
        self.fake.exc = LLMTimeoutError()
        self.assertEqual(self.post().status_code, 504)

    def test_failure_does_not_silently_use_mock(self):
        self.fake.exc = LLMProviderError()
        r = self.post(name="good_real_note.png")  # filename that would make the mock say "genuine"
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("verdict", r.json())

    def test_malformed_vision_responses_give_502(self):
        for text in ("not json at all", "{}", '{"reasons": ["x"]}'):
            self.fake.text = text
            r = self.post()
            self.assertEqual(r.status_code, 502, text)
            self.assertNotIn("Traceback", r.text)

    def test_unexpected_error_is_generic_500(self):
        self.fake.exc = RuntimeError("secret internal detail")
        r = self.post()
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret", r.text)

    # --- mock is explicit only ----------------------------------------
    def test_default_agent_is_real_and_mock_requires_flag(self):
        import config
        from agents.mock_vision_agent import MockVisionAgent
        from agents.vision_agent import VisionAgent
        self.assertIsInstance(self.main.build_vision_agent(), VisionAgent)
        config.USE_MOCK_VISION = True
        try:
            self.assertIsInstance(self.main.build_vision_agent(), MockVisionAgent)
        finally:
            config.USE_MOCK_VISION = False

    def test_mock_mode_is_labelled_in_response(self):
        self.main.vision_agent = self.main.agents_mock = __import__("agents.mock_vision_agent", fromlist=["x"]).MockVisionAgent()
        r = self.post(name="fake_note.png")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), KEYS)
        self.assertEqual(r.json()["evidence"]["analysis_mode"], "mock_filename_based")


if __name__ == "__main__":
    unittest.main()
