"""
Tests for the LLM provider layer. Stdlib only (unittest); no network, no SDK, no API key.
Run from the project root:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_providers import (  # noqa: E402
    ImagePart,
    LLMConfigError,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
    get_llm_provider,
    parse_json_response,
)
from llm_providers.gemini_provider import GeminiProvider  # noqa: E402

SECRET = "SECRET-KEY-12345"


def run(coro):
    return asyncio.run(coro)


class FakeTypes:
    class Part:
        @staticmethod
        def from_bytes(data, mime_type):
            return ("PART", data, mime_type)


class FakeModels:
    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = []

    def generate_content(self, model, contents):
        self.calls.append({"model": model, "contents": contents})
        return self.behaviour()


class FakeClient:
    def __init__(self, behaviour):
        self.models = FakeModels(behaviour)


class StubbedGemini(GeminiProvider):
    """GeminiProvider whose SDK is replaced by fakes."""

    def __init__(self, behaviour, **kw):
        super().__init__(**kw)
        self.fake_client = FakeClient(behaviour)
        self.client_created = 0

    def _load_sdk(self):
        outer = self

        class FakeGenai:
            @staticmethod
            def Client(api_key):
                outer.client_created += 1
                return outer.fake_client

        return FakeGenai, FakeTypes


def reply(text):
    return lambda: SimpleNamespace(text=text)


class ParseJsonTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_json_response('{"a": 1}'), {"a": 1})

    def test_fenced(self):
        self.assertEqual(parse_json_response('```json\n{"a": 1}\n```'), {"a": 1})

    def test_embedded_in_prose(self):
        self.assertEqual(parse_json_response('Sure! {"a": 1} Hope that helps'), {"a": 1})

    def test_malformed_raises_with_raw_text(self):
        with self.assertRaises(LLMResponseError) as ctx:
            parse_json_response("not json at all")
        self.assertEqual(ctx.exception.raw_text, "not json at all")

    def test_non_object_raises(self):
        with self.assertRaises(LLMResponseError):
            parse_json_response("[1, 2, 3]")

    def test_empty_raises(self):
        with self.assertRaises(LLMResponseError):
            parse_json_response("")


class GeminiProviderTests(unittest.TestCase):
    def test_missing_key_raises_config_error_without_touching_sdk(self):
        p = StubbedGemini(reply("{}"), api_key="")
        with self.assertRaises(LLMConfigError) as ctx:
            run(p.generate("hi"))
        self.assertIn("GEMINI_API_KEY", str(ctx.exception))
        self.assertEqual(p.client_created, 0)

    def test_construction_needs_no_key_or_sdk(self):
        GeminiProvider(api_key="")  # must not raise

    def test_success_text_only_passes_prompt_string_unchanged(self):
        p = StubbedGemini(reply('{"verdict": "ok"}'), api_key=SECRET, model="m-1")
        out = run(p.generate("hello"))
        self.assertIsInstance(out, LLMResponse)
        self.assertEqual((out.text, out.provider, out.model), ('{"verdict": "ok"}', "gemini", "m-1"))
        call = p.fake_client.models.calls[0]
        self.assertEqual(call, {"model": "m-1", "contents": "hello"})

    def test_client_created_once(self):
        p = StubbedGemini(reply("x"), api_key=SECRET)
        run(p.generate("a"))
        run(p.generate("b"))
        self.assertEqual(p.client_created, 1)

    def test_images_sent_as_parts_after_prompt(self):
        p = StubbedGemini(reply("x"), api_key=SECRET)
        run(p.generate("look", images=[ImagePart(b"\x01\x02", "image/png")]))
        self.assertEqual(
            p.fake_client.models.calls[0]["contents"],
            ["look", ("PART", b"\x01\x02", "image/png")],
        )

    def test_generate_json(self):
        p = StubbedGemini(reply('```json\n{"risk_level": "HIGH"}\n```'), api_key=SECRET)
        self.assertEqual(run(p.generate_json("x")), {"risk_level": "HIGH"})

    def test_empty_reply_is_response_error(self):
        for empty in (None, "", "   "):
            p = StubbedGemini(reply(empty), api_key=SECRET)
            with self.assertRaises(LLMResponseError):
                run(p.generate("x"))

    def test_sdk_exception_is_translated_and_never_leaks_secret(self):
        def boom():
            raise RuntimeError(f"connection failed for key={SECRET}")

        p = StubbedGemini(boom, api_key=SECRET)
        with self.assertRaises(LLMProviderError) as ctx:
            run(p.generate("x"))
        self.assertNotIn(SECRET, str(ctx.exception))
        self.assertNotIn("connection failed", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)

    def test_error_codes_map_to_safe_messages(self):
        class ApiErr(Exception):
            def __init__(self, code):
                super().__init__(f"{code} {SECRET}")
                self.code = code

        for code, fragment in ((429, "too many requests"), (403, "rejected the request"), (500, "temporarily unavailable")):
            def boom(code=code):
                raise ApiErr(code)

            p = StubbedGemini(boom, api_key=SECRET)
            with self.assertRaises(LLMProviderError) as ctx:
                run(p.generate("x"))
            self.assertIn(fragment, str(ctx.exception))
            self.assertNotIn(SECRET, str(ctx.exception))

    def test_failure_logs_do_not_contain_secret(self):
        def boom():
            raise RuntimeError(f"bad key {SECRET}")

        p = StubbedGemini(boom, api_key=SECRET)
        with self.assertLogs("suraksha.llm.gemini", level="ERROR") as logs:
            with self.assertRaises(LLMProviderError):
                run(p.generate("x"))
        self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_timeout(self):
        def slow():
            time.sleep(0.5)
            return SimpleNamespace(text="late")

        p = StubbedGemini(slow, api_key=SECRET, timeout=0.05)
        with self.assertRaises(LLMTimeoutError):
            run(p.generate("x"))

    def test_response_text_property_raising_is_response_error(self):
        class Blocked:
            @property
            def text(self):
                raise ValueError("blocked by safety filter")

        p = StubbedGemini(lambda: Blocked(), api_key=SECRET)
        with self.assertRaises(LLMResponseError):
            run(p.generate("x"))

    def test_missing_sdk_is_config_error(self):
        p = GeminiProvider(api_key=SECRET)

        def no_sdk():
            raise LLMConfigError("The Gemini SDK (google-genai) is not installed on the server.")

        p._load_sdk = no_sdk
        with self.assertRaises(LLMConfigError):
            run(p.generate("x"))


class FactoryTests(unittest.TestCase):
    def test_default_is_gemini_and_shared(self):
        a, b = get_llm_provider(), get_llm_provider("gemini")
        self.assertIsInstance(a, GeminiProvider)
        self.assertIs(a, b)

    def test_unknown_provider(self):
        with self.assertRaises(LLMConfigError):
            get_llm_provider("nope")

    def test_custom_provider_satisfies_interface(self):
        class Custom(LLMProvider):
            name = "custom"

            async def generate(self, prompt, *, images=()):
                return LLMResponse(text='{"verdict": "v"}', provider=self.name, model="c")

        self.assertEqual(run(Custom().generate_json("x")), {"verdict": "v"})


if __name__ == "__main__":
    unittest.main()
