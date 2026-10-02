import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# Configuration Settings
USE_MOCK_AGENTS = os.getenv("USE_MOCK_AGENTS", "true").lower() in ("true", "1", "yes")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
APP_URL = os.getenv("APP_URL", "http://localhost:3000")

# LLM provider settings (see llm_providers/)
# LLM_PROVIDER selects the backend; "gemini" is the only one implemented today.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").strip().lower() or "gemini"
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "models/gemini-3.1-flash-lite").strip() or "models/gemini-3.1-flash-lite"
LLM_TIMEOUT_SECONDS = _float_env("LLM_TIMEOUT_SECONDS", 60.0)

# Banknote upload limits (see upload_validation.py)
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


MAX_UPLOAD_BYTES = _int_env("MAX_UPLOAD_MB", 8) * 1024 * 1024

# Explicit dev-only switch: serve /api/note/check from the filename-based MOCK
# instead of Gemini. Default OFF. Never used as an automatic fallback on errors.
USE_MOCK_VISION = os.getenv("USE_MOCK_VISION", "false").strip().lower() in ("true", "1", "yes")
