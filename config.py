import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

# Configuration Settings
USE_MOCK_AGENTS = os.getenv("USE_MOCK_AGENTS", "true").lower() in ("true", "1", "yes")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
APP_URL = os.getenv("APP_URL", "http://localhost:3000")
