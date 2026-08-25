# Suraksha AI — Digital Public Safety Platform 🚨
### Hackathon Theme: Defeating Counterfeiting, Fraud & Digital Arrest Scams in India

Suraksha AI is a complete, production-ready hackathon prototype designed to protect Indian citizens from highly coercive **Digital Arrest scams**, **UPI/financial phishing**, and **counterfeit currency runs (Mahatma Gandhi Banknote series)**.

It uses a unique **Multi-Agent Safety Pipeline** where independent LLM-based agents cross-examine threats, arguing against false positives and formulating precise emergency response blueprints to freeze stolen funds within the critical first hour.

---

## 🏗️ System Architecture

Suraksha AI isolates all AI agent logic inside a decoupled `agents/` shell package. This design lets you develop, swap, or scale actual LLM or Computer Vision models without modifying any API endpoints, database schemas, or frontend pages.

```text
               +-------------------------------------------+
               |              Static Frontend              |
               | (HTML5 + Tailwind CSS CDN + Vanilla JS)   |
               +---------------------|---------------------+
                                     | (API Requests)
                                     v
               +-------------------------------------------+
               |          FastAPI Backend (main.py)        |
               +---------------------|---------------------+
                                     | (Orchestration)
                                     v
               +-------------------------------------------+
               |        Orchestrator Pipeline Shell        |
               +---------------------|---------------------+
                                     |
         +---------------------------+---------------------------+
         | (Message Scan Pipeline)                               | (Banknote Scan)
         v                                                       v
+------------------+     +------------------+           +------------------+
|  Detection Agent | --> |Verify Agent (Risk|           |   Vision Agent   |
| (Primary LLM/Tag)|     |Devil's Advocate) |           |  (OCR + Security)|
+------------------+     +--------|---------+           +--------|---------+
                                  |                              |
                                  | (Risk >= MEDIUM)             |
                                  v                              |
                         +------------------+                    |
                         | Reporting Agent  |                    |
                         | (1930 / Portal)  |                    |
                         +--------|---------+                    |
                                  |                              |
                                  +--------------+---------------+
                                                 | (Save Run logs)
                                                 v
                                  +------------------------------+
                                  |    SQLite DB (audit_log)     |
                                  +------------------------------+
```

---

## 📂 Project Structure

```text
/main.py                  → FastAPI app serving API endpoints and static templates
/config.py                → Environment loader checking .env and USE_MOCK_AGENTS
/database.py              → SQLAlchemy SQLite engine defining AuditLog table
/models.py                → Pydantic validation schemas (ScanRequest, StatsResponse)
/requirements.txt         → Python dependencies index
/README.md                → Full architecture and deployment guide
/.env.example             → Example environmental settings
/agents/
    ├── __init__.py       → Exposes the agents package
    ├── base_agent.py     → Abstract class BaseAgent & AgentResult contract
    ├── detection_agent.py→ Message scanner (Classifies government impersonation, urgent pressure)
    ├── verification_agent.py→ Verification cross-examiner (Devil's advocate checking false positives)
    ├── reporting_agent.py→ Incident counselor (Generates 1930 & cybercrime.gov.in blueprint)
    ├── vision_agent.py   → Counterfeit note analyzer (Serial number OCR + security thread check)
    └── orchestrator.py   → Manages agent pipeline execution and SQL logging
/data/
    ├── sample_messages.json → Preloaded high-fidelity mock alerts (scam/genuine) for testing
    └── mock_hotspots.json   → Coordinates of 25 cybercrime complaint hotspots across India
/static/
    ├── index.html        → Main dashboard with operational analytics
    ├── scam.html         → Interactive SMS / call transcript scanner
    ├── note.html         → Interactive banknote image uploader
    ├── report.html       → Actionable wizard for emergency locks & official filings
    ├── map.html          → Leaflet.js cybercrime geospatial map
    ├── audit.html        → Read-only audit trail database log
    ├── app.js            → API calling and visual pipeline animation states
    └── style.css         → Custom typography (Inter/Space Grotesk) and glowing card filters
```

---

## 📃 The AgentResult Contract

Every agent in Suraksha AI **MUST** return an `AgentResult` object. This strict schema acts as the interface contract, ensuring consistency regardless of what AI models are swapped in.

Defined inside `agents/base_agent.py`:

```python
class AgentResult(BaseModel):
    verdict: str         # Short descriptive string of the final verdict
    risk_level: str      # Classification enum: "LOW", "MEDIUM", "HIGH", "NEEDS_REVIEW"
    confidence: float    # Classification confidence rating (0.0 to 1.0)
    reasons: List[str]   # Detailed bullet points backing up the assessment
    evidence: Dict       # Key/Value attributes extracted (e.g. ocr_serial, matching_keywords)
    next_steps: List[str]# Immediate actionable guidelines
    agent_name: str      # Debug signature of the running agent
    timestamp: datetime  # UTC time of analysis completion
```

---

## 🔌 Plugging In Your Real AI Models

To replace the mock stubs with real generative models (e.g., using Gemini API via the `@google/genai` library), you only need to modify code inside the `agents/` folder. **Never touch main.py or your UI files.**

### For Text Agents (`detection_agent.py`, `verification_agent.py`, `reporting_agent.py`)

1. Ensure your Gemini API Key is loaded (e.g. from `.env` or injected secrets).
2. Inside the agent's `run()` method, initialize the Google GenAI SDK client:
   ```python
   from google import genai
   from google.genai import types
   import json
   
   client = genai.Client()
   ```
3. Use structural schemas to force Gemini to return JSON perfectly matching our `AgentResult` model:
   ```python
   response = client.models.generate_content(
       model='gemini-2.5-flash',
       contents='Analyze this scam threat: ' + text,
       config=types.GenerateContentConfig(
           response_mime_type="application/json",
           response_schema=AgentResult,
       ),
   )
   result_obj = AgentResult.parse_raw(response.text)
   ```

### For Vision Agent (`vision_agent.py`)

1. Load your uploaded banknote image file.
2. Initialize the client and call Gemini's multimodal capabilities to check safety marks:
   ```python
   response = client.models.generate_content(
       model='gemini-2.5-flash',
       contents=[
           types.Part.from_bytes(
               data=open(image_path, "rb").read(),
               mime_type="image/jpeg",
           ),
           "Extract the serial number. Check the alignment, Gandhi watermark, and color-shifting security thread. Grade risk as HIGH or LOW."
       ],
       config=types.GenerateContentConfig(
           response_mime_type="application/json",
           response_schema=AgentResult
       )
   )
   ```

---

## 🚀 Installation & Local Run

### Prerequisites
- Python 3.10 or 3.11
- Pip installed on your system

### 1. Clone & Set Up Directory
Ensure you are in the project workspace folder.

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize Environment Configurations
Create a `.env` file from the example:
```bash
cp .env.example .env
```
Keep `USE_MOCK_AGENTS=true` enabled to run out-of-the-box using the high-fidelity rule engine with realistic confidence values!

### 4. Run the Dev Server
```bash
uvicorn main:app --port 3000 --host 0.0.0.0 --reload
```
Open your browser at **`http://localhost:3000`** to interact with the full, beautifully-rendered platform dashboard!
