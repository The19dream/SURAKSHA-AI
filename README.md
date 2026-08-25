# Suraksha AI — Digital Public Safety Platform

Suraksha AI is an AI-powered digital public safety platform designed to help users identify and understand potential **digital scams, financial fraud, suspicious messages, counterfeit currency, and cybercrime hotspots**.

The platform uses Google's **Gemini API** to analyze text, images, and hotspot information and returns a structured assessment containing a verdict, risk level, confidence score, supporting reasons, evidence, and recommended next steps.

> **Note:** Suraksha AI is an assistive analysis tool. Its results should not be treated as definitive legal, financial, or law-enforcement decisions.

---

## Features

### 1. Scam & Fraud Message Detection

Users can submit suspicious SMS messages, WhatsApp messages, emails, or other text content for analysis.

Suraksha AI can analyze patterns associated with:

* Digital arrest scams
* UPI fraud
* Banking fraud
* OTP scams
* Fake police/government impersonation
* Fake courier scams
* Phishing attempts
* Other suspicious or fraudulent messages

The AI returns:

* Final verdict
* Risk level
* Confidence score
* Reasons for the assessment
* Extracted evidence
* Recommended next steps

---

### 2. Indian Banknote Analysis

The platform provides an image-based banknote analysis feature using Gemini's multimodal capabilities.

The Vision AI component can examine characteristics such as:

* Security thread
* Watermark
* Microlettering
* Serial number
* Latent image
* See-through register
* Print quality
* Colour consistency
* Possible signs of tampering
* Overall authenticity indicators

The result is classified as:

* `LOW`
* `MEDIUM`
* `HIGH`
* `NEEDS_REVIEW`

For uncertain cases, the system recommends manual verification rather than presenting an uncertain result as definitive.

---

### 3. Cybercrime Hotspot Analysis

Suraksha AI includes a cybercrime hotspot interface that displays geographic incident data.

Users can select a hotspot and provide information such as:

* City
* Crime type
* Incident date
* Incident description

The Hotspot AI component then generates an AI-based risk assessment containing:

* Verdict
* Risk level
* Confidence
* Reasons
* Evidence
* Recommended next steps

The project currently uses sample/mock hotspot data for demonstration.

---

### 4. Audit Logging

Analysis results are recorded in a local **SQLite database**.

The audit system stores information such as:

* Input text or uploaded file identifier
* SHA-256 input hash
* Verdict
* Risk level
* Confidence
* Timestamp

This provides a basic history of analyses performed through the platform.

---

## System Architecture

The current version intentionally uses a simpler architecture rather than the earlier multi-agent orchestrator design.

```text
                    ┌─────────────────────────┐
                    │      Web Interface      │
                    │ HTML / CSS / JavaScript │
                    └────────────┬────────────┘
                                 │
                                 │ HTTP / REST
                                 ▼
                    ┌─────────────────────────┐
                    │     FastAPI Backend     │
                    │        main.py          │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             │                   │                   │
             ▼                   ▼                   ▼
    ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
    │  Suraksha AI   │  │   Vision AI    │  │   Hotspot AI   │
    │ Text Analysis  │  │ Image Analysis │  │ Hotspot Risk   │
    └───────┬────────┘  └───────┬────────┘  └───────┬────────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │       Gemini API        │
                    │  Google Generative AI  │
                    └─────────────────────────┘

                                │
                                ▼
                    ┌─────────────────────────┐
                    │      SQLite Database    │
                    │       Audit Logs        │
                    └─────────────────────────┘
```

---

## AI Components

The project uses a common `BaseAgent` interface and a standardized `AgentResult` structure.

### SurakshaAgent

Responsible for analyzing suspicious text messages.

```text
Input Text
    ↓
Gemini AI
    ↓
Risk Classification
    ↓
Structured AgentResult
```

### VisionAgent

Responsible for image-based Indian banknote analysis.

```text
Banknote Image
      ↓
Gemini Multimodal Analysis
      ↓
Security Feature Assessment
      ↓
Structured AgentResult
```

### HotspotAgent

Responsible for analyzing cybercrime hotspot information.

```text
Hotspot Information
      ↓
Gemini AI
      ↓
Risk Assessment
      ↓
Structured AgentResult
```

---

## AgentResult

All AI components return a standardized result structure.

```python
class AgentResult:
    verdict: str
    risk_level: RiskLevel
    confidence: float
    reasons: list
    evidence: dict
    next_steps: list
    agent_name: str
    timestamp: datetime
```

### Risk Levels

| Level          | Meaning                                                             |
| -------------- | ------------------------------------------------------------------- |
| `LOW`          | Little evidence of an immediate threat                              |
| `MEDIUM`       | Suspicious indicators are present                                   |
| `HIGH`         | Strong indicators of a potential threat                             |
| `NEEDS_REVIEW` | The available information is insufficient for a reliable conclusion |

---

## Project Structure

```text
SURAKSHA-AI/
│
├── agents/
│   ├── __init__.py
│   ├── base_agent.py
│   ├── suraksha_agent.py
│   ├── vision_agent.py
│   ├── vision_agent_new.py
│   └── hotspot_agent.py
│
├── data/
│   ├── mock_hotspots.json
│   └── sample_messages.json
│
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css
│
├── static/
│   ├── index.html
│   ├── scam.html
│   ├── note.html
│   ├── map.html
│   ├── report.html
│   ├── audit.html
│   ├── app.js
│   └── style.css
│
├── config.py
├── database.py
├── models.py
├── main.py
├── requirements.txt
├── package.json
├── .env.example
├── .gitignore
└── suraksha_ai.db
```

---

## Technology Stack

### Backend

* Python
* FastAPI
* Uvicorn
* Pydantic
* SQLAlchemy
* SQLite

### AI

* Google Gemini API
* `google-genai`
* Gemini multimodal capabilities for image analysis

### Frontend

* HTML
* CSS
* JavaScript
* React/TypeScript components
* Vite configuration
* Leaflet-based map interface

### Other Libraries

* Pillow
* python-dotenv
* python-multipart

---

## Requirements

Before running the project, make sure you have:

* Python 3.10+
* pip
* A Google Gemini API key
* Git (optional, for development/version control)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/The19dream/SURAKSHA-AI.git
cd SURAKSHA-AI
```

### 2. Create a Virtual Environment

Windows:

```powershell
python -m venv .venv
```

Activate it using PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Gemini API

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

The project loads the API key through an environment variable.

**Never commit your real `.env` file or API key to GitHub.**

The repository includes `.env.example` as a safe configuration template.

---

## Run the Application

From the project root:

```bash
uvicorn main:app --reload
```

The backend will normally be available at:

```text
http://127.0.0.1:8000
```

Open the application in your browser:

```text
http://127.0.0.1:8000
```

FastAPI's interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

---

## API Endpoints

### Scam Detection

```http
POST /api/scam/check
```

Analyzes a suspicious text message.

Example request:

```json
{
  "text": "Your bank account will be blocked. Send your OTP immediately."
}
```

---

### Banknote Analysis

```http
POST /api/note/check
```

Accepts an uploaded banknote image and returns an AI-based authenticity assessment.

---

### Cybercrime Hotspots

```http
GET /api/hotspots
```

Returns the project's hotspot data.

---

### Hotspot Analysis

```http
POST /api/hotspot/analyze
```

Sends hotspot information to the Hotspot AI component for analysis.

---

### Sample Messages

```http
GET /api/sample-messages
```

Returns the sample messages included with the project for testing and demonstration.

---

## Example Analysis Flow

For a suspicious message:

```text
User enters suspicious message
            ↓
       FastAPI API
            ↓
      SurakshaAgent
            ↓
        Gemini API
            ↓
   Structured JSON result
            ↓
 ┌────────────────────────┐
 │ Verdict                │
 │ Risk Level             │
 │ Confidence             │
 │ Reasons                │
 │ Evidence               │
 │ Next Steps             │
 └────────────────────────┘
            ↓
       SQLite Audit Log
```

---

## Security & Privacy

The project is designed to avoid storing the actual Gemini API key in source code.

Use:

```text
.env
```

for local secrets and keep it out of version control.

The `.gitignore` file excludes environment files and virtual environments.

For a production deployment, additional security controls should be implemented, including:

* Authentication and authorization
* Secure secret management
* Rate limiting
* Input validation and sanitization
* HTTPS
* Secure file upload handling
* Database access controls
* Proper logging and monitoring
* Protection against prompt injection and malicious inputs

---

## Current Limitations

Suraksha AI is currently a **prototype / development project** and should not be considered a replacement for official verification or law-enforcement systems.

Current limitations include:

* AI results may be incorrect or incomplete.
* Banknote image analysis cannot guarantee physical authenticity.
* Hotspot information currently uses demonstration/sample data.
* The system relies on the availability of the Gemini API.
* Some analysis results require human verification.
* The application is primarily configured for local development.

---

## Future Improvements

Potential future development areas include:

* Integration with official cybercrime reporting systems
* Real-time cybercrime intelligence
* More advanced scam classification
* Multilingual Indian-language support
* Improved banknote computer-vision verification
* Real-time threat intelligence
* Better geographic crime analytics
* User authentication
* Production-grade database infrastructure
* Automated incident reporting workflows
* Explainable AI improvements
* Advanced fraud pattern detection

---

## Why Suraksha AI?

Digital fraud is increasingly becoming more sophisticated, with attackers using social engineering, impersonation, urgency, and financial manipulation to target users.

Suraksha AI aims to provide a simple interface where users can submit suspicious information and receive an understandable assessment of:

**What is happening → Why it may be dangerous → How serious it appears → What the user should do next.**

---

## Disclaimer

Suraksha AI provides AI-assisted analysis for educational, research, and demonstration purposes.

AI-generated assessments are not guaranteed to be accurate and should not be treated as official confirmation that a message, transaction, person, or banknote is fraudulent or genuine.

When dealing with suspected fraud or counterfeit currency, users should contact the appropriate bank, financial institution, cybercrime authority, or law-enforcement agency.

---

## License

This project is currently intended as an educational and development project.

Add an appropriate open-source license to this repository if you decide to distribute the project publicly under specific licensing terms.

---

## Author

**Harsh Wardhan**

GitHub: [@The19dream](https://github.com/The19dream)

Repository: [SURAKSHA-AI](https://github.com/The19dream/SURAKSHA-AI)
