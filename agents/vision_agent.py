import re
import os
from datetime import datetime
from .base_agent import BaseAgent, AgentResult, RiskLevel


try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

class VisionAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "Banknote Vision Verification Agent"

    async def run(self, input_data: dict) -> AgentResult:
        """
        Analyzes an uploaded image of an Indian Rupee note for counterfeiting.
        
        Args:
            input_data (dict): contains "image_path"
        """
        image_path = input_data.get("image_path", "")
        
        # ============ REPLACE THIS MOCK WITH YOUR REAL AGENT ============
        # Real Implementation Instructions:
        # 1. Load the image from image_path using PIL.Image.
        # 2. Run OCR using pytesseract to extract the banknote's unique serial number.
        # 3. Apply computer vision algorithms (or LLM multimodal model like gemini-2.5-flash)
        #    to inspect key security features of Indian currency:
        #    - Security Thread: check color shift (green to blue) and "BHARAT" / "RBI" print.
        #    - Watermark: Mahatma Gandhi watermark and electoral numeral.
        #    - Latent Image: denomination numeral visible at certain angles.
        #    - Microlettering & Bleed lines: check for alignment and quality.
        # 4. Formulate the AgentResult mapping OCR validation and vision authenticity scores.
        # ================================================================

        reasons = []
        evidence = {}
        risk_level = RiskLevel.NEEDS_REVIEW
        confidence = 0.75
        verdict = "Banknote Verification Pending Manual Review"
        next_steps = ["Verify key tactile and security marks manually."]

        # Attempt to perform mock OCR or read the file name for mock triggers
        extracted_serial = ""
        ocr_attempted = False
        ocr_success = False

        if Image and image_path and os.path.exists(image_path):
            ocr_attempted = True
            try:
                # In real scenario, we would run: pytesseract.image_to_string(Image.open(image_path))
                # Let's mock a success if pytesseract is available, otherwise mock a realistic extract
                if pytesseract:
                    # To avoid throwing error when binary is missing:
                    extracted_serial = "7CP 485129"  # Dummy text
                    ocr_success = True
                else:
                    ocr_success = False
            except Exception as e:
                reasons.append(f"Optical character recognition failed: {str(e)}")

        # Trigger logic based on file names for hackathon demo convenience!
        # E.g., if file name contains "fake" or "scam" or "counterfeit"
        file_name = os.path.basename(image_path).lower() if image_path else ""
        
        # Mocking highly realistic currency checks for INR 500 & INR 2000
        # If the filename contains "fake", "counterfeit", "bad", or "invalid", trigger high risk
        if "fake" in file_name or "counterfeit" in file_name or "bad" in file_name:
            risk_level = RiskLevel.HIGH
            confidence = 0.88
            verdict = "CRITICAL: Suspicious Banknote - Potential Counterfeit Detected"
            extracted_serial = "2AA 000000"  # Invalid/Common fake serial
            reasons.append("Banknote Serial Number matches known low-quality counterfeit runs (2AA block).")
            reasons.append("Security thread lacks color shift (remains static yellow/green, no blue transition).")
            reasons.append("Mahatma Gandhi watermark shows heavy blurred boundaries; likely printed, not embedded.")
            reasons.append("Alignment check failed: Latent denomination numeral is completely invisible.")
            
            evidence = {
                "denomination": "500 INR",
                "extracted_serial": extracted_serial,
                "serial_pattern_valid": False,
                "checks": {
                    "security_thread_color_shift": "Failed",
                    "watermark_clarity": "Failed (Blurred)",
                    "latent_image_numeral": "Not Visible",
                    "microlettering_alignment": "Failed",
                    "bleed_lines_tactile": "Smooth (Fake tactile print)"
                }
            }
            
            next_steps = [
                "DO NOT attempt to circulate this note. Circulating counterfeit currency is a criminal offense under Section 178 of BNS.",
                "Take the banknote to the nearest bank branch. Banks are mandated to impound fake notes and issue a receipt.",
                "File an official complaint with your local police station if you remember who handed you this note."
            ]
            
        elif "good" in file_name or "valid" in file_name or "real" in file_name or "genuine" in file_name:
            risk_level = RiskLevel.LOW
            confidence = 0.94
            verdict = "Banknote Verified: Genuine Security Features Detected"
            extracted_serial = "8CD 592831"
            reasons.append("Serial number format validated: correct alphanumeric sequence (2 letters + 1 suffix + 6 digits).")
            reasons.append("Security thread displays proper green-to-blue color shift at 45 degrees.")
            reasons.append("Mahatma Gandhi watermark and multi-directional security window are sharp and crisp.")
            reasons.append("Tactile bleed lines are highly distinct and raised, confirming high-quality intaglio printing.")
            
            evidence = {
                "denomination": "500 INR",
                "extracted_serial": extracted_serial,
                "serial_pattern_valid": True,
                "checks": {
                    "security_thread_color_shift": "Passed",
                    "watermark_clarity": "Passed (Crisp)",
                    "latent_image_numeral": "Visible",
                    "microlettering_alignment": "Passed",
                    "bleed_lines_tactile": "Passed (Raised)"
                }
            }
            next_steps = ["Note appears genuine. Secure to use."]
        else:
            # Neutral / Needs Review (Default fallback when checking generic images)
            risk_level = RiskLevel.NEEDS_REVIEW
            confidence = 0.65
            extracted_serial = "7CP 485129" if ocr_success else "UNDETERMINED"
            verdict = "Needs Physical Verification: Some Features Ambiguous"
            reasons.append("OCR successfully extracted serial number, but visual checks are inconclusive due to lighting or camera resolution.")
            reasons.append("Please check the security thread manually: tilt the note to see if the thread changes from green to blue.")
            reasons.append("Ensure the Mahatma Gandhi portrait is visible when held against light.")
            
            # Validate serial pattern (e.g., standard format like "2 letters + 1 char + 6 numbers" or "3 letters + 6 numbers")
            # Let's check standard Indian note serial regex: e.g. [0-9][A-Z]{2}\s*[0-9]{6} or similar
            # Indian banknotes usually have: prefix (e.g. 1AA, 2AB, or 9AA) + serial (6 digits). Let's check with regex.
            cleaned_serial = extracted_serial.replace(" ", "").upper()
            serial_regex = re.compile(r"^[0-9][A-Z]{2}[0-9]{6}$|^[A-Z]{2}[0-9]{6}$|^[0-9]{2}[A-Z]{2}[0-9]{6}$")
            pattern_valid = bool(serial_regex.match(cleaned_serial)) if cleaned_serial != "UNDETERMINED" else False
            
            if pattern_valid:
                reasons.append(f"Serial number format '{extracted_serial}' is syntactically valid.")
            else:
                reasons.append("Could not confirm a valid Reserve Bank of India serial number format.")

            evidence = {
                "denomination": "Unknown (Verify Manually)",
                "extracted_serial": extracted_serial,
                "serial_pattern_valid": pattern_valid,
                "checks": {
                    "security_thread_color_shift": "Needs Angle Tilt",
                    "watermark_clarity": "Needs Backlight",
                    "latent_image_numeral": "Needs Manual Verification",
                    "microlettering_alignment": "Needs Macro Lens",
                    "bleed_lines_tactile": "Feel tactile print manually"
                }
            }
            next_steps = [
                "Tilt the note to verify the color shift of the green security thread to blue.",
                "Feel the raised intaglio printing on Mahatma Gandhi's portrait, Ashok Pillar emblem, and bleed lines.",
                "Hold the note against light to verify the semi-transparent watermark of Mahatma Gandhi and the denomination value."
            ]

        return AgentResult(
            verdict=verdict,
            risk_level=risk_level,
            confidence=round(confidence, 2),
            reasons=reasons,
            evidence=evidence,
            next_steps=next_steps,
            agent_name=self.name,
            timestamp=datetime.utcnow()
        )
