"""Deterministic prevention advice. Static, editable text; no LLM.

Advice depends on the analysis kind and the *effective* risk level. A few extra lines are
added only when the agent's own verdict/reasons actually mention the topic.
"""
from __future__ import annotations

from typing import Iterable, List, Sequence

from .schemas import UnifiedRiskLevel

L = UnifiedRiskLevel
ELEVATED = {L.MEDIUM, L.HIGH, L.CRITICAL}

SCAM_CORE = [
    "Do not transfer money.",
    "Do not share OTP, PIN or password with anyone.",
    "Contact your bank using an official channel (number on your card or the bank's official app/website).",
    "Report the incident through an official channel such as the National Cyber Crime Reporting Portal (cybercrime.gov.in) or helpline 1930.",
]
SCAM_UNVERIFIED = [
    "Treat this message as unverified: do not click links, pay, or reply until you confirm through an official channel.",
    "Do not share OTP, PIN or password with anyone.",
]
SCAM_LOW = ["Even when no scam signs were found, never share OTP, PIN or password with anyone."]
# (keywords found in verdict/reasons, extra advice)
SCAM_TOPICS = [
    (("digital arrest", "arrest", "warrant", "cbi", "police", "custody"),
     "Genuine agencies do not demand money or keep you on a call/video call to 'settle' a case; hang up and verify with the agency directly."),
    (("otp",), "No genuine bank or service needs your OTP to send you money or 'cancel' something."),
    (("upi", "collect request", "qr"), "Do not approve unexpected UPI collect requests or scan QR codes to 'receive' money."),
]

NOTE_ALWAYS = [
    "Do not rely only on an uploaded image for authenticity; check the note physically (feel, security thread, watermark).",
    "Seek verification from a bank or another appropriate official source.",
]
NOTE_ELEVATED = [
    "Do not pass the note on to anyone else.",
    "If you believe the note is counterfeit, report it to the bank or police rather than spending it.",
]
NOTE_UNVERIFIED = ["If the image was unclear, retake it in good light, flat and fully in frame."]

HOTSPOT_ELEVATED = [
    "Exercise additional caution with unsolicited calls, messages and requests in this area/category of fraud.",
    "Report suspicious activity through appropriate channels (cybercrime.gov.in or helpline 1930).",
    "Do not expose personal information (OTP, PIN, Aadhaar, card or account details).",
]
HOTSPOT_LOW = ["Stay aware of common fraud tactics and do not expose personal information."]
HOTSPOT_UNVERIFIED = ["Escalate for manual review before relying on this assessment."]

FRAUD_INTEL_NOT_VERIFIED = (
    "This analysis used only the information you provided; no police, bank or government "
    "database was checked, so a lack of red flags is not proof that something is genuine."
)
FRAUD_INTEL_ELEVATED = [
    "Verify any suspicious payment request through an official channel (the number on your card or the organisation's official app/website), not through the contact details in the message.",
    "Do not transfer money or share OTP, PIN or password with anyone.",
    "Preserve evidence: keep screenshots, messages, numbers/UPI IDs/URLs, transaction details and dates; do not delete them.",
    "If you suspect fraud, report it through an official channel such as the National Cyber Crime Reporting Portal (cybercrime.gov.in) or helpline 1930, and inform your bank if money was involved. This is general guidance, not legal advice.",
]
FRAUD_INTEL_UNVERIFIED = [
    "Treat these indicators as unverified: do not pay, click links or share details until you confirm through an official channel.",
    "Do not share OTP, PIN or password with anyone.",
    "Preserve the messages, numbers and other details in case you need to report them.",
]
FRAUD_INTEL_LOW = ["Even if no warning signs were found, never share OTP, PIN or password, and verify payment requests through official channels."]

VOICE_NOT_VERIFIED = (
    "This analysis is based only on the provided transcript text; it does not verify who the caller is."
)
VOICE_ELEVATED = [
    "Do not transfer money during an unsolicited call, however urgent or official the caller sounds.",
    "Verify the caller independently: hang up and call the organisation's official number from its website or your card, not a number the caller gives you.",
    "Do not share OTP, PIN or password with anyone.",
    "Preserve the transcript and call details (number, date/time, what was demanded); do not delete them.",
    "If you suspect fraud, report it through an official channel such as cybercrime.gov.in or helpline 1930. This is general guidance, not legal advice.",
]
VOICE_UNVERIFIED = [
    "Treat the call as unverified: do not pay or share any details until you verify the caller independently through an official channel.",
    "Do not share OTP, PIN or password with anyone.",
]
VOICE_LOW = ["Even if the text looked harmless, never share OTP, PIN or password during a call, and verify unexpected callers independently."]


def _mentions(text: str, words: Iterable[str]) -> bool:
    return any(w in text for w in words)


def advice_for(kind: str, level: UnifiedRiskLevel, verdict: str, reasons: Sequence[str]) -> List[str]:
    text = (verdict + " " + " ".join(reasons)).lower()
    out: List[str] = []
    if kind == "scam":
        if level in ELEVATED:
            out += SCAM_CORE
            out += [tip for words, tip in SCAM_TOPICS if _mentions(text, words)]
        elif level == L.NEEDS_REVIEW:
            out += SCAM_UNVERIFIED
        else:
            out += SCAM_LOW
    elif kind == "note":
        out += NOTE_ALWAYS
        if level in ELEVATED:
            out += NOTE_ELEVATED
        elif level == L.NEEDS_REVIEW:
            out += NOTE_UNVERIFIED
    elif kind == "hotspot":
        if level in ELEVATED:
            out += HOTSPOT_ELEVATED
        elif level == L.NEEDS_REVIEW:
            out += HOTSPOT_UNVERIFIED
        else:
            out += HOTSPOT_LOW
    elif kind == "fraud_intel":
        out.append(FRAUD_INTEL_NOT_VERIFIED)
        if level in ELEVATED:
            out += FRAUD_INTEL_ELEVATED
            out += [tip for words, tip in SCAM_TOPICS if _mentions(text, words)]
        elif level == L.NEEDS_REVIEW:
            out += FRAUD_INTEL_UNVERIFIED
        else:
            out += FRAUD_INTEL_LOW
    elif kind == "voice":
        out.append(VOICE_NOT_VERIFIED)
        if level in ELEVATED:
            out += VOICE_ELEVATED
            out += [tip for words, tip in SCAM_TOPICS if _mentions(text, words)]
        elif level == L.NEEDS_REVIEW:
            out += VOICE_UNVERIFIED
        else:
            out += VOICE_LOW
    return out


def build_prevention(entries: Sequence[tuple]) -> List[str]:
    """entries: (kind, effective_level, verdict, reasons) per contributing agent."""
    seen, merged = set(), []
    for kind, level, verdict, reasons in entries:
        for line in advice_for(kind, level, verdict, reasons):
            if line not in seen:
                seen.add(line)
                merged.append(line)
    return merged
