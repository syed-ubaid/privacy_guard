"""
detector.py — PII Detection Engine
Scans text for Personally Identifiable Information using regex patterns.
"""

import re
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+1[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{4}\b"
    ),
    "ssn": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
    ),
    "credit_card": re.compile(
        r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"
    ),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "url": re.compile(
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
    ),
    "date_of_birth": re.compile(
        r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:19|20)\d{2}\b"
    ),
    "postcode_uk": re.compile(
        r"\b[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}\b"
    ),
}

RISK_LEVELS = {
    "ssn": "HIGH",
    "credit_card": "HIGH",
    "email": "MEDIUM",
    "phone_us": "MEDIUM",
    "date_of_birth": "MEDIUM",
    "ip_address": "LOW",
    "url": "LOW",
    "postcode_uk": "LOW",
}


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    start: int
    end: int
    risk: str = field(init=False)

    def __post_init__(self):
        self.risk = RISK_LEVELS.get(self.pii_type, "LOW")

    def __repr__(self):
        return f"PIIMatch(type={self.pii_type!r}, value={self.value!r}, risk={self.risk})"


def detect(text: str, types: List[str] = None) -> List[PIIMatch]:
    """
    Scan *text* for PII. Optionally restrict to specific *types*.

    Args:
        text:  The string to scan.
        types: List of PII type keys to check (default: all).

    Returns:
        A list of PIIMatch objects, sorted by position.
    """
    selected = {k: v for k, v in PATTERNS.items() if types is None or k in types}
    matches: List[PIIMatch] = []

    for pii_type, pattern in selected.items():
        for m in pattern.finditer(text):
            matches.append(PIIMatch(pii_type, m.group(), m.start(), m.end()))

    matches.sort(key=lambda x: x.start)
    return matches


def scan_report(text: str) -> dict:
    """Return a summary report of detected PII by type and risk."""
    matches = detect(text)
    report = {"total": len(matches), "by_type": {}, "by_risk": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}}
    for m in matches:
        report["by_type"].setdefault(m.pii_type, 0)
        report["by_type"][m.pii_type] += 1
        report["by_risk"][m.risk] += 1
    return report


# ---------------------------------------------------------------------------
# Quick demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample = (
        "Contact Jane at jane.doe@example.com or call +1 (555) 867-5309. "
        "Her SSN is 123-45-6789 and card number 4111111111111111. "
        "Server IP: 192.168.1.42. DOB: 04/15/1990."
    )
    print("=== PII Detector Demo ===\n")
    for match in detect(sample):
        print(f"  [{match.risk:6}] {match.pii_type:15} → {match.value!r}")
    print(f"\nReport: {scan_report(sample)}")
