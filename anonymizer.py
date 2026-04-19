"""
anonymizer.py — PII Anonymization Engine
Replaces detected PII tokens using mask, redact, or hash strategies.
"""

import hashlib
import re
from typing import List, Literal

from detector import detect, PIIMatch, PATTERNS

Strategy = Literal["mask", "redact", "hash"]

# Mask characters per type
MASK_TEMPLATES = {
    "email":       "****@****.***",
    "phone_us":    "***-***-****",
    "ssn":         "***-**-****",
    "credit_card": "**** **** **** ****",
    "ip_address":  "***.***.***.***",
    "url":         "[URL REDACTED]",
    "date_of_birth": "**/**/****",
    "postcode_uk": "*** ***",
}


def _mask(match: PIIMatch) -> str:
    return MASK_TEMPLATES.get(match.pii_type, f"[{match.pii_type.upper()}]")


def _redact(match: PIIMatch) -> str:
    return f"[REDACTED:{match.pii_type.upper()}]"


def _hash_value(match: PIIMatch) -> str:
    digest = hashlib.sha256(match.value.encode()).hexdigest()[:8]
    return f"[HASH:{digest}]"


STRATEGIES = {
    "mask":   _mask,
    "redact": _redact,
    "hash":   _hash_value,
}


def anonymize(text: str, strategy: Strategy = "mask", types: List[str] = None) -> str:
    """
    Replace all PII in *text* with anonymized placeholders.

    Args:
        text:     Input text containing potential PII.
        strategy: One of 'mask', 'redact', or 'hash'.
        types:    Restrict anonymization to specific PII type keys.

    Returns:
        Anonymized string.
    """
    handler = STRATEGIES.get(strategy)
    if handler is None:
        raise ValueError(f"Unknown strategy '{strategy}'. Choose from: mask, redact, hash.")

    matches = detect(text, types=types)
    # Process in reverse order so index positions remain valid
    result = text
    for match in reversed(matches):
        replacement = handler(match)
        result = result[: match.start] + replacement + result[match.end :]
    return result


def anonymize_csv_column(series, strategy: Strategy = "mask", types: List[str] = None):
    """
    Anonymize a pandas Series column in-place (returns new Series).
    Requires pandas.
    """
    try:
        import pandas as pd  # noqa: F401
    except ImportError:
        raise ImportError("pandas is required to use anonymize_csv_column()")
    return series.apply(lambda val: anonymize(str(val), strategy=strategy, types=types))


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample = (
        "Contact Jane at jane.doe@example.com or call +1 (555) 867-5309. "
        "Her SSN is 123-45-6789 and card number 4111111111111111."
    )
    print("=== Anonymizer Demo ===\n")
    print(f"ORIGINAL : {sample}\n")
    for strat in ("mask", "redact", "hash"):
        print(f"{strat.upper():7}: {anonymize(sample, strategy=strat)}")
