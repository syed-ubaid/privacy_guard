"""
json_handler.py — PrivacyGuard JSON & API Response Handler
Recursively scans and anonymizes nested JSON structures (dicts and lists) for PII.
"""

from typing import Any, List
from detector import detect
from anonymizer import anonymize, Strategy

# Keys to automatically mask their values if matched
SENSITIVE_KEYS = {
    "ssn", "social_security", "credit_card", "card_num", "password", "passphrase",
    "email", "phone", "mobile", "birth_date", "dob", "salary", "address", "ip_address"
}


def anonymize_json(data: Any, strategy: Strategy = "mask", types: List[str] = None) -> Any:
    """
    Recursively traverse and anonymize PII in JSON objects (dicts and lists).
    Supports scanning both the values (using regex patterns) and key identifiers.
    """
    if isinstance(data, dict):
        anonymized_dict = {}
        for k, v in data.items():
            k_lower = k.lower()
            # If the key itself is highly sensitive, mask the value immediately
            if any(sens_key in k_lower for sens_key in SENSITIVE_KEYS) and isinstance(v, (str, int, float)):
                anonymized_dict[k] = _anonymize_scalar(str(v), strategy, label=k.upper())
            else:
                anonymized_dict[k] = anonymize_json(v, strategy, types)
        return anonymized_dict

    elif isinstance(data, list):
        return [anonymize_json(item, strategy, types) for item in data]

    elif isinstance(data, str):
        # Scan standard string value for PII using the regex detector
        return anonymize(data, strategy, types)

    return data


def _anonymize_scalar(val: str, strategy: Strategy, label: str) -> str:
    """Mask a single scalar value based on key context."""
    if strategy == "redact":
        return f"[REDACTED:{label}]"
    elif strategy == "hash":
        import hashlib
        digest = hashlib.sha256(val.encode()).hexdigest()[:8]
        return f"[HASH:{digest}]"
    else:  # mask
        if "EMAIL" in label:
            return "****@****.***"
        elif "SSN" in label:
            return "***-**-****"
        elif "CARD" in label or "CREDIT" in label:
            return "**** **** **** ****"
        elif "PHONE" in label or "MOBILE" in label:
            return "***-***-****"
        return "********"


# Quick Demo
if __name__ == "__main__":
    import json
    sample_json = {
        "user_id": 1001,
        "profile": {
            "name": "Jane Doe",
            "email_address": "jane.doe@gmail.com",
            "phone": "+1-555-019-2834"
        },
        "billing": {
            "credit_card": "4111222233334444",
            "salary": 95000,
            "ip": "127.0.0.1"
        },
        "comments": [
            "Sent an email to supervisor.doe@company.org yesterday.",
            "Please call me back tomorrow."
        ]
    }
    
    print("=== JSON PII Anonymizer Demo ===\n")
    print("Original JSON:")
    print(json.dumps(sample_json, indent=2))
    
    print("\nMasked JSON:")
    masked = anonymize_json(sample_json, strategy="mask")
    print(json.dumps(masked, indent=2))
