# PrivacyGuard 🛡️

> Detect and anonymize Personally Identifiable Information (PII) in your data pipelines — from the command line.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## Overview

**PrivacyGuard** is a lightweight, dependency-minimal CLI tool for data analysts and engineers who need to audit datasets for sensitive information and anonymize it before storage, sharing, or processing — in compliance with GDPR, HIPAA, and similar data protection frameworks.

### Detectable PII Types

| Type | Risk Level | Example |
|------|-----------|---------|
| `email` | MEDIUM | `jane@example.com` |
| `phone_us` | MEDIUM | `+1 (555) 867-5309` |
| `ssn` | **HIGH** | `123-45-6789` |
| `credit_card` | **HIGH** | `4111111111111111` |
| `ip_address` | LOW | `192.168.1.42` |
| `date_of_birth` | MEDIUM | `04/15/1990` |
| `url` | LOW | `https://example.com` |
| `postcode_uk` | LOW | `SW1A 1AA` |

---

## Installation

```bash
git clone https://github.com/syed-ubaid/privacy_guard.git
cd privacy_guard
pip install -r requirements.txt
```

---

## Usage

### Scan text for PII
```bash
python cli.py scan "Contact Jane at jane.doe@example.com, SSN: 123-45-6789"
```
```
⚠️  Found 2 PII instance(s):

  [MEDIUM] email           → 'jane.doe@example.com'  (pos 15-37)
  [HIGH  ] ssn             → '123-45-6789'            (pos 44-55)
```

### Anonymize text
```bash
python cli.py anon "Jane's card: 4111111111111111" --strategy redact
# → Jane's card: [REDACTED:CREDIT_CARD]

python cli.py anon "Email: jane@mail.com" --strategy hash
# → Email: [HASH:a3f5c2d1]

python cli.py anon "Call +1 555 867-5309 or email jane@mail.com" --strategy mask
# → Call ***-***-**** or email ****@****.***
```

### Generate a JSON report
```bash
python cli.py report "SSN: 123-45-6789, card: 4111111111111111, IP: 10.0.0.1"
```
```json
{
  "total": 3,
  "by_type": { "ssn": 1, "credit_card": 1, "ip_address": 1 },
  "by_risk": { "HIGH": 2, "MEDIUM": 0, "LOW": 1 }
}
```

### Scan a CSV file
```bash
python cli.py scan --file sample_data.csv --column notes
python cli.py anon --file sample_data.csv --column notes --strategy mask
```

### Scan/Anonymize a JSON file or API response
```bash
python cli.py scan --file response.json
python cli.py anon --file response.json --strategy redact
```

### Filter by PII type
```bash
python cli.py scan "jane@mail.com, 4111111111111111" --types email credit_card
```

---

## Anonymization Strategies

| Strategy | Description | Output Example |
|----------|-------------|---------------|
| `mask` | Replace with format-preserving placeholder | `****@****.***` |
| `redact` | Replace with labelled redaction tag | `[REDACTED:EMAIL]` |
| `hash` | Replace with SHA-256 short hash | `[HASH:a3f5c2d1]` |

---

## Architecture

```
privacy_guard/
├── detector.py      # Regex-based PII pattern matching engine
├── anonymizer.py    # Masking / redaction / hashing engine
├── json_handler.py  # Recursive JSON & API response scanning engine
├── cli.py           # argparse CLI interface
├── sample_data.csv  # Demo dataset with embedded PII
└── requirements.txt
```

---

## Use Cases

- **GDPR compliance auditing** — scan data exports before sharing
- **Data pipeline pre-processing** — anonymize before feeding ML models
- **Log sanitization** — strip PII from application logs
- **Security reviews** — identify PII leakage in codebases or config files

---

## License

MIT © [Syed Ubaid](https://github.com/syed-ubaid)
