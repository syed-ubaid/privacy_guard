"""
cli.py — PrivacyGuard Command-Line Interface

Usage examples:
  python cli.py scan    "Contact me at test@email.com"
  python cli.py anon    "Contact me at test@email.com" --strategy redact
  python cli.py report  "SSN: 123-45-6789, card: 4111111111111111"
  python cli.py scan    --file sample_data.csv --column notes
"""

import argparse
import json
import sys

from detector import detect, scan_report
from anonymizer import anonymize, anonymize_csv_column


def cmd_scan(args):
    text = _get_text(args)
    matches = detect(text, types=args.types or None)
    if not matches:
        print("✅ No PII detected.")
        return
    print(f"⚠️  Found {len(matches)} PII instance(s):\n")
    for m in matches:
        print(f"  [{m.risk:6}] {m.pii_type:15} → {m.value!r}  (pos {m.start}-{m.end})")


def cmd_anon(args):
    text = _get_text(args)
    result = anonymize(text, strategy=args.strategy, types=args.types or None)
    print(result)


def cmd_report(args):
    text = _get_text(args)
    report = scan_report(text)
    print(json.dumps(report, indent=2))


def _get_text(args) -> str:
    if args.file:
        try:
            import pandas as pd
            df = pd.read_csv(args.file)
            col = args.column or df.columns[0]
            return "\n".join(df[col].astype(str).tolist())
        except ImportError:
            print("pandas required for CSV mode. Install with: pip install pandas")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading CSV: {e}")
            sys.exit(1)
    elif args.text:
        return args.text
    else:
        print("Provide text via argument or --file flag.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="privacy_guard",
        description="🛡️  PrivacyGuard — Detect and anonymize PII in your data.",
    )
    parser.add_argument("--file", help="Path to a CSV file")
    parser.add_argument("--column", help="Column name to scan (default: first column)")
    parser.add_argument(
        "--types", nargs="+",
        help="PII types to target: email phone_us ssn credit_card ip_address url date_of_birth postcode_uk",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Detect PII and list matches")
    p_scan.add_argument("text", nargs="?", default=None, help="Text to scan")
    p_scan.set_defaults(func=cmd_scan)

    # anon
    p_anon = sub.add_parser("anon", help="Anonymize PII in text")
    p_anon.add_argument("text", nargs="?", default=None, help="Text to anonymize")
    p_anon.add_argument("--strategy", choices=["mask", "redact", "hash"], default="mask")
    p_anon.set_defaults(func=cmd_anon)

    # report
    p_rep = sub.add_parser("report", help="Generate a JSON summary report")
    p_rep.add_argument("text", nargs="?", default=None, help="Text to report on")
    p_rep.set_defaults(func=cmd_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
