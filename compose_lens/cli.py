import argparse
import json
import sys
from .audit import InputError, LIMITATIONS, audit, load_compose

RANK = {"info": 0, "medium": 1, "high": 2, "none": 3}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review a Compose file locally without contacting Docker or executing containers.")
    parser.add_argument("file", help="Path to a single Compose YAML file")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=tuple(RANK), default="high", help="Minimum severity that returns exit code 1 (default: high); none always returns 0 for valid input")
    args = parser.parse_args(argv)
    try:
        findings = audit(load_compose(args.file))
    except InputError as exc:
        if args.format == "json":
            print(json.dumps({"schema_version": 1, "error": str(exc)}))
        else:
            print(f"Input error: {exc}", file=sys.stderr)
        return 2
    counts = {level: sum(f.severity == level for f in findings) for level in ("high", "medium", "info")}
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "summary": counts, "findings": [f.to_dict() for f in findings], "limitations": LIMITATIONS}, indent=2))
    else:
        print("Compose Lens | static configuration review")
        print(" | ".join(f"{level}: {count}" for level, count in counts.items()))
        for finding in findings:
            # JSON escaping prevents control characters in names from reaching the terminal.
            service = json.dumps(finding.service, ensure_ascii=True)
            print(f"\n[{finding.severity.upper()}] {finding.rule_id} {service} / {finding.field}: {finding.title}")
            print(f"  Why: {finding.explanation}\n  Review: {finding.recommendation}")
        if not findings:
            print("No findings from the implemented rules. This does not establish that the configuration is secure.")
        print("\nLimitations:")
        for limitation in LIMITATIONS:
            print(f"  - {limitation}")
    return int(any(RANK[f.severity] >= RANK[args.fail_on] for f in findings))
