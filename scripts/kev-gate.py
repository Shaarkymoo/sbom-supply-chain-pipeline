#!/usr/bin/env python3
"""Fail the build if any Trivy finding is on the CISA KEV catalog."""

import json
import sys
from pathlib import Path


def main() -> None:
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("trivy.json")
    report = json.loads(report_path.read_text())
    kev = [
        {"id": vuln.get("VulnerabilityID"), "target": result.get("Target")}
        for result in report.get("Results", [])
        for vuln in result.get("Vulnerabilities", [])
        if vuln.get("CISAKEV")
    ]
    if kev:
        print("FAIL: actively-exploited (CISA KEV) vulnerabilities found:")
        for item in kev:
            print(f"  - {item['id']} in {item['target']}")
        sys.exit(1)
    print("OK: no CISA KEV (actively-exploited) vulnerabilities")


if __name__ == "__main__":
    main()