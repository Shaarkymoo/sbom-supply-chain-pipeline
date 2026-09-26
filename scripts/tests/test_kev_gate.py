import json
import subprocess
import sys
from pathlib import Path

KEV_REPORT = {
    "Results": [
        {
            "Target": "python:3.12-slim (debian:12)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "CISAKEV": {"KnownRansomwareCampaignUse": "Known"}},
                {"VulnerabilityID": "CVE-2024-0002"},
            ],
        }
    ]
}

CLEAN_REPORT = {
    "Results": [
        {"Target": "python:3.12-slim (debian:12)", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0002"}]}
    ]
}


def _run(report: dict) -> subprocess.CompletedProcess:
    p = Path("/tmp/trivy-test.json")
    p.write_text(json.dumps(report))
    return subprocess.run([sys.executable, "scripts/kev-gate.py", str(p)], capture_output=True, text=True)


def test_kev_gate_fails_on_kev_vulnerability() -> None:
    result = _run(KEV_REPORT)
    assert result.returncode == 1
    assert "CVE-2024-0001" in result.stdout


def test_kev_gate_passes_without_kev() -> None:
    result = _run(CLEAN_REPORT)
    assert result.returncode == 0
    assert "OK" in result.stdout