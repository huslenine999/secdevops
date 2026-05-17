import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SCAN_DIR = Path("scans")

BANDIT_REPORT = SCAN_DIR / "bandit-report.json"
SAFETY_REPORT = SCAN_DIR / "safety-report.json"
TRIVY_REPORT = SCAN_DIR / "trivy-report.json"

FAIL_ON_BANDIT_SEVERITIES = {"HIGH"}
FAIL_ON_SAFETY = True
FAIL_ON_TRIVY_SEVERITIES = {"HIGH", "CRITICAL"}


def load_json(path: Path) -> Any:
    if not path.exists():
        print(f"[WARN] Missing report: {path}")
        return None

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        print(f"[WARN] Invalid JSON report: {path}")
        return None


def analyze_bandit(report: Dict[str, Any]) -> Dict[str, Any]:
    if not report:
        return {
            "tool": "Bandit",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    issues = report.get("results", []) if report else []

    high_issues = [
        issue for issue in issues
        if issue.get("issue_severity", "").upper() in FAIL_ON_BANDIT_SEVERITIES
    ]

    return {
        "tool": "Bandit",
        "total_issues": len(issues),
        "blocking_issues": len(high_issues),
        "status": "FAIL" if high_issues else "PASS",
        "examples": [
            {
                "severity": issue.get("issue_severity"),
                "test_id": issue.get("test_id"),
                "filename": issue.get("filename"),
                "line_number": issue.get("line_number"),
                "issue_text": issue.get("issue_text"),
            }
            for issue in high_issues[:5]
        ],
    }


def analyze_safety(report: Any) -> Dict[str, Any]:
    """
    Supports Safety JSON output shapes from both 'check' and 'scan' commands.
    """
    vulnerabilities: List[Any] = []

    if not report:
        return {
            "tool": "Safety",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    # Handle 'safety scan' format
    if isinstance(report, dict) and "vulnerabilities" in report:
        vulnerabilities = report["vulnerabilities"]
    # Handle older 'safety check' formats
    elif isinstance(report, list):
        vulnerabilities = report
    elif isinstance(report, dict) and "affected_packages" in report:
        for package_data in report["affected_packages"].values():
            vulns = package_data.get("vulnerabilities", [])
            vulnerabilities.extend(vulns)

    return {
        "tool": "Safety",
        "total_issues": len(vulnerabilities),
        "blocking_issues": len(vulnerabilities) if FAIL_ON_SAFETY else 0,
        "status": "FAIL" if vulnerabilities and FAIL_ON_SAFETY else "PASS",
        "examples": vulnerabilities[:5],
    }


def analyze_trivy(report: Dict[str, Any]) -> Dict[str, Any]:
    vulnerabilities = []

    if not report:
        return {
            "tool": "Trivy",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    for result in report.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = vulnerability.get("Severity", "").upper()
            if severity in FAIL_ON_TRIVY_SEVERITIES:
                vulnerabilities.append({
                    "target": result.get("Target"),
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": severity,
                    "title": vulnerability.get("Title"),
                })

    return {
        "tool": "Trivy",
        "total_issues": len(vulnerabilities),
        "blocking_issues": len(vulnerabilities),
        "status": "FAIL" if vulnerabilities else "PASS",
        "examples": vulnerabilities[:5],
    }


def print_result(result: Dict[str, Any]) -> None:
    print(f"\n[{result['tool']}]")
    print(f"Status: {result['status']}")
    print(f"Total Issues: {result['total_issues']}")
    print(f"Blocking Issues: {result['blocking_issues']}")

    if result["examples"]:
        print("Examples:")
        for example in result["examples"]:
            print(json.dumps(example, indent=2, ensure_ascii=False))


def main() -> int:
    print("=== PyShield Policy Engine ===")

    bandit_report = load_json(BANDIT_REPORT)
    safety_report = load_json(SAFETY_REPORT)
    trivy_report = load_json(TRIVY_REPORT)

    results = [
        analyze_bandit(bandit_report),
        analyze_safety(safety_report),
        analyze_trivy(trivy_report),
    ]

    for result in results:
        print_result(result)

    failed_tools = [result["tool"] for result in results if result["status"] == "FAIL"]
    missing_tools = [result["tool"] for result in results if result["status"] == "MISSING"]

    print("\n=== Final Decision ===")

    if failed_tools or missing_tools:
        print("DEPLOYMENT BLOCKED")
        if failed_tools:
            print(f"Reason: Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            print(f"Reason: Required scan reports missing for: {', '.join(missing_tools)}")
        return 1

    print("DEPLOYMENT ALLOWED")
    print("Reason: No blocking security issues found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
