import base64
import hashlib
import os
import pickle
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add the current directory to sys.path to allow imports when running from root
sys.path.append(str(Path(__file__).resolve().parent))

from flask import Flask, Response, jsonify, render_template, request

from database import DB_PATH, initialize_database

app = Flask(__name__)

# Global state for the WAF toggle (demo only)
WAF_ENABLED = False

# Default dynamic WAF Rules (mutable in memory)
WAF_RULES = [
    {"pattern": "' OR '", "description": "SQL Injection (OR operator bypass)", "enabled": True},
    {"pattern": "1=1", "description": "SQL Injection (tautology bypass)", "enabled": True},
    {"pattern": "--", "description": "SQL comment character block", "enabled": True},
    {"pattern": "cat /etc/passwd", "description": "LFI/Command execution pattern 1", "enabled": True},
    {"pattern": "\\.\\./", "description": "Directory Traversal pattern (../)", "enabled": True},
    {"pattern": "pickle\\.loads", "description": "Python deserialization hijack detector", "enabled": True},
    {"pattern": "eval\\(", "description": "Python dynamic expression injection detector", "enabled": True}
]

@app.before_request
def waf_middleware():
    """
    Simulated Web Application Firewall (WAF).
    Blocks suspicious patterns if enabled.
    """
    global WAF_ENABLED, WAF_RULES
    # Bypass WAF checks for WAF management, scanning, and dossier export routes
    if request.path in ["/toggle-waf", "/get-waf-rules", "/save-waf-rules", "/run-scan", "/export-dossier"]:
        return

    if not WAF_ENABLED:
        return

    # Check query params, form body, and raw data
    payload = str(request.args) + str(request.form) + str(request.data)
    
    for rule in WAF_RULES:
        if not rule.get("enabled", True):
            continue
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        try:
            # Check with compiled regex pattern
            if re.search(pattern, payload, re.IGNORECASE):
                return jsonify({
                    "error": "Blocked by Aegis WAF",
                    "reason": f"Detected malicious pattern: {rule.get('description', pattern)}",
                    "status": "security_violation"
                }), 403
        except re.error:
            # Fallback to simple literal check
            if pattern in payload:
                return jsonify({
                    "error": "Blocked by Aegis WAF",
                    "reason": f"Detected malicious pattern (literal): {rule.get('description', pattern)}",
                    "status": "security_violation"
                }), 403


@app.route("/toggle-waf", methods=["POST"])
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    return jsonify({"status": "success", "waf_enabled": WAF_ENABLED})


@app.route("/get-waf-rules", methods=["GET"])
def get_waf_rules():
    global WAF_RULES, WAF_ENABLED
    return jsonify({"status": "success", "rules": WAF_RULES, "waf_enabled": WAF_ENABLED})


@app.route("/save-waf-rules", methods=["POST"])
def save_waf_rules():
    global WAF_RULES
    try:
        data = request.json
        rules = data.get("rules", [])
        new_rules = []
        for r in rules:
            if "pattern" in r:
                new_rules.append({
                    "pattern": str(r["pattern"]),
                    "description": str(r.get("description", "")),
                    "enabled": bool(r.get("enabled", True))
                })
        WAF_RULES = new_rules
        return jsonify({"status": "success", "message": "WAF rules updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# Use environment variables for secrets.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "default-dev-secret-key")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "dev-password")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "DEV-AWS-ID")

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

if os.environ.get("VERCEL"):
    DOWNLOAD_DIR = Path("/tmp/downloads")
    SCANS_DIR = Path("/tmp/scans")
else:
    DOWNLOAD_DIR = BASE_DIR / "downloads"
    SCANS_DIR = PROJECT_ROOT / "scans"

# Initialize directories and sample file safely
DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
SCANS_DIR.mkdir(exist_ok=True, parents=True)

sample_file = DOWNLOAD_DIR / "sample.txt"
if not sample_file.exists():
    sample_file.write_text("This is a safe sample file.\n")

# Initialize database if it doesn't exist (critical for Vercel /tmp)
if not DB_PATH.exists():
    initialize_database()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report")
def get_report():
    """
    Serves the latest security report.
    """
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return "<h1>Report not found</h1><p>Please run the security scans first.</p>", 404
    return report_path.read_text()


@app.route("/run-scan", methods=["POST"])
def run_scan():
    """
    Triggers fresh security scans and then runs the policy engine.
    Supports either scanning the local application codebase or a custom uploaded file.
    """
    import uuid
    import shutil
    import json
    from werkzeug.utils import secure_filename

    uploaded_file = request.files.get("file")
    is_custom_scan = False
    temp_dir = None

    try:
        # Determine the python executable and tool paths.
        # Use current sys.executable to ensure we stay in the same venv.
        python_bin = sys.executable
        semgrep_bin = Path(python_bin).parent / "semgrep"
        if not semgrep_bin.exists():
            semgrep_bin = Path("semgrep")
        
        if uploaded_file and uploaded_file.filename:
            is_custom_scan = True
            filename = secure_filename(uploaded_file.filename)
            uuid_str = uuid.uuid4().hex
            temp_dir = SCANS_DIR / "uploads" / uuid_str
            temp_dir.mkdir(exist_ok=True, parents=True)
            temp_filepath = temp_dir / filename
            uploaded_file.save(str(temp_filepath))
            
            # Run Semgrep (SAST) on the custom file specifically
            semgrep_cmd = [str(semgrep_bin), "scan", "--config=auto", "--json", "-o", str(SCANS_DIR / "semgrep-report.json"), str(temp_filepath)]
            subprocess.run(semgrep_cmd, cwd=PROJECT_ROOT, check=False)
            
            # Write clean/empty mock results to safety-report.json and trivy-report.json
            with open(SCANS_DIR / "safety-report.json", "w") as f:
                json.dump([], f)
            with open(SCANS_DIR / "trivy-report.json", "w") as f:
                json.dump({"Results": []}, f)
        else:
            # Run Semgrep (SAST) on default app directory
            semgrep_cmd = [str(semgrep_bin), "scan", "--config=auto", "--json", "-o", str(SCANS_DIR / "semgrep-report.json"), "app"]
            subprocess.run(semgrep_cmd, cwd=PROJECT_ROOT, check=False)
            
            # Run Safety (SCA) - using 'check' which works with requirements.txt
            safety_cmd = [python_bin, "-m", "safety", "check", "-r", "requirements.txt", "--save-json", str(SCANS_DIR / "safety-report.json")]
            subprocess.run(safety_cmd, cwd=PROJECT_ROOT, check=False)
            
            # Ensure trivy-report.json exists
            trivy_path = SCANS_DIR / "trivy-report.json"
            if not trivy_path.exists():
                with open(trivy_path, "w") as f:
                    json.dump({"Results": []}, f)
        
        # Run the policy engine
        engine_path = PROJECT_ROOT / "policy_engine.py"
        subprocess.run([python_bin, str(engine_path)], cwd=PROJECT_ROOT, check=False, env={**os.environ, "SCANS_DIR": str(SCANS_DIR)})
        
        return jsonify({"status": "success", "message": "Scan completed and report generated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if is_custom_scan and temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                app.logger.error(f"Failed to clean up temp directory {temp_dir}: {e}")


@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "service": "aegis-vulnerable-demo"
    })


@app.route("/user")
def get_user():
    """
    SQL Injection vulnerability.

    Example:
    /user?name=admin

    Dangerous example:
    /user?name=admin' OR '1'='1
    """
    username = request.args.get("name", "guest")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Intentionally vulnerable string formatting.
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{username}'"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        "query": query,
        "results": rows
    })


@app.route("/ping")
def ping_host():
    """
    Command Injection vulnerability.

    Example:
    /ping?host=127.0.0.1
    """
    host = request.args.get("host", "127.0.0.1")

    # Intentionally vulnerable shell=True usage.
    command = f"ping -c 1 {host}"
    output = subprocess.check_output(command, shell=True, text=True)

    return jsonify({
        "command": command,
        "output": output
    })


@app.route("/calculate")
def calculate():
    """
    Unsafe eval vulnerability.

    Example:
    /calculate?expr=2+2
    """
    expression = request.args.get("expr", "1+1")

    # Intentionally dangerous eval usage.
    result = eval(expression)

    return jsonify({
        "expression": expression,
        "result": result
    })


@app.route("/load-profile", methods=["POST"])
def load_profile():
    """
    Insecure deserialization vulnerability.

    The endpoint accepts base64 encoded pickle data.
    This is intentionally unsafe and should never be used in production.
    """
    encoded_profile = request.json.get("profile", "")

    raw_data = base64.b64decode(encoded_profile)

    # Intentionally dangerous pickle deserialization.
    profile = pickle.loads(raw_data)

    return jsonify({
        "loaded_profile": str(profile)
    })


@app.route("/download")
def download_file():
    """
    Path Traversal vulnerability.

    Example:
    /download?file=sample.txt

    Dangerous example:
    /download?file=../main.py
    """
    filename = request.args.get("file", "sample.txt")

    # Intentionally unsafe path join.
    target_file = DOWNLOAD_DIR / filename

    if not target_file.exists():
        return jsonify({"error": "File not found"}), 404

    return target_file.read_text()


@app.route("/hash")
def weak_hash():
    """
    Weak hashing vulnerability using MD5.

    Example:
    /hash?value=password123
    """
    value = request.args.get("value", "password123")

    # Intentionally weak hash.
    digest = hashlib.md5(value.encode()).hexdigest()

    return jsonify({
        "value": value,
        "md5": digest
    })


@app.route("/debug-info")
def debug_info():
    """
    Information exposure demo.
    """
    return jsonify({
        "database_password": DATABASE_PASSWORD,
        "aws_access_key": AWS_ACCESS_KEY_ID,
        "environment": dict(os.environ)
    })


@app.route("/export-dossier")
def export_dossier():
    """
    Generates and downloads a retro monospaced dot-matrix ASCII compliance report
    summarizing results from bandit, safety, and trivy.
    """
    import json
    from datetime import datetime
    
    def load_json(path):
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            return None

    semgrep_report = load_json(SCANS_DIR / "semgrep-report.json")
    safety_report = load_json(SCANS_DIR / "safety-report.json")
    trivy_report = load_json(SCANS_DIR / "trivy-report.json")

    # Determine status & counts for Semgrep
    if not (SCANS_DIR / "semgrep-report.json").exists():
        semgrep_status = "MISSING"
        semgrep_total = 0
        semgrep_blocking = 0
    else:
        semgrep_results = semgrep_report.get("results", []) if semgrep_report else []
        semgrep_total = len(semgrep_results)
        semgrep_blocking = 0
        for r in semgrep_results:
            raw_sev = r.get("extra", {}).get("severity", "").upper()
            if raw_sev in {"ERROR", "WARNING"}:
                semgrep_blocking += 1
        semgrep_status = "FAIL" if semgrep_blocking > 0 else "PASS"

    # Determine status & counts for Safety
    if not (SCANS_DIR / "safety-report.json").exists():
        safety_status = "MISSING"
        safety_total = 0
        safety_blocking = 0
    else:
        safety_vulns = []
        if isinstance(safety_report, dict):
            safety_vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            safety_vulns = safety_report
        safety_total = len(safety_vulns)
        safety_blocking = safety_total
        safety_status = "FAIL" if safety_blocking > 0 else "PASS"

    # Determine status & counts for Trivy
    if not (SCANS_DIR / "trivy-report.json").exists():
        trivy_status = "MISSING"
        trivy_total = 0
        trivy_blocking = 0
    else:
        trivy_vulns = []
        for result in (trivy_report.get("Results", []) or []):
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append(vulnerability)
        trivy_total = len(trivy_vulns)
        trivy_blocking = len([v for v in trivy_vulns if v.get("Severity", "").upper() in {"MEDIUM", "HIGH", "CRITICAL"}])
        trivy_status = "FAIL" if trivy_blocking > 0 else "PASS"

    # Final overall decision
    failed_tools = []
    missing_tools = []
    for tool, status in [("Semgrep", semgrep_status), ("Safety", safety_status), ("Trivy", trivy_status)]:
        if status == "FAIL":
            failed_tools.append(tool)
        elif status == "MISSING":
            missing_tools.append(tool)

    if failed_tools or missing_tools:
        gate_decision = "BLOCKED"
        reasons = []
        if failed_tools:
            reasons.append(f"Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            reasons.append(f"Required scan reports missing for: {', '.join(missing_tools)}")
        reason = " | ".join(reasons)
    else:
        gate_decision = "ALLOWED"
        reason = "No blocking security issues found."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format Semgrep findings
    semgrep_findings = ""
    if semgrep_report and semgrep_report.get("results"):
        for issue in semgrep_report.get("results", [])[:5]:
            extra = issue.get("extra", {})
            semgrep_findings += f"  - ID: {issue.get('check_id')} | Severity: {extra.get('severity')} | Confidence: {extra.get('metadata', {}).get('confidence', 'MEDIUM')}\n"
            semgrep_findings += f"    Location: {issue.get('path')}:{issue.get('start', {}).get('line')}\n"
            semgrep_findings += f"    Details: {extra.get('message')}\n"
            code = extra.get('lines', '')
            if code:
                code_lines = code.strip().split('\n')
                semgrep_findings += f"    Source:\n"
                for cl in code_lines[:3]:
                    semgrep_findings += f"      >> {cl}\n"
            semgrep_findings += "  ------------------------------------------------------------------\n"
    else:
        semgrep_findings = "  No issues detected.\n"

    # Format Safety findings
    safety_findings = ""
    if safety_report:
        vulns = []
        if isinstance(safety_report, dict):
            vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            vulns = safety_report
        
        if vulns:
            for v in vulns[:5]:
                pkg = v.get("package_name") or v.get("package")
                vuln_id = v.get("vulnerability_id") or v.get("advisory")
                affected = v.get("affected_versions") or v.get("version")
                fixed = v.get("fixed_versions") or v.get("fixed")
                desc = v.get("description") or v.get("reason", "No description provided.")
                safety_findings += f"  - Package: {pkg} | ID: {vuln_id}\n"
                safety_findings += f"    Affected: {affected} | Fixed: {fixed}\n"
                safety_findings += f"    Description: {desc[:120]}...\n"
                safety_findings += "  ------------------------------------------------------------------\n"
        else:
            safety_findings = "  No issues detected.\n"
    else:
        safety_findings = "  No report file found.\n"

    # Format Trivy findings
    trivy_findings = ""
    if trivy_report:
        trivy_vulns = []
        for result in trivy_report.get("Results", []) or []:
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append({
                    "target": result.get("Target"),
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": vulnerability.get("Severity", "").upper(),
                    "title": vulnerability.get("Title"),
                })
        if trivy_vulns:
            for v in trivy_vulns[:5]:
                trivy_findings += f"  - Target: {v.get('target')} | Package: {v.get('package_name')} | ID: {v.get('vulnerability_id')}\n"
                trivy_findings += f"    Severity: {v.get('severity')} | Installed: {v.get('installed_version')} | Fixed: {v.get('fixed_version')}\n"
                trivy_findings += f"    Title: {v.get('title')}\n"
                trivy_findings += "  ------------------------------------------------------------------\n"
        else:
            trivy_findings = "  No issues detected.\n"
    else:
        trivy_findings = "  No report file found.\n"

    dossier_text = f"""================================================================================
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      AEGIS DEVSECOPS COMPLIANCE DOSSIER
================================================================================
TIMESTAMP: {timestamp}
GATE DECISION: {gate_decision}
REASON: {reason}
================================================================================

[1] STATIC APPLICATION SECURITY TESTING (SAST) - SEMGREP
--------------------------------------------------------------------------------
Status: {semgrep_status}
Total Issues Detected: {semgrep_total}
Blocking Issues: {semgrep_blocking}

FINDINGS (Top 5):
{semgrep_findings}

[2] SOFTWARE COMPOSITION ANALYSIS (SCA) - SAFETY
--------------------------------------------------------------------------------
Status: {safety_status}
Total Issues Detected: {safety_total}
Blocking Issues: {safety_blocking}

FINDINGS (Top 5):
{safety_findings}

[3] CONTAINER IMAGE SCANNING - TRIVY
--------------------------------------------------------------------------------
Status: {trivy_status}
Total Issues Detected: {trivy_total}
Blocking Issues: {trivy_blocking}

FINDINGS (Top 5):
{trivy_findings}

================================================================================
                    [ END OF SECURE TRANSMISSION ]
================================================================================
"""

    return Response(
        dossier_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment;filename=aegis-compliance-dossier.txt"
        }
    )


if __name__ == "__main__":
    initialize_database()

    # Debug mode disabled for hardening.
    app.run(host="0.0.0.0", port=5001, debug=False)
