import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add the current directory to sys.path to allow imports when running from root
sys.path.append(str(Path(__file__).resolve().parent))

from flask import Flask, jsonify, render_template, request

from database import DB_PATH, initialize_database

app = Flask(__name__)

# Global state for the WAF toggle (demo only)
WAF_ENABLED = False

@app.before_request
def waf_middleware():
    """
    Simulated Web Application Firewall (WAF).
    Blocks suspicious patterns if enabled.
    """
    global WAF_ENABLED
    if not WAF_ENABLED:
        return

    # Simple pattern matching for common attacks
    suspicious_patterns = [
        "' OR '", "1=1", "--", "cat /etc/passwd", "../", "pickle.loads", "eval("
    ]
    
    # Check query params and body
    payload = str(request.args) + str(request.form) + str(request.data)
    for pattern in suspicious_patterns:
        if pattern in payload:
            return jsonify({
                "error": "Blocked by Aegis WAF",
                "reason": f"Detected malicious pattern: {pattern}",
                "status": "security_violation"
            }), 403


@app.route("/toggle-waf", methods=["POST"])
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    return jsonify({"status": "success", "waf_enabled": WAF_ENABLED})


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
    """
    try:
        # Determine the python executable and tool paths.
        # Use current sys.executable to ensure we stay in the same venv.
        python_bin = sys.executable
        
        # Run Bandit (SAST)
        bandit_cmd = [python_bin, "-m", "bandit", "-r", "app", "-f", "json", "-o", str(SCANS_DIR / "bandit-report.json")]
        subprocess.run(bandit_cmd, cwd=PROJECT_ROOT, check=False)
        
        # Run Safety (SCA) - using 'check' which works with requirements.txt
        safety_cmd = [python_bin, "-m", "safety", "check", "-r", "requirements.txt", "--save-json", str(SCANS_DIR / "safety-report.json")]
        subprocess.run(safety_cmd, cwd=PROJECT_ROOT, check=False)
        
        # Run the policy engine
        engine_path = PROJECT_ROOT / "policy_engine.py"
        # Pass SCANS_DIR to policy engine via environment variable if needed, 
        # but policy_engine.py also needs to be updated.
        subprocess.run([python_bin, str(engine_path)], cwd=PROJECT_ROOT, check=False, env={**os.environ, "SCANS_DIR": str(SCANS_DIR)})
        
        return jsonify({"status": "success", "message": "Scan completed and report generated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


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


if __name__ == "__main__":
    initialize_database()

    # Debug mode disabled for hardening.
    app.run(host="0.0.0.0", port=5001, debug=False)
