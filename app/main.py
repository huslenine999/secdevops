import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from database import DB_PATH, initialize_database

app = Flask(__name__)

# Intentionally hardcoded secrets for Bandit detection.
app.config["SECRET_KEY"] = "super-secret-hardcoded-key"
DATABASE_PASSWORD = "root-password-123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

BASE_DIR = Path(__file__).resolve().parent
DOWNLOAD_DIR = BASE_DIR / "downloads"
DOWNLOAD_DIR.mkdir(exist_ok=True)

sample_file = DOWNLOAD_DIR / "sample.txt"
sample_file.write_text("This is a safe sample file.\n")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "service": "pyshield-vulnerable-demo"
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

    # Intentionally enabling debug mode.
    app.run(host="0.0.0.0", port=5000, debug=True)
