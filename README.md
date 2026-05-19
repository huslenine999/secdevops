# PyShield: Automated DevSecOps Pipeline for Python Applications

PyShield is a DevSecOps demo project that automatically scans Python source code, dependencies, and Docker images before deployment.

## Security Reports

PyShield now generates visual reports after every scan:

- **Console Output**: Concise summary in the terminal/logs.
- **HTML Report**: `scans/report.html` - A beautiful, standalone dashboard for detailed review.
- **Markdown Report**: `scans/report.md` - Optimized for GitHub Job Summaries and documentation.

## Core Flow

Developer pushes code → GitHub Actions runs scans → Python policy engine checks results → deployment allowed or blocked

## Tools Used

| Tool | Purpose |
|---|---|
| Bandit | Finds insecure Python code |
| Safety | Checks vulnerable Python dependencies |
| Trivy | Scans Docker images and containers |
| Python Policy Engine | Reads scan results and decides Pass/Fail |
| GitHub Actions | Automates the pipeline |

## Project Structure

```txt
pyshield/
├── app/
│   ├── main.py
│   ├── database.py
│   └── templates/
│       └── index.html
├── scripts/
│   └── seed_db.py
├── scans/
│   └── .gitkeep
├── policy_engine.py
├── requirements.txt
├── Dockerfile
├── .github/
│   └── workflows/
│       └── security-pipeline.yml
└── README.md
```

## Vulnerabilities Intentionally Included

This project intentionally includes vulnerabilities for security scanning and demonstration:

- Hardcoded secret
- SQL Injection
- Command Injection
- Unsafe `eval()`
- Insecure deserialization with `pickle`
- Path Traversal
- Weak hashing with MD5
- Debug mode enabled
- Vulnerable/outdated Python dependencies
- Potentially vulnerable Docker base image

## Local Run

1. **Setup Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Initialize & Start**:
   ```bash
   python scripts/seed_db.py
   python app/main.py
   ```

3. **Access the Dashboard**:
   Open [http://127.0.0.1:5001](http://127.0.0.1:5001) in your browser.

## 🚀 Implementation Guide for Teams

You can adopt the PyShield pattern in your own projects by following these steps:

### 1. Integrate Security Scanners
Add security tools to your `requirements-dev.txt` and run them as part of your build process:
- **Bandit**: `bandit -r src/ -f json -o bandit-report.json`
- **Safety**: `safety check -r requirements.txt --save-json safety-report.json`

### 2. Implement the Policy Engine
Don't just look at tool outputs. Use a script like `policy_engine.py` to:
- **Set Thresholds**: Decide which severity levels (e.g., HIGH/CRITICAL) should block a deployment.
- **Fail Fast**: Return a non-zero exit code (`exit 1`) when a policy is violated to stop the CI/CD pipeline.
- **Consolidate Reports**: Turn fragmented JSON data into a single, readable HTML dashboard for the team.

### 3. Automate with CI/CD
Copy the logic from `.github/workflows/security-pipeline.yml` to ensure every Pull Request is automatically scanned before it can be merged.

---

## Expected Behavior
The policy engine is **configured to fail** by default in this repository because it intentionally contains dangerous vulnerabilities. This is to demonstrate how a "blocked" deployment looks and feels.

---
*This project is for educational DevSecOps demonstration only.*
