# PyShield: Automated DevSecOps Pipeline for Python Applications

PyShield is a DevSecOps demo project that automatically scans Python source code, dependencies, and Docker images before deployment.

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

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/seed_db.py
python app/main.py
```

Open:

```txt
http://127.0.0.1:5000
```

## Run Security Scans Locally

```bash
mkdir -p scans

bandit -r app -f json -o scans/bandit-report.json || true
safety check -r requirements.txt --json > scans/safety-report.json || true

docker build -t pyshield-demo .
trivy image --format json --output scans/trivy-report.json pyshield-demo || true

python policy_engine.py
```

## Expected Behavior

The policy engine should fail because this repository intentionally contains dangerous vulnerabilities.

This is for educational DevSecOps demonstration only.
