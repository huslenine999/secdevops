import io
import json
import pytest
from pathlib import Path
from app.main import app, SCANS_DIR

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_run_scan_default(client):
    """Ensure the default run-scan (no file uploaded) scans the codebase and runs successfully."""
    response = client.post('/run-scan')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # Check that reports were generated
    assert (SCANS_DIR / "semgrep-report.json").exists()
    assert (SCANS_DIR / "safety-report.json").exists()
    assert (SCANS_DIR / "trivy-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

def test_run_scan_custom_clean(client):
    """Ensure a custom clean Python file upload runs successfully and passes the policy gate."""
    # Create a mock clean python file in memory
    clean_code = "print('Hello, secure world!')\n"
    data = {
        'file': (io.BytesIO(clean_code.encode('utf-8')), 'clean_test.py')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # The uploads folder should be completely clean (no UUID subdirectories remaining)
    uploads_dir = SCANS_DIR / "uploads"
    if uploads_dir.exists():
        subdirs = list(uploads_dir.iterdir())
        assert len(subdirs) == 0

    # Ensure reports are generated
    assert (SCANS_DIR / "semgrep-report.json").exists()
    semgrep_report = json.loads((SCANS_DIR / "semgrep-report.json").read_text())
    # Should find no issues
    assert len(semgrep_report.get("results", [])) == 0

def test_run_scan_custom_vulnerable(client):
    """Ensure a custom vulnerable Python file upload runs successfully but fails the policy gate due to Semgrep flagging it."""
    # Create a mock vulnerable python file using eval()
    vuln_code = "eval(input())\n"
    data = {
        'file': (io.BytesIO(vuln_code.encode('utf-8')), 'vuln_test.py')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # Ensure it contains the vulnerability
    assert (SCANS_DIR / "semgrep-report.json").exists()
    semgrep_report = json.loads((SCANS_DIR / "semgrep-report.json").read_text())
    assert len(semgrep_report.get("results", [])) > 0
    assert any("eval" in issue.get("extra", {}).get("message", "").lower() or "eval" in issue.get("check_id", "").lower() for issue in semgrep_report.get("results", []))

    # The HTML report should reflect BLOCKED because of the medium/high vulnerability in Semgrep
    assert (SCANS_DIR / "report.html").exists()
    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html

def test_run_scan_custom_clean_js(client):
    """Ensure a custom clean JavaScript file upload runs successfully and passes the policy gate."""
    clean_code = "console.log('Hello, secure JS world!');\n"
    data = {
        'file': (io.BytesIO(clean_code.encode('utf-8')), 'clean_test.js')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # The uploads folder should be completely clean (no UUID subdirectories remaining)
    uploads_dir = SCANS_DIR / "uploads"
    if uploads_dir.exists():
        subdirs = list(uploads_dir.iterdir())
        assert len(subdirs) == 0

    assert (SCANS_DIR / "semgrep-report.json").exists()
    semgrep_report = json.loads((SCANS_DIR / "semgrep-report.json").read_text())
    assert len(semgrep_report.get("results", [])) == 0

def test_run_scan_custom_vulnerable_js(client):
    """Ensure a custom vulnerable JavaScript file upload runs successfully but fails the policy gate."""
    vuln_code = "eval(req.query.code);\n"
    data = {
        'file': (io.BytesIO(vuln_code.encode('utf-8')), 'vuln_test.js')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    assert (SCANS_DIR / "semgrep-report.json").exists()
    semgrep_report = json.loads((SCANS_DIR / "semgrep-report.json").read_text())
    assert len(semgrep_report.get("results", [])) > 0
    
    assert (SCANS_DIR / "report.html").exists()
    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html
