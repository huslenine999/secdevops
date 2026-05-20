import pytest
from app.main import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_waf_disabled_by_default(client):
    """Ensure the WAF is disabled by default and allow SQLi."""
    response = client.get('/user?name=admin\' OR \'1\'=\'1')
    assert response.status_code == 200

def test_waf_blocking(client):
    """Enable WAF and ensure it blocks malicious patterns."""
    # Enable WAF
    client.post('/toggle-waf')
    
    # Test SQLi blocking
    response = client.get('/user?name=admin\' OR \'1\'=\'1')
    assert response.status_code == 403
    assert b"Blocked by PyShield WAF" in response.data

    # Test Command Injection blocking
    response = client.get('/ping?host=127.0.0.1; cat /etc/passwd')
    assert response.status_code == 403

    # Test Path Traversal blocking
    response = client.get('/download?file=../../etc/passwd')
    assert response.status_code == 403

    # Test legitimate traffic still works
    response = client.get('/health')
    assert response.status_code == 200

    # Disable WAF for other tests
    client.post('/toggle-waf')

def test_waf_toggle(client):
    """Test the WAF toggle endpoint."""
    # Toggle on
    response = client.post('/toggle-waf')
    assert response.json['waf_enabled'] is True
    
    # Toggle off
    response = client.post('/toggle-waf')
    assert response.json['waf_enabled'] is False
