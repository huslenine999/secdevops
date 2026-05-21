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
    assert b"Blocked by Aegis WAF" in response.data

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

def test_waf_custom_rules(client):
    """Test custom WAF rules retrieval, saving, and blocking."""
    # 1. Fetch initial rules
    response = client.get('/get-waf-rules')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    assert 'rules' in response.json
    assert 'waf_enabled' in response.json
    original_rules = response.json['rules']

    try:
        # 2. Save a custom rule pattern
        custom_rules = [
            {"pattern": "custom_hack_pattern", "description": "Custom hacker signature", "enabled": True}
        ]
        save_response = client.post('/save-waf-rules', json={"rules": custom_rules})
        assert save_response.status_code == 200
        assert save_response.json['status'] == 'success'

        # 3. Enable WAF
        toggle_response = client.post('/toggle-waf')
        assert toggle_response.json['waf_enabled'] is True

        # 4. Test blocking of custom pattern
        blocked_response = client.get('/user?name=custom_hack_pattern')
        assert blocked_response.status_code == 403
        assert b"Custom hacker signature" in blocked_response.data

        # 5. Disable custom pattern and test bypass
        disabled_rules = [
            {"pattern": "custom_hack_pattern", "description": "Custom hacker signature", "enabled": False}
        ]
        client.post('/save-waf-rules', json={"rules": disabled_rules})
        allowed_response = client.get('/user?name=custom_hack_pattern')
        assert allowed_response.status_code == 200

        # Disable WAF
        client.post('/toggle-waf')

    finally:
        # Restore original rules
        client.post('/save-waf-rules', json={"rules": original_rules})
