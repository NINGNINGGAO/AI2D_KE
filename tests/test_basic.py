"""
Tests for KE Analyzer
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client."""
    from orchestrator.main import app
    return TestClient(app)


class TestHealth:
    """Test health check endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"


class TestWebhook:
    """Test Jira webhook handling."""
    
    def test_webhook_without_auth(self, client):
        """Test webhook without proper authentication."""
        response = client.post("/webhook/jira", json={})
        # Should fail validation
        assert response.status_code in [400, 401]
    
    def test_webhook_invalid_payload(self, client):
        """Test webhook with invalid payload."""
        response = client.post("/webhook/jira", json={"invalid": "data"})
        assert response.status_code == 400


class TestAnalysis:
    """Test analysis endpoints."""
    
    def test_get_analysis_not_found(self, client):
        """Test getting non-existent analysis."""
        response = client.get("/api/v1/analysis/NONEXISTENT-123")
        assert response.status_code == 404
    
    def test_list_analyses(self, client):
        """Test listing analyses."""
        response = client.get("/api/v1/analyses")
        assert response.status_code == 200
        data = response.json()
        assert "analyses" in data


class TestConfig:
    """Test configuration."""
    
    def test_settings_loading(self):
        """Test settings load correctly."""
        from orchestrator.config import get_settings
        settings = get_settings()
        assert settings.APP_NAME == "KE Analyzer"
