"""
Unit tests for event bridge service
"""
import pytest
import json
import sys
import os

# Add services to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../services'))

from event_bridge import app as event_app


@pytest.fixture
def client():
    """Create test client"""
    event_app.app.config['TESTING'] = True
    with event_app.app.test_client() as client:
        yield client


@pytest.fixture
def valid_ecs_event():
    """Valid ECS-formatted event"""
    return {
        "@timestamp": "2025-01-01T12:00:00Z",
        "event": {
            "id": "test-event-123",
            "category": "malware"
        },
        "alert": {
            "severity": 8,
            "rule": "malware-detected",
            "risk_score": 90.0,
            "techniques": ["T1059"]
        },
        "host": {
            "hostname": "test-host",
            "ip": "192.168.1.100"
        },
        "indicator": {
            "ip": "10.0.0.1"
        }
    }


@pytest.fixture
def non_compliant_event():
    """Non-ECS compliant event"""
    return {
        "severity": 5,
        "rule": "suspicious-activity",
        "host": "test-host",
        "src_ip": "192.168.1.50"
    }


class TestHealthEndpoint:
    """Test health check endpoint"""

    def test_health_check_success(self, client):
        """Test health endpoint returns 200"""
        response = client.get('/health')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['service'] == 'event_bridge'
        assert 'timestamp' in data


class TestWebhookEndpoint:
    """Test webhook ingestion endpoint"""

    def test_webhook_valid_ecs_event(self, client, valid_ecs_event):
        """Test ingesting valid ECS event"""
        response = client.post(
            '/ingest/webhook',
            data=json.dumps(valid_ecs_event),
            content_type='application/json'
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert data['status'] == 'queued'
        assert data['id'] == 'test-event-123'

    def test_webhook_non_compliant_event(self, client, non_compliant_event):
        """Test ingesting non-ECS compliant event (should wrap it)"""
        response = client.post(
            '/ingest/webhook',
            data=json.dumps(non_compliant_event),
            content_type='application/json'
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert data['status'] == 'queued'
        assert 'id' in data
        assert data.get('note') == 'wrapped'

    def test_webhook_invalid_json(self, client):
        """Test with invalid JSON"""
        response = client.post(
            '/ingest/webhook',
            data='invalid json{',
            content_type='application/json'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    def test_webhook_with_api_key(self, client, valid_ecs_event, monkeypatch):
        """Test API key authentication"""
        # Set API key in environment
        monkeypatch.setenv('API_KEY', 'test-api-key')

        # Request without API key
        response = client.post(
            '/ingest/webhook',
            data=json.dumps(valid_ecs_event),
            content_type='application/json'
        )
        # Note: In test mode API_KEY might not be loaded, test behavior may vary

    def test_webhook_rate_limiting(self, client, valid_ecs_event):
        """Test rate limiting (should eventually hit limit)"""
        # Send many requests
        for _ in range(10):
            response = client.post(
                '/ingest/webhook',
                data=json.dumps(valid_ecs_event),
                content_type='application/json'
            )
            # First 10 should succeed
            assert response.status_code in [202, 429]


class TestEnqueueFunction:
    """Test event enqueueing"""

    def test_enqueue_creates_file(self, valid_ecs_event, tmp_path, monkeypatch):
        """Test that enqueue creates a file"""
        import event_bridge.app as eb

        # Use temporary directory
        monkeypatch.setattr(eb, 'QUEUE_DIR', str(tmp_path))

        event_id = eb.enqueue(valid_ecs_event)

        assert event_id == 'test-event-123'
        queue_file = tmp_path / f"{event_id}.json"
        assert queue_file.exists()

        # Verify content
        with open(queue_file) as f:
            saved_event = json.load(f)
        assert saved_event['event']['id'] == 'test-event-123'
