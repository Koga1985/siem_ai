"""
Pytest configuration — sets up sys.path and required env vars before any
test module is imported, so module-level initialisation in the services
(queue directory creation, schema loading, etc.) works outside Docker.
"""

import os
import sys
import tempfile

import pytest

# Make all service packages importable from the repo root
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO, "services"))
sys.path.insert(0, os.path.join(_REPO, "services", "event_bridge"))
sys.path.insert(0, os.path.join(_REPO, "services", "ai_generator"))

# Point schema env var at the real schema file before app.py is imported
os.environ.setdefault("ECS_SCHEMA_PATH", os.path.join(_REPO, "schemas", "ecs_min.json"))

# Use a temp queue dir so tests don't need /repo/...
_TMP_QUEUE = tempfile.mkdtemp(prefix="siem_test_queue_")
os.environ.setdefault("QUEUE_DIR", _TMP_QUEUE)


@pytest.fixture(autouse=True)
def _clean_queue(tmp_path, monkeypatch):
    """Give each test its own isolated queue directory."""
    import event_bridge.app as eb

    monkeypatch.setattr(eb, "QUEUE_DIR", str(tmp_path))
    yield
