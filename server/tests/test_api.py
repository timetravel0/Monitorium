import importlib
import os
import sqlite3
import sys
from pathlib import Path
import uuid

import pytest


@pytest.fixture
def app_module(monkeypatch):
    artifacts_dir = Path(__file__).resolve().parent / ".artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    db_path = artifacts_dir / f"test-{uuid.uuid4().hex}.db"

    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "strong-password")
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-flask-secret")
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    monkeypatch.setenv("AUTH_RATE_LIMIT_MAX_REQUESTS", "2")
    monkeypatch.setenv("RATE_LIMIT_MAX_REQUESTS", "10")

    server_dir = Path(__file__).resolve().parents[1]
    if str(server_dir) not in sys.path:
        sys.path.insert(0, str(server_dir))

    if "app" in sys.modules:
        del sys.modules["app"]

    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    yield module

    if db_path.exists():
        db_path.unlink()


def _valid_update_payload():
    return {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "hostname": "host-1",
        "local_ip_address": "192.168.1.20",
        "public_ip_address": "1.2.3.4",
        "platform": "Windows-11",
        "cpu_usage": 20.5,
        "memory_usage": 44.3,
        "hdd_usage": {"total": 512, "used": 200, "free": 312, "percent": 39.1},
        "running_processes": ["1-system"],
        "used_ports": ["127.0.0.1:5001 -> LISTENING"],
        "last_reboot": "2026-01-01 10:00:00",
        "uptime": "1 day",
        "current_users": ["admin"],
        "disk_io": {"read_bytes": 100, "write_bytes": 200},
        "network_io": {"bytes_sent": 1000, "bytes_recv": 2000},
        "last_updated": "2026-01-01 10:10:00",
    }


def test_issue_token_success(app_module):
    client = app_module.app.test_client()
    response = client.post(
        "/api/auth/token",
        json={"username": "admin", "password": "strong-password"},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["token"]


def test_update_requires_token(app_module):
    client = app_module.app.test_client()
    response = client.post("/update", json=_valid_update_payload())

    assert response.status_code == 403


def test_update_with_valid_token(app_module):
    client = app_module.app.test_client()

    token_response = client.post(
        "/api/auth/token",
        json={"username": "admin", "password": "strong-password"},
    )
    token = token_response.get_json()["token"]

    response = client.post(
        "/update",
        json=_valid_update_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"


def test_auth_rate_limit(app_module):
    client = app_module.app.test_client()

    response1 = client.post("/api/auth/token", json={"username": "admin", "password": "wrong"})
    response2 = client.post("/api/auth/token", json={"username": "admin", "password": "wrong"})
    response3 = client.post("/api/auth/token", json={"username": "admin", "password": "wrong"})

    assert response1.status_code == 401
    assert response2.status_code == 401
    assert response3.status_code == 429


def test_audit_log_written_for_failed_auth(app_module):
    client = app_module.app.test_client()
    client.post("/api/auth/token", json={"username": "admin", "password": "wrong"})

    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_log WHERE event_type = ? AND outcome = ?", ("api_token_issue", "failure"))
    count = cursor.fetchone()[0]
    conn.close()

    assert count >= 1
