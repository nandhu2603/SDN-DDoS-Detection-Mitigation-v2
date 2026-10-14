"""
Unit tests for Flask Dashboard REST API.
"""

import json
import pytest
from dashboard.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"SDN-Based DDoS Detection & Mitigation" in res.data


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "status" in data
    assert "latest_features" in data
    assert "blocked_hosts" in data


def test_api_simulate_and_unblock(client):
    # 1. Reset state
    res = client.post("/api/simulate", json={"scenario": "reset"})
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 2. Simulate SYN flood
    res = client.post("/api/simulate", json={"scenario": "syn_flood"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["blocked_ip"] == "10.0.0.1"

    # 3. Check status shows ATTACK and blocked IP
    res_status = client.get("/api/status")
    status_data = res_status.get_json()
    assert status_data["status"] == "ATTACK"
    assert status_data["blocked_count"] >= 1
    assert any(h["ip"] == "10.0.0.1" for h in status_data["blocked_hosts"])

    # 4. Unblock host
    res_unblock = client.post("/api/unblock", json={"ip": "10.0.0.1"})
    assert res_unblock.status_code == 200
    assert res_unblock.get_json()["success"] is True

    # 5. Check blocked count dropped
    res_status2 = client.get("/api/status")
    assert not any(h["ip"] == "10.0.0.1" for h in res_status2.get_json()["blocked_hosts"])
