"""Testes — IntentionManager (offline)"""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from service_mesh.consul import ConsulMeshClient
from service_mesh.intentions import IntentionManager


def test_apply_default_deny_allow_payload():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    captured = {}

    def fake_request(method, path, body=None, params=None):
        captured["method"] = method
        captured["path"] = path
        captured["body"] = body
        return None

    mgr = IntentionManager(client)
    with patch.object(client, "_request", side_effect=fake_request):
        mgr.apply_default_deny_allow(
            destination="ventura-seg",
            allow_from=["ai-agent", "admin-api"],
        )

    assert captured["method"] == "PUT"
    assert captured["path"] == "/v1/config"
    body = captured["body"]
    assert body["Kind"] == "service-intentions"
    assert body["Name"] == "ventura-seg"
    actions = [(s["Name"], s["Action"]) for s in body["Sources"]]
    assert ("ai-agent", "allow") in actions
    assert ("admin-api", "allow") in actions
    assert ("*", "deny") in actions


def test_apply_json_file():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    captured = {}

    def fake_request(method, path, body=None, params=None):
        captured["body"] = body
        return None

    mgr = IntentionManager(client)
    path = ROOT / "consul" / "intentions" / "ventura-seg.json"
    with patch.object(client, "_request", side_effect=fake_request):
        mgr.apply_json_file(path)

    assert captured["body"]["Name"] == "ventura-seg"
    assert any(s["Action"] == "deny" and s["Name"] == "*" for s in captured["body"]["Sources"])
