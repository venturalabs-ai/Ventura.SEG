"""Testes unitários offline — Consul Service Mesh client"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from service_mesh.consul import ConsulMeshClient, ServiceInstance


def test_service_instance_dataclass():
    inst = ServiceInstance(
        id="svc-1",
        name="api",
        address="10.0.0.1",
        port=8080,
        tags=["v1"],
        healthy=True,
    )
    assert inst.port == 8080
    assert inst.healthy


def test_register_builds_payload():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    captured = {}

    def fake_request(method, path, body=None, params=None):
        captured["method"] = method
        captured["path"] = path
        captured["body"] = body
        return None

    with patch.object(client, "_request", side_effect=fake_request):
        sid = client.register_ventura_service(
            name="ventura-seg",
            service_id="ventura-seg-test",
            port=8080,
            address="127.0.0.1",
            tags=["security"],
            enable_connect=True,
            health_http="http://127.0.0.1:8080/health",
        )

    assert sid == "ventura-seg-test"
    assert captured["method"] == "PUT"
    assert captured["path"] == "/v1/agent/service/register"
    assert captured["body"]["Name"] == "ventura-seg"
    assert captured["body"]["Port"] == 8080
    assert "Connect" in captured["body"]
    assert captured["body"]["Check"]["HTTP"] == "http://127.0.0.1:8080/health"


def test_discover_parses_instances():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    fake_data = [
        {
            "Node": {"Address": "10.0.0.5"},
            "Service": {
                "ID": "api-1",
                "Service": "payment-api",
                "Address": "10.0.0.5",
                "Port": 9000,
                "Tags": ["prod"],
                "Meta": {"team": "payments"},
            },
            "Checks": [{"ServiceID": "api-1", "Status": "passing"}],
        }
    ]

    with patch.object(client, "_request", return_value=fake_data):
        instances = client.discover("payment-api", passing_only=True)

    assert len(instances) == 1
    assert instances[0].port == 9000
    assert instances[0].healthy is True
    assert "prod" in instances[0].tags
