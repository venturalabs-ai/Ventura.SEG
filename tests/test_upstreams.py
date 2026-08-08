"""Testes — UpstreamManager (offline)"""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from service_mesh.consul import ConsulMeshClient
from service_mesh.upstreams import UpstreamManager, Upstream


def test_load_yaml():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    mgr = UpstreamManager(client)
    cfg = mgr.load_yaml(ROOT / "consul" / "upstreams.yaml")
    assert cfg.service_name == "ventura-seg"
    assert len(cfg.upstreams) >= 1
    assert any(u.destination_name == "vault" for u in cfg.upstreams)


def test_get_local_endpoint():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    mgr = UpstreamManager(client)
    mgr.load_yaml(ROOT / "consul" / "upstreams.yaml")
    url = mgr.get_local_endpoint("vault")
    assert url == "http://127.0.0.1:8200"


def test_apply_includes_upstreams_in_connect():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    mgr = UpstreamManager(client)
    cfg = mgr.load_yaml(ROOT / "consul" / "upstreams.yaml")
    captured = {}

    def fake_request(method, path, body=None, params=None):
        captured["body"] = body
        return None

    with patch.object(client, "_request", side_effect=fake_request):
        sid = mgr.apply(cfg, service_id="ventura-seg-test", address="127.0.0.1")

    assert sid == "ventura-seg-test"
    ups = captured["body"]["Connect"]["SidecarService"]["Proxy"]["Upstreams"]
    names = [u["DestinationName"] for u in ups]
    assert "vault" in names


def test_add_remove():
    client = ConsulMeshClient(addr="http://127.0.0.1:8500")
    mgr = UpstreamManager(client)
    mgr.add("payments", 9400, description="payments API")
    assert mgr.get_local_endpoint("payments") == "http://127.0.0.1:9400"
    assert mgr.remove("payments") is True
    assert mgr.get_local_endpoint("payments") is None
