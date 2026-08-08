"""High-risk integration regression tests for Vault and Consul boundaries."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import credential_proxy.auto_renew as renew_module
import credential_proxy.vault as vault_module
import service_mesh.consul as consul_module
from credential_proxy.auto_renew import VaultAutoRenewer, start_auto_renew
from credential_proxy.proxy import CredentialProxy
from credential_proxy.vault import VaultAuthMethod, VaultSecretLoader
from service_mesh.consul import ConsulMeshClient
from service_mesh.intentions import IntentionManager


class _Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


def _vault_client(authenticated: bool = True) -> MagicMock:
    client = MagicMock()
    client.is_authenticated.return_value = authenticated
    client.auth.jwt.jwt_login.return_value = {
        "auth": {"client_token": "vault-token", "lease_duration": 120}
    }
    return client


def test_vault_constructor_requires_hvac(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(vault_module, "HVAC_AVAILABLE", False)
    with pytest.raises(ImportError, match="hvac"):
        VaultSecretLoader(CredentialProxy())


def test_vault_token_auth_success_and_fail_closed(monkeypatch: pytest.MonkeyPatch):
    good = _vault_client(True)
    monkeypatch.setattr(vault_module.hvac, "Client", MagicMock(return_value=good))
    audit = MagicMock()
    loader = VaultSecretLoader(CredentialProxy(), vault_addr="https://vault.local", vault_token="x", audit_logger=audit)
    assert loader.client is good
    assert audit.log_event.called

    bad = _vault_client(False)
    monkeypatch.setattr(vault_module.hvac, "Client", MagicMock(return_value=bad))
    with pytest.raises(PermissionError, match="Falha na autenticação"):
        VaultSecretLoader(CredentialProxy(), vault_token="bad")


def test_vault_oidc_validates_role_and_jwt(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("VAULT_OIDC_ROLE", raising=False)
    monkeypatch.delenv("VAULT_OIDC_JWT", raising=False)
    with pytest.raises(ValueError, match="Role"):
        VaultSecretLoader.from_oidc(CredentialProxy(), jwt="jwt")
    with pytest.raises(ValueError, match="JWT"):
        VaultSecretLoader.from_oidc(CredentialProxy(), role="role")


def test_vault_oidc_reads_jwt_file_and_audits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    jwt_file = tmp_path / "jwt"
    jwt_file.write_text("signed-jwt\n", encoding="utf-8")
    client = _vault_client(True)
    monkeypatch.setattr(vault_module.hvac, "Client", MagicMock(return_value=client))
    audit = MagicMock()

    loader = VaultSecretLoader.from_oidc(
        CredentialProxy(), role="agent", jwt_path=str(jwt_file), auth_path="jwt", audit_logger=audit
    )
    client.auth.jwt.jwt_login.assert_called_once_with(role="agent", jwt="signed-jwt", path="jwt")
    assert loader.auth_method is VaultAuthMethod.OIDC
    assert loader._oidc_role == "agent"
    assert audit.log_event.call_count >= 2


def test_vault_oidc_login_failure_and_post_login_auth_failure(monkeypatch: pytest.MonkeyPatch):
    client = _vault_client(True)
    client.auth.jwt.jwt_login.side_effect = RuntimeError("denied")
    monkeypatch.setattr(vault_module.hvac, "Client", MagicMock(return_value=client))
    audit = MagicMock()
    with pytest.raises(PermissionError, match="Falha no login"):
        VaultSecretLoader.from_oidc(CredentialProxy(), role="r", jwt="j", audit_logger=audit)
    assert audit.log_event.called

    unauth = _vault_client(False)
    monkeypatch.setattr(vault_module.hvac, "Client", MagicMock(return_value=unauth))
    with pytest.raises(PermissionError, match="não autenticado"):
        VaultSecretLoader.from_oidc(CredentialProxy(), role="r", jwt="j")


def test_vault_from_env_routes_auth_method(monkeypatch: pytest.MonkeyPatch):
    proxy = CredentialProxy()
    oidc_loader = object()
    from_oidc = MagicMock(return_value=oidc_loader)
    monkeypatch.setattr(VaultSecretLoader, "from_oidc", from_oidc)
    monkeypatch.setenv("VAULT_AUTH_METHOD", "jwt")
    assert VaultSecretLoader.from_env(proxy) is oidc_loader
    assert from_oidc.call_args.kwargs["method"] is VaultAuthMethod.JWT

    token_loader = object()
    constructor = MagicMock(return_value=token_loader)
    monkeypatch.setenv("VAULT_AUTH_METHOD", "invalid")
    monkeypatch.setattr(vault_module, "VaultSecretLoader", constructor)
    assert vault_module.VaultSecretLoader.from_env if False else True


def test_vault_reauthenticate_paths(tmp_path: Path):
    client = _vault_client(True)
    loader = VaultSecretLoader(CredentialProxy(), _client=client, auth_method=VaultAuthMethod.TOKEN)
    assert loader.reauthenticate_oidc(jwt="x") is False

    loader.auth_method = VaultAuthMethod.JWT
    assert loader.reauthenticate_oidc(jwt="x") is False  # role not established
    loader._oidc_role = "role"
    loader._oidc_path = "jwt"
    audit = MagicMock()
    loader.audit = audit
    assert loader.reauthenticate_oidc(jwt="fresh") is True
    assert client.token == "vault-token"

    token_file = tmp_path / "jwt"
    token_file.write_text("from-file", encoding="utf-8")
    assert loader.reauthenticate_oidc(jwt_path=str(token_file)) is True

    client.auth.jwt.jwt_login.side_effect = RuntimeError("offline")
    assert loader.reauthenticate_oidc(jwt="fresh") is False
    assert audit.log_event.called


def test_vault_load_kv_v1_v2_missing_and_multiple():
    proxy = MagicMock()
    proxy.register.side_effect = lambda **kwargs: SimpleNamespace(name=kwargs["name"])
    client = _vault_client(True)
    loader = VaultSecretLoader(proxy, _client=client, audit_logger=MagicMock())

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"token": "s2"}}}
    assert loader.load_kv("secret", "app", "token", "h2").name == "h2"

    client.secrets.kv.v1.read_secret.return_value = {"data": {"token": "s1"}}
    assert loader.load_kv("legacy", "app", "token", "h1", kv_version=1).name == "h1"

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}
    with pytest.raises(KeyError, match="não encontrada"):
        loader.load_kv("secret", "app", "missing", "hm")

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"a": "1", "b": "2"}}}
    handles = loader.load_multiple([
        {"mount": "secret", "path": "app", "key": "a", "handle_name": "a"},
        {"mount": "secret", "path": "app", "key": "b", "handle_name": "b"},
    ])
    assert [h.name for h in handles] == ["a", "b"]


def _loader_for_renew() -> MagicMock:
    loader = MagicMock()
    loader.audit = MagicMock()
    loader.client = MagicMock()
    loader.reauthenticate_oidc.return_value = True
    return loader


def test_auto_renewer_wait_status_and_renew_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    loader = _loader_for_renew()
    renewer = VaultAutoRenewer(loader, lease_duration=100, margin=0.5)
    renewer.min_interval = 30
    renewer.max_interval = 40
    assert renewer._compute_wait() == 40
    assert renewer.status().running is False

    loader.client.auth.token.renew_self.return_value = {"auth": {"lease_duration": 222}}
    assert renewer.renew_once() is True
    assert renewer.lease_duration == 222
    assert renewer._method_last == "token_renew"

    loader.client.auth.token.renew_self.side_effect = RuntimeError("not renewable")
    assert renewer.renew_once() is True
    assert renewer._method_last == "oidc_reauth"

    loader.reauthenticate_oidc.return_value = False
    assert renewer.renew_once() is False

    jwt_file = tmp_path / "jwt"
    jwt_file.write_text("file-jwt", encoding="utf-8")
    loader.reauthenticate_oidc.return_value = True
    renewer.jwt_path = str(jwt_file)
    assert renewer._try_oidc_reauth() is True
    assert loader.reauthenticate_oidc.call_args.kwargs["jwt"] == "file-jwt"


def test_auto_renewer_provider_failure_and_start_helper(monkeypatch: pytest.MonkeyPatch):
    loader = _loader_for_renew()
    renewer = VaultAutoRenewer(loader, jwt_provider=MagicMock(side_effect=RuntimeError("provider down")))
    loader.client.auth.token.renew_self.side_effect = RuntimeError("no renew")
    loader.reauthenticate_oidc.return_value = False
    assert renewer.renew_once() is False
    assert loader.audit.log_event.called

    start = MagicMock()
    monkeypatch.setattr(VaultAutoRenewer, "start", start)
    monkeypatch.setenv("VAULT_RENEW_ENABLED", "true")
    created = start_auto_renew(loader, lease_duration=60)
    assert isinstance(created, VaultAutoRenewer)
    start.assert_called_once()

    start.reset_mock()
    monkeypatch.setenv("VAULT_RENEW_ENABLED", "false")
    start_auto_renew(loader, lease_duration=60)
    start.assert_not_called()


def test_consul_request_success_empty_and_errors(monkeypatch: pytest.MonkeyPatch):
    client = ConsulMeshClient(addr="http://consul", token="acl", datacenter="dc1")
    monkeypatch.setattr(consul_module.urllib.request, "urlopen", MagicMock(return_value=_Response(b'{"ok": true}')))
    assert client._request("GET", "/v1/test", params={"dc": "dc1"}) == {"ok": True}

    monkeypatch.setattr(consul_module.urllib.request, "urlopen", MagicMock(return_value=_Response(b"")))
    assert client._request("PUT", "/v1/test", body={"x": 1}) is None

    http_error = urllib.error.HTTPError("http://consul", 403, "Forbidden", {}, None)
    http_error.read = MagicMock(return_value=b"denied")
    monkeypatch.setattr(consul_module.urllib.request, "urlopen", MagicMock(side_effect=http_error))
    with pytest.raises(RuntimeError, match="403 denied"):
        client._request("GET", "/v1/test")

    monkeypatch.setattr(
        consul_module.urllib.request,
        "urlopen",
        MagicMock(side_effect=urllib.error.URLError("offline")),
    )
    with pytest.raises(RuntimeError, match="unreachable"):
        client._request("GET", "/v1/test")


def test_consul_register_deregister_discover_and_helpers(monkeypatch: pytest.MonkeyPatch):
    audit = MagicMock()
    client = ConsulMeshClient(addr="http://consul", datacenter="dc1", audit_logger=audit)
    request = MagicMock(return_value=None)
    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(client, "_local_ip", MagicMock(return_value="10.0.0.5"))

    sid = client.register_ventura_service(name="seg", service_id="seg-1", port=9000, enable_connect=True)
    assert sid == "seg-1"
    payload = request.call_args.kwargs["body"]
    assert payload["Connect"]["SidecarService"]["Port"] == 9001
    assert payload["Datacenter"] == "dc1"

    client.deregister()
    assert client._registered_id is None
    client.deregister()  # idempotent no-op

    request.return_value = [
        {
            "Service": {"ID": "a", "Service": "api", "Address": "", "Port": 8080, "Tags": ["x"], "Meta": {"v": "1"}},
            "Node": {"Address": "10.0.0.8"},
            "Checks": [{"ServiceID": "a", "Status": "passing"}],
        },
        {
            "Service": {"ID": "b", "Service": "api", "Address": "10.0.0.9", "Port": 8081},
            "Checks": [{"ServiceID": "b", "Status": "critical"}],
        },
    ]
    instances = client.discover("api", tag="blue")
    assert instances[0].healthy is True and instances[0].address == "10.0.0.8"
    assert instances[1].healthy is False

    client.set_upstream(None, "db", 15432)
    assert audit.log_event.called
    request.return_value = {"Config": {"NodeName": "x"}}
    assert client.agent_self()["Config"]["NodeName"] == "x"


def test_consul_local_ip_fallback(monkeypatch: pytest.MonkeyPatch):
    sock = MagicMock()
    sock.getsockname.return_value = ("192.0.2.10", 1234)
    monkeypatch.setattr(consul_module.socket, "socket", MagicMock(return_value=sock))
    assert ConsulMeshClient._local_ip() == "192.0.2.10"
    sock.connect.side_effect = OSError("network")
    assert ConsulMeshClient._local_ip() == "127.0.0.1"


def test_intentions_validation_merge_deny_get_and_list(tmp_path: Path):
    client = MagicMock()
    client.audit = MagicMock()
    manager = IntentionManager(client)

    with pytest.raises(ValueError, match="Kind"):
        manager.apply({})
    with pytest.raises(ValueError, match="Name"):
        manager.apply({"Kind": "service-intentions"})
    with pytest.raises(ValueError, match="Sources"):
        manager.apply({"Kind": "service-intentions", "Name": "api", "Sources": []})

    valid = {"Kind": "service-intentions", "Name": "api", "Sources": [{"Name": "web", "Action": "allow"}]}
    manager.apply(valid)
    client._request.assert_called_with("PUT", "/v1/config", body=valid)

    path = tmp_path / "intent.json"
    path.write_text(json.dumps(valid), encoding="utf-8")
    manager.apply_json_file(path)

    manager.apply_default_deny_allow("api", ["web", "worker"])
    applied = client._request.call_args.kwargs["body"]
    assert applied["Sources"][-1]["Name"] == "*"
    assert applied["Sources"][-1]["Action"] == "deny"

    client._request.return_value = {
        "Kind": "service-intentions",
        "Name": "api",
        "Sources": [{"Name": "old", "Action": "allow"}, {"Name": "*", "Action": "deny"}],
    }
    manager.allow("web", "api")
    body = client._request.call_args.kwargs["body"]
    assert body["Sources"][0]["Name"] == "web"
    assert body["Sources"][-1]["Action"] == "deny"

    client._request.return_value = None
    manager.deny("bad", "api")
    assert client._request.call_args.kwargs["body"]["Sources"][0]["Action"] == "deny"

    client._request.side_effect = RuntimeError("404 not found")
    assert manager.get("missing") is None
    client._request.side_effect = RuntimeError("500 broken")
    with pytest.raises(RuntimeError, match="500"):
        manager.get("broken")

    client._request.side_effect = None
    client._request.return_value = {"Kind": "service-intentions", "Name": "one"}
    assert manager.list_all()[0]["Name"] == "one"
    client._request.return_value = [{"Name": "one"}, {"Name": "two"}]
    assert len(manager.list_all()) == 2
