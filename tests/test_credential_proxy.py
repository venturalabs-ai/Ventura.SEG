"""Testes de segurança — Proxy de Credenciais"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from credential_proxy.proxy import CredentialProxy


def test_register_and_get_handle():
    proxy = CredentialProxy()
    handle = proxy.register(
        "github_token",
        "ghp_secretvalue123456789012345678",
        allowed_domains=["api.github.com"],
    )
    assert str(handle) == "cred:github_token"
    assert proxy.get_handle("github_token") is not None


def test_handle_does_not_expose_secret():
    proxy = CredentialProxy()
    secret = "super_secret_value_xyz"
    handle = proxy.register("mykey", secret, allowed_domains=["example.com"])
    assert secret not in str(handle)
    assert secret not in handle.name


def test_inject_allowed_domain():
    proxy = CredentialProxy()
    proxy.register("gh", "token123", allowed_domains=["api.github.com"])
    result = proxy.inject("gh", "https://api.github.com/user")
    assert result.success is True
    assert result.injected is True


def test_inject_blocked_domain():
    proxy = CredentialProxy()
    proxy.register("gh", "token123", allowed_domains=["api.github.com"])
    result = proxy.inject("gh", "https://evil.example.com/steal")
    assert result.success is False
    assert result.injected is False


def test_inject_unknown_credential():
    proxy = CredentialProxy()
    result = proxy.inject("nao_existe", "https://api.github.com")
    assert result.success is False


def test_inject_without_allowed_domains_fails_secure():
    proxy = CredentialProxy()
    proxy.register("orphan", "secret", allowed_domains=[])  # lista vazia
    result = proxy.inject("orphan", "https://anything.com")
    assert result.success is False  # fail-secure


def test_list_handles_no_secrets():
    proxy = CredentialProxy()
    proxy.register("a", "secret_a", allowed_domains=["a.com"])
    proxy.register("b", "secret_b", allowed_domains=["b.com"])
    handles = proxy.list_handles()
    serialized = " ".join(str(h) for h in handles)
    assert "secret_a" not in serialized
    assert "secret_b" not in serialized
