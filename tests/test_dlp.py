"""Testes de segurança — Motor DLP (Data Loss Prevention)"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gateway_out.dlp import DLPGateway, DLPAction


def _dlp():
    return DLPGateway.from_policy_file(ROOT / "policies" / "dlp_rules.yaml")


def test_block_aws_key():
    dlp = _dlp()
    result = dlp.scan("AWS key: AKIAIOSFODNN7EXAMPLE")
    assert result.action == DLPAction.BLOCK
    assert result.rule_id == "aws-access-key"


def test_block_github_token():
    dlp = _dlp()
    result = dlp.scan("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert result.action == DLPAction.BLOCK
    assert result.rule_id == "github-token"


def test_block_private_key():
    dlp = _dlp()
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    result = dlp.scan(content)
    assert result.action == DLPAction.BLOCK
    assert result.rule_id == "private-key-pem"


def test_block_vault_token():
    dlp = _dlp()
    result = dlp.scan("vault token: hvs.CAESIJabcdefghijklmnopqrstuvwx")
    assert result.action == DLPAction.BLOCK
    assert result.rule_id == "vault-token"


def test_ask_jwt():
    dlp = _dlp()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    result = dlp.scan(jwt)
    assert result.action == DLPAction.ASK


def test_allow_clean_text():
    dlp = _dlp()
    result = dlp.scan("Hello world, this is a normal message without secrets.")
    assert result.action == DLPAction.ALLOW


def test_matched_content_is_redacted_in_decision():
    dlp = _dlp()
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = dlp.scan(f"key={secret}")
    assert result.blocked
    # O matched_content não deve conter o segredo completo
    if result.matched_content:
        assert secret not in result.matched_content
