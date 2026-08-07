"""Testes básicos do Motor de Permissões do Ventura.SEG"""

import sys
from pathlib import Path

# Garante que o src está no path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from permissions.engine import Action, PermissionEngine


def test_block_rm_rf():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_command("rm -rf /")
    assert decision.action == Action.BLOCK
    assert decision.rule_id == "destructive-rm"


def test_allow_ls():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_command("ls -la")
    assert decision.action == Action.ALLOW


def test_ask_git_push():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_command("git push origin main")
    assert decision.action == Action.ASK
    assert decision.requires_human is True


def test_block_sensitive_path():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_command("cat ~/.ssh/id_rsa")
    assert decision.action == Action.BLOCK


def test_domain_allow():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_domain("api.github.com")
    assert decision.action == Action.ALLOW


def test_domain_block():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_domain("pastebin.com")
    assert decision.action == Action.BLOCK


def test_default_block_unknown():
    engine = PermissionEngine.from_policy_dir(ROOT / "policies")
    decision = engine.evaluate_command("some_unknown_binary --flag")
    assert decision.action == Action.BLOCK
