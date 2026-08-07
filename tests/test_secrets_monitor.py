"""Testes — Monitoramento de Segredos"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from credential_proxy.proxy import CredentialProxy
from credential_proxy.monitor import SecretsMonitor


def test_monitor_detects_missing_domains():
    proxy = CredentialProxy()
    proxy.register("bad", "secret", allowed_domains=[])  # sem domínios
    monitor = SecretsMonitor(proxy)
    report = monitor.check()
    assert report.critical >= 1
    assert any(s.risk_level == "critical" for s in report.secrets)


def test_monitor_healthy_secret():
    proxy = CredentialProxy()
    proxy.register("good", "secret", allowed_domains=["api.github.com"])
    monitor = SecretsMonitor(proxy)
    report = monitor.check()
    assert report.total_secrets == 1
    assert report.healthy == 1
    assert report.critical == 0


def test_monitor_report_has_no_secret_values():
    proxy = CredentialProxy()
    proxy.register("x", "SUPER_SECRET_VALUE_123", allowed_domains=["x.com"])
    monitor = SecretsMonitor(proxy)
    report = monitor.check()
    blob = str(report.to_dict())
    assert "SUPER_SECRET_VALUE_123" not in blob
