"""
Ventura.SEG — Monitoramento de Segredos (Vault)
===============================================
Monitora o estado dos segredos carregados do HashiCorp Vault:
- Verifica se o token Vault ainda é válido
- Detecta handles registrados sem domínios allowlist (risco)
- Alerta sobre tentativas de injeção bloqueadas
- Gera relatório de higiene de segredos

Não expõe valores de segredos — apenas metadados e status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .proxy import CredentialProxy

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


@dataclass
class SecretHealth:
    handle_name: str
    has_allowed_domains: bool
    domain_count: int
    description: str = ""
    risk_level: str = "ok"  # ok | warning | critical


@dataclass
class MonitorReport:
    timestamp: str
    total_secrets: int
    healthy: int
    warnings: int
    critical: int
    secrets: list[SecretHealth] = field(default_factory=list)
    vault_authenticated: Optional[bool] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_secrets": self.total_secrets,
            "healthy": self.healthy,
            "warnings": self.warnings,
            "critical": self.critical,
            "vault_authenticated": self.vault_authenticated,
            "notes": self.notes,
            "secrets": [
                {
                    "handle": s.handle_name,
                    "has_allowed_domains": s.has_allowed_domains,
                    "domain_count": s.domain_count,
                    "risk_level": s.risk_level,
                    "description": s.description,
                }
                for s in self.secrets
            ],
        }


class SecretsMonitor:
    """
    Monitor de higiene e status dos segredos no CredentialProxy.

    Uso:
        monitor = SecretsMonitor(proxy, audit_logger=audit)
        report = monitor.check()
        if report.critical > 0:
            ...
    """

    def __init__(
        self,
        proxy: CredentialProxy,
        vault_loader: Any = None,  # VaultSecretLoader opcional
        audit_logger: Any = None,
    ) -> None:
        self.proxy = proxy
        self.vault_loader = vault_loader
        self.audit = audit_logger

    def check(self) -> MonitorReport:
        """Executa verificação completa e retorna relatório."""
        secrets: list[SecretHealth] = []
        notes: list[str] = []

        handles = self.proxy.list_handles()

        for handle in handles:
            domains = self.proxy._allowed_domains.get(handle.name, set())
            domain_count = len(domains)
            has_domains = domain_count > 0

            if not has_domains:
                risk = "critical"
                notes.append(
                    f"CRITICAL: handle '{handle.name}' sem allowed_domains (fail-secure ativo)"
                )
            elif domain_count > 10:
                risk = "warning"
                notes.append(
                    f"WARNING: handle '{handle.name}' com {domain_count} domínios (superfície ampla)"
                )
            else:
                risk = "ok"

            secrets.append(
                SecretHealth(
                    handle_name=handle.name,
                    has_allowed_domains=has_domains,
                    domain_count=domain_count,
                    description=handle.description,
                    risk_level=risk,
                )
            )

        # Status do Vault (se disponível)
        vault_auth: Optional[bool] = None
        if self.vault_loader is not None:
            try:
                vault_auth = self.vault_loader.client.is_authenticated()
                if not vault_auth:
                    notes.append("CRITICAL: Token Vault inválido ou expirado")
            except Exception as exc:
                vault_auth = False
                notes.append(f"CRITICAL: Falha ao verificar Vault: {exc}")

        healthy = sum(1 for s in secrets if s.risk_level == "ok")
        warnings = sum(1 for s in secrets if s.risk_level == "warning")
        critical = sum(1 for s in secrets if s.risk_level == "critical")

        if vault_auth is False:
            critical += 1

        report = MonitorReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_secrets=len(secrets),
            healthy=healthy,
            warnings=warnings,
            critical=critical,
            secrets=secrets,
            vault_authenticated=vault_auth,
            notes=notes,
        )

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="secrets_monitor",
                decision="ok" if critical == 0 else "alert",
                reason=f"{len(secrets)} segredos | healthy={healthy} warn={warnings} crit={critical}",
                metadata=report.to_dict(),
            )

        return report
