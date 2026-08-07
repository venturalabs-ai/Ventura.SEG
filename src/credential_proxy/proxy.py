"""
Ventura.SEG — Proxy de Credenciais
==================================
Mantém segredos FORA do perímetro do agente.

O agente nunca vê a chave real. Em vez disso, ele recebe um handle
opaco (ex: "cred:github_token"). O proxy resolve o handle e injeta
o segredo apenas no momento da chamada real, e somente se o destino
estiver na allowlist.

Princípio: Segredo nunca exposto ao modelo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


@dataclass
class CredentialHandle:
    """Handle opaco que o agente pode usar no lugar do segredo real."""
    name: str
    description: str = ""

    def __str__(self) -> str:
        return f"cred:{self.name}"


@dataclass
class InjectionResult:
    success: bool
    reason: str
    injected: bool = False  # True se o segredo foi realmente injetado


class CredentialProxy:
    """
    Proxy de credenciais.

    Uso típico:
        proxy = CredentialProxy(audit_logger=audit)
        proxy.register("github_token", os.getenv("GITHUB_TOKEN"), allowed_domains=["api.github.com"])

        # O agente só conhece o handle
        handle = proxy.get_handle("github_token")  # → "cred:github_token"

        # Na hora da chamada real:
        result = proxy.inject("github_token", target_url="https://api.github.com/user")
        if result.success:
            real_token = proxy.resolve("github_token")  # só aqui o segredo aparece
    """

    def __init__(self, audit_logger: Any = None) -> None:
        self._store: dict[str, str] = {}           # name → secret value
        self._allowed_domains: dict[str, set[str]] = {}  # name → domains permitidos
        self._descriptions: dict[str, str] = {}
        self.audit = audit_logger

    def register(
        self,
        name: str,
        secret: str,
        allowed_domains: list[str] | None = None,
        description: str = "",
    ) -> CredentialHandle:
        """
        Registra um segredo no proxy.

        O segredo fica apenas na memória do proxy (nunca é logado).
        """
        if not name or not secret:
            raise ValueError("name e secret são obrigatórios")

        self._store[name] = secret
        self._allowed_domains[name] = set(d.lower() for d in (allowed_domains or []))
        self._descriptions[name] = description

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="register",
                decision="success",
                reason=f"Credencial '{name}' registrada",
                metadata={"allowed_domains": list(self._allowed_domains[name])},
            )

        return CredentialHandle(name=name, description=description)

    def get_handle(self, name: str) -> Optional[CredentialHandle]:
        """Retorna o handle opaco (o que o agente pode ver)."""
        if name not in self._store:
            return None
        return CredentialHandle(name=name, description=self._descriptions.get(name, ""))

    def resolve(self, name: str) -> Optional[str]:
        """
        Resolve o handle para o segredo real.

        ATENÇÃO: este método deve ser chamado APENAS pelo próprio proxy
        ou por código de infraestrutura confiável — nunca pelo agente.
        """
        return self._store.get(name)

    def inject(self, name: str, target_url: str) -> InjectionResult:
        """
        Verifica se a credencial pode ser injetada para o destino informado.

        Não retorna o segredo — apenas autoriza ou nega a injeção.
        O código chamador deve usar resolve() somente após sucesso.
        """
        if name not in self._store:
            result = InjectionResult(success=False, reason=f"Credencial '{name}' não registrada")
            self._audit_inject(name, target_url, result)
            return result

        domain = self._extract_domain(target_url)
        allowed = self._allowed_domains.get(name, set())

        # Se a lista de domínios estiver vazia, bloqueia por padrão (fail-secure)
        if not allowed:
            result = InjectionResult(
                success=False,
                reason=f"Credencial '{name}' não possui domínios permitidos configurados",
            )
            self._audit_inject(name, target_url, result)
            return result

        if domain not in allowed and not any(domain.endswith("." + d) for d in allowed):
            result = InjectionResult(
                success=False,
                reason=f"Domínio '{domain}' não autorizado para credencial '{name}'",
            )
            self._audit_inject(name, target_url, result)
            return result

        result = InjectionResult(
            success=True,
            reason=f"Injeção autorizada para {domain}",
            injected=True,
        )
        self._audit_inject(name, target_url, result)
        return result

    def list_handles(self) -> list[CredentialHandle]:
        """Lista todos os handles disponíveis (sem expor segredos)."""
        return [
            CredentialHandle(name=n, description=self._descriptions.get(n, ""))
            for n in self._store
        ]

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return (parsed.hostname or "").lower()

    def _audit_inject(self, name: str, target: str, result: InjectionResult) -> None:
        if self.audit is None:
            return
        self.audit.log_event(
            component="credential_proxy",
            action="inject_attempt",
            decision="success" if result.success else "blocked",
            reason=result.reason,
            metadata={"credential": name, "target": target},
        )
