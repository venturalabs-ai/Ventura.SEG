"""
Ventura.SEG — HashiCorp Vault Integration
=========================================
Carrega segredos do Vault e registra handles opacos no CredentialProxy.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

from .proxy import CredentialHandle, CredentialProxy


class VaultAuthMethod(str, Enum):
    TOKEN = "token"  # nosec B105 - authentication method identifier, not a credential value
    OIDC = "oidc"
    JWT = "jwt"


class VaultSecretLoader:
    """Carrega segredos do HashiCorp Vault e registra no CredentialProxy."""

    def __init__(
        self,
        proxy: CredentialProxy,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
        audit_logger: Any = None,
        auth_method: VaultAuthMethod = VaultAuthMethod.TOKEN,
    ) -> None:
        if not HVAC_AVAILABLE:
            raise RuntimeError("hvac não instalado. Instale com: pip install hvac")
        self.proxy = proxy
        self.addr = addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.getenv("VAULT_TOKEN")
        self.namespace = namespace or os.getenv("VAULT_NAMESPACE")
        self.audit = audit_logger
        self.auth_method = auth_method
        self.client = hvac.Client(url=self.addr, token=self.token, namespace=self.namespace)
        self._last_auth_check = 0.0

    def is_authenticated(self) -> bool:
        try:
            result = bool(self.client.is_authenticated())
            self._last_auth_check = time.time()
            return result
        except Exception:
            return False

    def load_kv(
        self,
        mount: str,
        path: str,
        key: str,
        handle_name: str,
        allowed_domains: list[str],
        kv_version: int = 2,
        metadata: Optional[dict[str, Any]] = None,
    ) -> CredentialHandle:
        """Lê um campo KV do Vault e registra como handle opaco."""
        if not self.is_authenticated():
            raise RuntimeError("Vault client não autenticado")

        if kv_version == 2:
            response = self.client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
            values = response.get("data", {}).get("data", {})
        elif kv_version == 1:
            response = self.client.secrets.kv.v1.read_secret(path=path, mount_point=mount)
            values = response.get("data", {})
        else:
            raise ValueError("kv_version deve ser 1 ou 2")

        if key not in values:
            raise KeyError(f"Chave '{key}' não encontrada em {mount}/{path}")
        secret = values[key]
        if not isinstance(secret, str) or not secret:
            raise ValueError(f"Segredo '{key}' deve ser string não vazia")

        handle = self.proxy.register(
            handle_name,
            secret,
            allowed_domains=allowed_domains,
            metadata={
                "source": "vault",
                "mount": mount,
                "path": path,
                "key": key,
                **(metadata or {}),
            },
        )
        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_load",
                decision="success",
                reason=f"handle={handle_name} source={mount}/{path}",
                metadata={"handle": handle_name, "mount": mount, "path": path},
            )
        return handle

    def load_many(self, specs: list[dict[str, Any]]) -> list[CredentialHandle]:
        handles = []
        for spec in specs:
            handles.append(self.load_kv(**spec))
        return handles

    def token_info(self) -> dict[str, Any]:
        """Metadados seguros do token Vault; nunca retorna o token."""
        if not self.is_authenticated():
            return {"authenticated": False}
        try:
            data = self.client.auth.token.lookup_self().get("data", {})
            return {
                "authenticated": True,
                "display_name": data.get("display_name"),
                "policies": data.get("policies", []),
                "ttl": data.get("ttl"),
                "renewable": data.get("renewable", False),
            }
        except Exception as exc:
            return {"authenticated": True, "metadata_error": str(exc)}

    def renew_self(self, increment: Optional[str] = None) -> bool:
        try:
            kwargs = {"increment": increment} if increment else {}
            self.client.auth.token.renew_self(**kwargs)
            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_renew",
                    decision="success",
                    reason="Vault token renewed",
                )
            return True
        except Exception as exc:
            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_renew",
                    decision="failed",
                    reason=str(exc),
                )
            return False
