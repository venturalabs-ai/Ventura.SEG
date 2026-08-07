"""
Ventura.SEG — Integração HashiCorp Vault
=========================================
Carrega segredos do Vault e os registra no CredentialProxy
sem jamais expor os valores ao contexto do agente.

Requisitos:
  pip install hvac

Variáveis de ambiente esperadas:
  VAULT_ADDR   — URL do Vault (ex: https://vault.exemplo.com:8200)
  VAULT_TOKEN  — Token de autenticação (ou use AppRole)
"""

from __future__ import annotations

import os
from typing import Any, Optional

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

from .proxy import CredentialProxy, CredentialHandle


class VaultSecretLoader:
    """
    Carrega segredos do HashiCorp Vault e registra no CredentialProxy.

    Uso:
        proxy = CredentialProxy(audit_logger=audit)
        loader = VaultSecretLoader(proxy)

        # Carrega um segredo KV v2
        loader.load_kv(
            mount="secret",
            path="agents/github",
            key="token",
            handle_name="github_token",
            allowed_domains=["api.github.com", "github.com"],
        )
    """

    def __init__(
        self,
        proxy: CredentialProxy,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        audit_logger: Any = None,
    ) -> None:
        if not HVAC_AVAILABLE:
            raise ImportError(
                "Pacote 'hvac' não instalado. Execute: pip install hvac"
            )

        self.proxy = proxy
        self.audit = audit_logger
        self.vault_addr = vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")

        self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)

        if not self.client.is_authenticated():
            raise PermissionError(
                f"Falha na autenticação com Vault em {self.vault_addr}. "
                "Verifique VAULT_TOKEN ou AppRole."
            )

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_connect",
                decision="success",
                reason=f"Conectado ao Vault em {self.vault_addr}",
            )

    def load_kv(
        self,
        mount: str,
        path: str,
        key: str,
        handle_name: str,
        allowed_domains: list[str] | None = None,
        description: str = "",
        kv_version: int = 2,
    ) -> CredentialHandle:
        """
        Lê um segredo do KV engine e registra no proxy.

        O valor real nunca é logado — apenas o handle_name e o path.
        """
        try:
            if kv_version == 2:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=mount,
                )
                data = response["data"]["data"]
            else:
                response = self.client.secrets.kv.v1.read_secret(
                    path=path,
                    mount_point=mount,
                )
                data = response["data"]

            secret_value = data.get(key)
            if secret_value is None:
                raise KeyError(f"Chave '{key}' não encontrada em {mount}/{path}")

            handle = self.proxy.register(
                name=handle_name,
                secret=secret_value,
                allowed_domains=allowed_domains,
                description=description or f"Vault:{mount}/{path}#{key}",
            )

            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_load",
                    decision="success",
                    reason=f"Segredo carregado: {mount}/{path}#{key} → handle '{handle_name}'",
                    metadata={
                        "mount": mount,
                        "path": path,
                        "key": key,
                        "handle": handle_name,
                        "allowed_domains": allowed_domains or [],
                    },
                )

            return handle

        except Exception as exc:
            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_load",
                    decision="failed",
                    reason=str(exc),
                    metadata={"mount": mount, "path": path, "key": key},
                )
            raise

    def load_multiple(
        self,
        secrets: list[dict],
    ) -> list[CredentialHandle]:
        """
        Carrega múltiplos segredos de uma vez.

        Cada item do formato:
          {
            "mount": "secret",
            "path": "agents/github",
            "key": "token",
            "handle_name": "github_token",
            "allowed_domains": ["api.github.com"]
          }
        """
        handles = []
        for item in secrets:
            handle = self.load_kv(
                mount=item["mount"],
                path=item["path"],
                key=item["key"],
                handle_name=item["handle_name"],
                allowed_domains=item.get("allowed_domains"),
                description=item.get("description", ""),
                kv_version=item.get("kv_version", 2),
            )
            handles.append(handle)
        return handles
