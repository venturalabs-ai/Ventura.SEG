"""
Ventura.SEG — Integração HashiCorp Vault (+ OIDC)
==================================================
Carrega segredos do Vault e os registra no CredentialProxy
sem jamais expor os valores ao contexto do agente.

Métodos de autenticação suportados:
  1. Token estático          — VAULT_TOKEN
  2. OIDC / JWT              — login via auth method jwt/oidc do Vault

Requisitos:
  pip install hvac

Variáveis de ambiente:
  VAULT_ADDR              URL do Vault (ex: https://vault.exemplo.com:8200)
  VAULT_TOKEN             Token estático (modo token)
  VAULT_AUTH_METHOD       token | oidc | jwt  (default: token)
  VAULT_OIDC_ROLE         Role configurada no auth method OIDC/JWT
  VAULT_OIDC_PATH         Mount path do auth method (default: oidc ou jwt)
  VAULT_OIDC_JWT          JWT emitido pelo Identity Provider
  VAULT_OIDC_JWT_PATH     Caminho de arquivo com o JWT (ex: service account K8s)
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Optional

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

from .proxy import CredentialProxy, CredentialHandle


class VaultAuthMethod(str, Enum):
    TOKEN = "token"
    OIDC = "oidc"
    JWT = "jwt"


class VaultSecretLoader:
    """
    Carrega segredos do HashiCorp Vault e registra no CredentialProxy.

    Exemplos
    --------
    # Token estático
    loader = VaultSecretLoader(proxy)

    # OIDC / JWT
    loader = VaultSecretLoader.from_oidc(
        proxy,
        role="ventura-seg",
        jwt=os.environ["VAULT_OIDC_JWT"],
        auth_path="oidc",
    )
    """

    def __init__(
        self,
        proxy: CredentialProxy,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        audit_logger: Any = None,
        *,
        _client: Any = None,
        auth_method: VaultAuthMethod = VaultAuthMethod.TOKEN,
    ) -> None:
        if not HVAC_AVAILABLE:
            raise ImportError(
                "Pacote 'hvac' não instalado. Execute: pip install hvac"
            )

        self.proxy = proxy
        self.audit = audit_logger
        self.vault_addr = vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.auth_method = auth_method
        self._oidc_role: Optional[str] = None
        self._oidc_path: Optional[str] = None

        if _client is not None:
            self.client = _client
        else:
            token = vault_token or os.getenv("VAULT_TOKEN")
            self.client = hvac.Client(url=self.vault_addr, token=token)

            if not self.client.is_authenticated():
                raise PermissionError(
                    f"Falha na autenticação com Vault em {self.vault_addr}. "
                    "Use VAULT_TOKEN ou VaultSecretLoader.from_oidc(...)."
                )

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_connect",
                decision="success",
                reason=f"Conectado ao Vault em {self.vault_addr} via {self.auth_method.value}",
                metadata={"auth_method": self.auth_method.value},
            )

    @classmethod
    def from_oidc(
        cls,
        proxy: CredentialProxy,
        role: Optional[str] = None,
        jwt: Optional[str] = None,
        jwt_path: Optional[str] = None,
        auth_path: Optional[str] = None,
        vault_addr: Optional[str] = None,
        audit_logger: Any = None,
        method: VaultAuthMethod = VaultAuthMethod.OIDC,
    ) -> "VaultSecretLoader":
        if not HVAC_AVAILABLE:
            raise ImportError("Pacote 'hvac' não instalado. Execute: pip install hvac")

        addr = vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        role = role or os.getenv("VAULT_OIDC_ROLE")
        auth_path = auth_path or os.getenv("VAULT_OIDC_PATH") or method.value
        jwt_token = jwt or os.getenv("VAULT_OIDC_JWT")

        if not jwt_token:
            path = jwt_path or os.getenv("VAULT_OIDC_JWT_PATH")
            if path and Path(path).is_file():
                jwt_token = Path(path).read_text(encoding="utf-8").strip()

        if not role:
            raise ValueError(
                "Role OIDC/JWT obrigatória. Informe role= ou VAULT_OIDC_ROLE."
            )
        if not jwt_token:
            raise ValueError(
                "JWT obrigatório. Informe jwt=, VAULT_OIDC_JWT ou VAULT_OIDC_JWT_PATH."
            )

        client = hvac.Client(url=addr)

        try:
            login_response = client.auth.jwt.jwt_login(
                role=role,
                jwt=jwt_token,
                path=auth_path,
            )
            client_token = login_response["auth"]["client_token"]
            client.token = client_token
        except Exception as exc:
            if audit_logger:
                audit_logger.log_event(
                    component="credential_proxy",
                    action="vault_oidc_login",
                    decision="failed",
                    reason=str(exc),
                    metadata={"role": role, "auth_path": auth_path},
                )
            raise PermissionError(
                f"Falha no login OIDC/JWT no Vault (path={auth_path}, role={role}): {exc}"
            ) from exc

        if not client.is_authenticated():
            raise PermissionError("Login OIDC/JWT concluído, mas cliente não autenticado.")

        if audit_logger:
            lease = login_response.get("auth", {}).get("lease_duration")
            audit_logger.log_event(
                component="credential_proxy",
                action="vault_oidc_login",
                decision="success",
                reason=f"Login OIDC/JWT ok (role={role}, path={auth_path})",
                metadata={
                    "role": role,
                    "auth_path": auth_path,
                    "lease_duration": lease,
                    "auth_method": method.value,
                },
            )

        loader = cls(
            proxy=proxy,
            vault_addr=addr,
            audit_logger=audit_logger,
            _client=client,
            auth_method=method,
        )
        loader._oidc_role = role
        loader._oidc_path = auth_path
        return loader

    @classmethod
    def from_env(cls, proxy: CredentialProxy, audit_logger: Any = None) -> "VaultSecretLoader":
        method_raw = (os.getenv("VAULT_AUTH_METHOD") or "token").lower().strip()
        try:
            method = VaultAuthMethod(method_raw)
        except ValueError:
            method = VaultAuthMethod.TOKEN

        if method in (VaultAuthMethod.OIDC, VaultAuthMethod.JWT):
            return cls.from_oidc(
                proxy=proxy,
                method=method,
                auth_path=os.getenv("VAULT_OIDC_PATH") or method.value,
                audit_logger=audit_logger,
            )

        return cls(proxy=proxy, audit_logger=audit_logger, auth_method=VaultAuthMethod.TOKEN)

    def reauthenticate_oidc(
        self,
        jwt: Optional[str] = None,
        jwt_path: Optional[str] = None,
    ) -> bool:
        if self.auth_method not in (VaultAuthMethod.OIDC, VaultAuthMethod.JWT):
            return False
        if not self._oidc_role:
            return False

        jwt_token = jwt or os.getenv("VAULT_OIDC_JWT")
        if not jwt_token:
            path = jwt_path or os.getenv("VAULT_OIDC_JWT_PATH")
            if path and Path(path).is_file():
                jwt_token = Path(path).read_text(encoding="utf-8").strip()

        if not jwt_token:
            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_oidc_renew",
                    decision="failed",
                    reason="JWT ausente para reautenticação",
                )
            return False

        try:
            login_response = self.client.auth.jwt.jwt_login(
                role=self._oidc_role,
                jwt=jwt_token,
                path=self._oidc_path or self.auth_method.value,
            )
            self.client.token = login_response["auth"]["client_token"]

            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_oidc_renew",
                    decision="success",
                    reason="Sessão Vault renovada via OIDC/JWT",
                    metadata={"role": self._oidc_role},
                )
            return self.client.is_authenticated()
        except Exception as exc:
            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_oidc_renew",
                    decision="failed",
                    reason=str(exc),
                )
            return False

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
                        "auth_method": self.auth_method.value,
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

    def load_multiple(self, secrets: list[dict]) -> list[CredentialHandle]:
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
