"""
Ventura.SEG — Renovação Automática de Sessão Vault
====================================================
Mantém a sessão Vault viva em background:

1. Tenta `token renew-self` (se o token for renovável)
2. Se falhar ou não for renovável, faz reauth OIDC/JWT com JWT fresco
3. Agenda a próxima renovação com base no lease (default: 2/3 da duração)

Variáveis de ambiente:
  VAULT_RENEW_ENABLED     true|false  (default: true quando start() é chamado)
  VAULT_RENEW_MARGIN      fração do lease antes de renovar (default: 0.66)
  VAULT_RENEW_MIN_SECONDS intervalo mínimo entre tentativas (default: 30)
  VAULT_RENEW_MAX_SECONDS intervalo máximo entre tentativas (default: 3600)
  VAULT_OIDC_JWT_PATH     arquivo re-lido a cada reauth (K8s SA token)
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .vault import VaultSecretLoader


# Callback opcional: retorna um JWT fresco do Identity Provider
JwtProvider = Callable[[], Optional[str]]


@dataclass
class RenewStatus:
    """Snapshot do estado do renovador (sem segredos)."""
    running: bool
    last_success: Optional[str]
    last_error: Optional[str]
    next_renew_in_seconds: Optional[float]
    lease_duration: Optional[int]
    renew_count: int
    method_last_used: Optional[str]  # "token_renew" | "oidc_reauth"


class VaultAutoRenewer:
    """
    Renovador automático em thread daemon.

    Uso:
        loader = VaultSecretLoader.from_oidc(...)
        renewer = VaultAutoRenewer(loader, lease_duration=3600)
        renewer.start()
        ...
        renewer.stop()
    """

    def __init__(
        self,
        loader: "VaultSecretLoader",
        lease_duration: Optional[int] = None,
        jwt_provider: Optional[JwtProvider] = None,
        jwt_path: Optional[str] = None,
        margin: Optional[float] = None,
        audit_logger: Any = None,
    ) -> None:
        self.loader = loader
        self.audit = audit_logger or getattr(loader, "audit", None)
        self.jwt_provider = jwt_provider
        self.jwt_path = jwt_path or os.getenv("VAULT_OIDC_JWT_PATH")

        self.lease_duration = lease_duration or int(
            os.getenv("VAULT_LEASE_DURATION", "3600")
        )
        self.margin = margin if margin is not None else float(
            os.getenv("VAULT_RENEW_MARGIN", "0.66")
        )
        self.min_interval = int(os.getenv("VAULT_RENEW_MIN_SECONDS", "30"))
        self.max_interval = int(os.getenv("VAULT_RENEW_MAX_SECONDS", "3600"))

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self._last_success: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._renew_count = 0
        self._method_last: Optional[str] = None
        self._next_wait: Optional[float] = None

    # ------------------------------------------------------------------
    # Controle do loop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Inicia a thread de renovação (daemon). Idempotente."""
        if self._thread and self._thread.is_alive():
            return

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="ventura-vault-auto-renew",
            daemon=True,
        )
        self._thread.start()

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_auto_renew_start",
                decision="success",
                reason=f"Auto-renew iniciado (lease={self.lease_duration}s, margin={self.margin})",
                metadata={
                    "lease_duration": self.lease_duration,
                    "margin": self.margin,
                },
            )

    def stop(self, timeout: float = 5.0) -> None:
        """Sinaliza parada e aguarda a thread."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        if self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_auto_renew_stop",
                decision="success",
                reason="Auto-renew parado",
                metadata={"renew_count": self._renew_count},
            )

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def status(self) -> RenewStatus:
        return RenewStatus(
            running=self.running,
            last_success=self._last_success.isoformat() if self._last_success else None,
            last_error=self._last_error,
            next_renew_in_seconds=self._next_wait,
            lease_duration=self.lease_duration,
            renew_count=self._renew_count,
            method_last_used=self._method_last,
        )

    # ------------------------------------------------------------------
    # Loop interno
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            wait = self._compute_wait()
            self._next_wait = wait

            # Espera interrompível
            if self._stop.wait(timeout=wait):
                break

            try:
                ok = self.renew_once()
                if ok:
                    self._last_success = datetime.now(timezone.utc)
                    self._last_error = None
                    self._renew_count += 1
                else:
                    self._last_error = "renew_once retornou False"
            except Exception as exc:
                self._last_error = str(exc)
                if self.audit:
                    self.audit.log_event(
                        component="credential_proxy",
                        action="vault_auto_renew",
                        decision="failed",
                        reason=str(exc),
                    )
                # Backoff simples em caso de erro
                self._next_wait = min(self.min_interval * 2, self.max_interval)

    def _compute_wait(self) -> float:
        """Calcula segundos até a próxima tentativa (2/3 do lease por padrão)."""
        raw = self.lease_duration * self.margin
        return max(self.min_interval, min(raw, self.max_interval))

    # ------------------------------------------------------------------
    # Uma tentativa de renovação
    # ------------------------------------------------------------------

    def renew_once(self) -> bool:
        """
        Tenta renovar a sessão atual.

        Ordem:
          1. token renew-self (se suportado)
          2. reauth OIDC/JWT com JWT fresco
        """
        with self._lock:
            # 1) Renew do token Vault
            if self._try_token_renew():
                self._method_last = "token_renew"
                return True

            # 2) Reauth OIDC/JWT
            if self._try_oidc_reauth():
                self._method_last = "oidc_reauth"
                return True

            return False

    def _try_token_renew(self) -> bool:
        """Usa a API de renew do próprio token Vault."""
        client = self.loader.client
        try:
            # hvac: renew_self retorna dados do token renovado
            resp = client.auth.token.renew_self()
            lease = (
                resp.get("auth", {}).get("lease_duration")
                or resp.get("lease_duration")
            )
            if lease:
                self.lease_duration = int(lease)

            if self.audit:
                self.audit.log_event(
                    component="credential_proxy",
                    action="vault_auto_renew",
                    decision="success",
                    reason="Token Vault renovado (renew-self)",
                    metadata={
                        "method": "token_renew",
                        "lease_duration": self.lease_duration,
                    },
                )
            return True
        except Exception:
            return False

    def _try_oidc_reauth(self) -> bool:
        """Reautentica com JWT fresco (provider, path ou env)."""
        jwt: Optional[str] = None

        if self.jwt_provider:
            try:
                jwt = self.jwt_provider()
            except Exception as exc:
                if self.audit:
                    self.audit.log_event(
                        component="credential_proxy",
                        action="vault_auto_renew",
                        decision="failed",
                        reason=f"jwt_provider falhou: {exc}",
                    )

        if not jwt and self.jwt_path:
            path = Path(self.jwt_path)
            if path.is_file():
                jwt = path.read_text(encoding="utf-8").strip()

        ok = self.loader.reauthenticate_oidc(jwt=jwt, jwt_path=self.jwt_path)

        if ok and self.audit:
            self.audit.log_event(
                component="credential_proxy",
                action="vault_auto_renew",
                decision="success",
                reason="Sessão renovada via OIDC/JWT reauth",
                metadata={"method": "oidc_reauth"},
            )
        return ok


def start_auto_renew(
    loader: "VaultSecretLoader",
    lease_duration: Optional[int] = None,
    jwt_provider: Optional[JwtProvider] = None,
    jwt_path: Optional[str] = None,
    audit_logger: Any = None,
) -> VaultAutoRenewer:
    """
    Atalho: cria e inicia o renovador.

    Respeita VAULT_RENEW_ENABLED (default: true).
    """
    enabled = os.getenv("VAULT_RENEW_ENABLED", "true").lower() in ("1", "true", "yes")
    renewer = VaultAutoRenewer(
        loader=loader,
        lease_duration=lease_duration,
        jwt_provider=jwt_provider,
        jwt_path=jwt_path,
        audit_logger=audit_logger,
    )
    if enabled:
        renewer.start()
    return renewer
