"""
Ventura.SEG — Proxy de Credenciais
==================================
Fica fora do perímetro do agente. Injeta tokens/segredos nas requisições
sem que o agente jamais os veja. Aplica allowlist de domínios.

Suporta:
- HashiCorp Vault (token, OIDC, JWT)
- Renovação automática de sessão
- Monitoramento de higiene de segredos

Princípio: Segredo nunca exposto ao modelo.
"""

from .proxy import CredentialProxy, CredentialHandle, InjectionResult
from .monitor import SecretsMonitor, MonitorReport, SecretHealth
from .auto_renew import VaultAutoRenewer, RenewStatus, start_auto_renew

try:
    from .vault import VaultSecretLoader, VaultAuthMethod
except ImportError:
    VaultSecretLoader = None  # type: ignore
    VaultAuthMethod = None  # type: ignore

__all__ = [
    "CredentialProxy",
    "CredentialHandle",
    "InjectionResult",
    "VaultSecretLoader",
    "VaultAuthMethod",
    "VaultAutoRenewer",
    "RenewStatus",
    "start_auto_renew",
    "SecretsMonitor",
    "MonitorReport",
    "SecretHealth",
]
