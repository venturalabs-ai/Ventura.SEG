"""
Ventura.SEG — Proxy de Credenciais
==================================
Fica fora do perímetro do agente. Injeta tokens/segredos nas requisições
sem que o agente jamais os veja. Aplica allowlist de domínios.

Suporta:
- Carregamento via HashiCorp Vault (token estático, OIDC, JWT)
- Monitoramento de higiene de segredos

Princípio: Segredo nunca exposto ao modelo.
"""

from .proxy import CredentialProxy, CredentialHandle, InjectionResult
from .monitor import SecretsMonitor, MonitorReport, SecretHealth

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
    "SecretsMonitor",
    "MonitorReport",
    "SecretHealth",
]
