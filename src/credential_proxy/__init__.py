"""
Ventura.SEG — Proxy de Credenciais
==================================
Fica fora do perímetro do agente. Injeta tokens/segredos nas requisições
sem que o agente jamais os veja. Aplica allowlist de domínios.

Suporta carregamento de segredos via HashiCorp Vault e monitoramento de higiene.

Princípio: Segredo nunca exposto ao modelo.
"""

from .proxy import CredentialProxy, CredentialHandle, InjectionResult
from .monitor import SecretsMonitor, MonitorReport, SecretHealth

try:
    from .vault import VaultSecretLoader
except ImportError:
    VaultSecretLoader = None  # type: ignore

__all__ = [
    "CredentialProxy",
    "CredentialHandle",
    "InjectionResult",
    "VaultSecretLoader",
    "SecretsMonitor",
    "MonitorReport",
    "SecretHealth",
]
