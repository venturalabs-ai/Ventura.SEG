"""
Ventura.SEG — Proxy de Credenciais
==================================
Fica fora do perímetro do agente. Injeta tokens/segredos nas requisições
sem que o agente jamais os veja. Aplica allowlist de domínios.

Suporta carregamento de segredos via HashiCorp Vault.

Princípio: Segredo nunca exposto ao modelo.
"""

from .proxy import CredentialProxy, CredentialHandle, InjectionResult

try:
    from .vault import VaultSecretLoader
    _vault_available = True
except ImportError:
    VaultSecretLoader = None  # type: ignore
    _vault_available = False

__all__ = [
    "CredentialProxy",
    "CredentialHandle",
    "InjectionResult",
    "VaultSecretLoader",
]
