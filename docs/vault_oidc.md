# Vault + OIDC — Ventura.SEG

## Visão

O `VaultSecretLoader` autentica no HashiCorp Vault **sem** entregar um token de longa duração ao agente. Com OIDC/JWT:

1. O Identity Provider emite um JWT.
2. O Ventura.SEG envia esse JWT ao Vault (`auth/oidc` ou `auth/jwt`).
3. O Vault valida o JWT e devolve um **client token** de curta duração.
4. Esse token fica só no proxy — o agente nunca o vê.
5. Segredos são lidos e registrados como handles opacos (`cred:...`).
6. **Renovação automática** mantém a sessão viva em background.

## Variáveis de ambiente

| Variável | Descrição |
|----------|-----------|
| `VAULT_ADDR` | URL do Vault |
| `VAULT_AUTH_METHOD` | `token` \| `oidc` \| `jwt` |
| `VAULT_OIDC_ROLE` | Role no auth method |
| `VAULT_OIDC_PATH` | Mount path (default: `oidc` / `jwt`) |
| `VAULT_OIDC_JWT` | JWT em texto |
| `VAULT_OIDC_JWT_PATH` | Arquivo com JWT (K8s SA token) |
| `VAULT_TOKEN` | Modo token estático |
| `VAULT_RENEW_ENABLED` | `true`/`false` (default `true` ao usar `start_auto_renew`) |
| `VAULT_RENEW_MARGIN` | Fração do lease para renovar (default `0.66`) |
| `VAULT_RENEW_MIN_SECONDS` | Intervalo mínimo (default `30`) |
| `VAULT_RENEW_MAX_SECONDS` | Intervalo máximo (default `3600`) |
| `VAULT_LEASE_DURATION` | Lease inicial se não informado no login (default `3600`) |

## Renovação automática

```python
from credential_proxy import (
    CredentialProxy,
    VaultSecretLoader,
    start_auto_renew,
)
from audit import AuditLogger

audit = AuditLogger()
proxy = CredentialProxy(audit_logger=audit)

loader = VaultSecretLoader.from_oidc(
    proxy,
    role="ventura-seg",
    jwt_path="/var/run/secrets/oidc/token",
    auth_path="jwt",
    audit_logger=audit,
)

# Inicia thread daemon: renew-self → se falhar, reauth OIDC com JWT re-lido do arquivo
renewer = start_auto_renew(
    loader,
    lease_duration=3600,  # ou o lease retornado pelo Vault
    jwt_path="/var/run/secrets/oidc/token",
    audit_logger=audit,
)

print(renewer.status())
# RenewStatus(running=True, renew_count=..., method_last_used="token_renew"|"oidc_reauth")

# No shutdown:
renewer.stop()
```

### Ordem de renovação

1. **`auth/token/renew-self`** — se o client token for renovável
2. **Reauth OIDC/JWT** — lê JWT fresco de:
   - `jwt_provider()` (callback),
   - ou `VAULT_OIDC_JWT_PATH` / `jwt_path` (arquivo),
   - ou `VAULT_OIDC_JWT`

### Callback de JWT (IdP)

```python
def meu_idp() -> str:
    # obter JWT fresco do seu Identity Provider
    return fetch_jwt_from_idp()

renewer = start_auto_renew(loader, jwt_provider=meu_idp, audit_logger=audit)
```

## Uso básico (sem auto-renew)

```python
loader = VaultSecretLoader.from_env(proxy, audit_logger=audit)
loader.load_kv(
    mount="secret",
    path="agents/github",
    key="token",
    handle_name="github_token",
    allowed_domains=["api.github.com"],
)
```

## Segurança

- JWT e client token **nunca** são gravados nos logs.
- Preferir JWT de curta duração + auto-renew.
- Handles continuam com allowlist de domínios.
- `SecretsMonitor` alerta se `vault_authenticated` for `False`.
