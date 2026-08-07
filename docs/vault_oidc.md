# Vault + OIDC — Ventura.SEG

## Visão

O `VaultSecretLoader` autentica no HashiCorp Vault **sem** entregar um token de longa duração ao agente. Com OIDC/JWT:

1. O Identity Provider (Okta, Azure AD, Keycloak, Google, etc.) emite um JWT.
2. O Ventura.SEG envia esse JWT ao Vault (`auth/oidc` ou `auth/jwt`).
3. O Vault valida o JWT e devolve um **client token** de curta duração.
4. Esse token fica só no proxy — o agente nunca o vê.
5. Segredos são lidos e registrados como handles opacos (`cred:...`).

## Variáveis de ambiente

| Variável | Descrição |
|----------|-----------|
| `VAULT_ADDR` | URL do Vault |
| `VAULT_AUTH_METHOD` | `token` \| `oidc` \| `jwt` |
| `VAULT_OIDC_ROLE` | Role configurada no auth method |
| `VAULT_OIDC_PATH` | Mount path (default: `oidc` ou `jwt`) |
| `VAULT_OIDC_JWT` | JWT em texto |
| `VAULT_OIDC_JWT_PATH` | Arquivo com JWT (ex: SA token no Kubernetes) |
| `VAULT_TOKEN` | Só no modo `token` |

## Uso rápido

```python
from credential_proxy import CredentialProxy, VaultSecretLoader, SecretsMonitor
from audit import AuditLogger

audit = AuditLogger()
proxy = CredentialProxy(audit_logger=audit)

# Opção A — explícito
loader = VaultSecretLoader.from_oidc(
    proxy,
    role="ventura-seg",
    jwt=open("/var/run/secrets/oidc/token").read().strip(),
    auth_path="oidc",
    audit_logger=audit,
)

# Opção B — via ambiente (VAULT_AUTH_METHOD=oidc)
loader = VaultSecretLoader.from_env(proxy, audit_logger=audit)

loader.load_kv(
    mount="secret",
    path="agents/github",
    key="token",
    handle_name="github_token",
    allowed_domains=["api.github.com"],
)

# Monitor também verifica se a sessão Vault continua válida
monitor = SecretsMonitor(proxy, vault_loader=loader, audit_logger=audit)
print(monitor.check().vault_authenticated)
```

## Renovação de sessão

```python
# Quando o lease estiver perto de expirar, obtenha um novo JWT do IdP
ok = loader.reauthenticate_oidc(jwt=novo_jwt)
```

## Configuração no Vault (referência)

```bash
# Habilitar auth OIDC
vault auth enable oidc

# Exemplo de role (ajuste bound_audiences, policies, oidc_discovery_url)
vault write auth/oidc/role/ventura-seg \\
  user_claim="sub" \\
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \\
  policies="ventura-seg-read" \\
  ttl="1h"
```

Para workloads (Kubernetes / CI), o auth method **JWT** costuma ser mais adequado que o fluxo browser OIDC:

```bash
vault auth enable jwt
vault write auth/jwt/config \\
  bound_issuer="https://seu-idp/.well-known/openid-configuration" \\
  oidc_discovery_url="https://seu-idp"
```

## Segurança

- JWT e client token **nunca** são gravados nos logs de auditoria.
- Preferir JWT de curta duração + `reauthenticate_oidc`.
- Handles continuam sujeitos a allowlist de domínios no `CredentialProxy`.
- `SecretsMonitor` alerta se `vault_authenticated` for `False`.
