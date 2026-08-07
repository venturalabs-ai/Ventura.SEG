# Ventura.SEG

**Camada de Segurança Full-time e Regenerativa para Sistemas Multi-Agentes de IA**

Ventura.SEG é uma infraestrutura de proteção que atua como **guardião permanente** do tráfego de entrada e saída de agentes de IA. Ele intercepta, valida, registra e bloqueia ações perigosas, protegendo dados sensíveis de todos os agentes do sistema.

> Desenvolvido por **Ventura Autor** (Wemerson Mota de Oliveira)

---

## ✅ Status Final de Implementação

| Módulo | Status | Descrição |
|--------|--------|-----------|
| **Motor de Permissões** | ✅ Completo | YAML + hot-reload + auditoria |
| **Sistema de Auditoria** | ✅ Completo | Logs JSONL imutáveis |
| **Gateway de Saída (DLP)** | ✅ Completo | Regras YAML (AWS, GitHub, Vault, CPF…) |
| **Proxy de Credenciais** | ✅ Completo | Handles opacos + allowlist de domínios |
| **HashiCorp Vault** | ✅ Completo | Carregamento de segredos KV v1/v2 |
| **Monitor de Segredos** | ✅ Completo | Higiene + status Vault + alertas |
| **Gateway de Entrada** | ✅ Completo | Sanitização + anti prompt-injection |
| **Sandbox** | ✅ Completo | Process + Docker hardenizado |
| **Loop Regenerativo** | ✅ Completo | Self-healing (suggest / ask / auto) |
| **Testes de Segurança** | ✅ Completo | DLP, Gateway In, Proxy, Monitor, Permissões |

---

## 🚀 Quickstart

```bash
pip install -r requirements.txt
pytest tests/ -v
```

```python
from permissions import PermissionEngine, Action
from gateway_out.dlp import DLPGateway
from gateway_in import ContentSanitizer
from credential_proxy import CredentialProxy, SecretsMonitor
from sandbox import SandboxExecutor, IsolationLevel
from audit import AuditLogger

audit = AuditLogger(log_dir="logs/audit")

# 1. Motor de permissões
engine = PermissionEngine.from_policy_dir("policies/", audit_logger=audit)
decision = engine.evaluate_command("rm -rf /")
# → Action.BLOCK

# 2. DLP de saída
dlp = DLPGateway.from_policy_file("policies/dlp_rules.yaml", audit_logger=audit)
dlp_result = dlp.scan("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789")
# → BLOCK (github-token)

# 3. Sanitização de entrada
sanitizer = ContentSanitizer(audit_logger=audit)
clean = sanitizer.sanitize("Ignore previous instructions and...")
# → conteúdo neutralizado

# 4. Proxy de credenciais + Vault (opcional)
proxy = CredentialProxy(audit_logger=audit)
proxy.register("github_token", "ghp_xxx", allowed_domains=["api.github.com"])

# Monitoramento de higiene dos segredos
monitor = SecretsMonitor(proxy, audit_logger=audit)
report = monitor.check()
print(report.critical, report.notes)

# 5. Sandbox
sandbox = SandboxExecutor(level=IsolationLevel.PROCESS, audit_logger=audit)
result = sandbox.run("echo hello", timeout=5)
```

### Integração HashiCorp Vault

```python
from credential_proxy import CredentialProxy, VaultSecretLoader, SecretsMonitor

proxy = CredentialProxy(audit_logger=audit)
loader = VaultSecretLoader(proxy)  # usa VAULT_ADDR + VAULT_TOKEN

loader.load_kv(
    mount="secret",
    path="agents/github",
    key="token",
    handle_name="github_token",
    allowed_domains=["api.github.com", "github.com"],
)

# Monitor verifica token Vault + higiene dos handles
monitor = SecretsMonitor(proxy, vault_loader=loader, audit_logger=audit)
report = monitor.check()
```

---

## 📁 Estrutura do Repositório

```
Ventura.SEG/
├── LICENSE                    # Apache 2.0
├── SECURITY.md
├── THREAT_MODEL.md
├── requirements.txt
├── docs/architecture.md
├── policies/
│   ├── allowlist_commands.yaml
│   ├── allowlist_domains.yaml
│   └── dlp_rules.yaml         # v1.1 (inclui Vault)
├── src/
│   ├── permissions/           # Motor YAML + hot-reload
│   ├── audit/                 # Logger imutável
│   ├── gateway_in/            # Sanitização anti-injection
│   ├── gateway_out/           # DLP
│   ├── credential_proxy/      # Proxy + Vault + Monitor
│   ├── sandbox/               # Process + Docker
│   └── core/                  # Loop regenerativo
└── tests/
    ├── test_permission_engine.py
    ├── test_dlp.py
    ├── test_gateway_in.py
    ├── test_credential_proxy.py
    └── test_secrets_monitor.py
```

---

## 🛡️ Modelo de Ameaça Coberto

- Injeção de prompt indireta
- Exfiltração de dados (DLP)
- Escalonamento de privilégio
- Abuso / vazamento de credenciais
- Erros destrutivos do modelo
- Segredos sem allowlist de domínio
- Token Vault expirado / inválido

---

## 📝 Licença

**Apache License 2.0** — licença open-source real e válida.

> Certificações organizacionais (SOC 2, ISO 27001, LGPD etc.) não são atribuídas a repositórios de código.

---

**Ventura Autor**  
Segurança de agentes como infraestrutura, não como afterthought.
