# Ventura.SEG

**Camada de Segurança Full-time e Regenerativa para Sistemas Multi-Agentes de IA**

Ventura.SEG é uma infraestrutura de proteção que atua como **guardião permanente** do tráfego de entrada e saída de agentes de IA. Ele intercepta, valida, registra e bloqueia ações perigosas, protegendo dados sensíveis de todos os agentes do sistema.

> Desenvolvido por **Ventura Autor** (Wemerson Mota de Oliveira)

---

## ✅ Status de Implementação

| Módulo | Status | Descrição |
|--------|--------|-----------|
| **Motor de Permissões** | ✅ Implementado | YAML + hot-reload + logs |
| **Sistema de Auditoria** | ✅ Implementado | Logs estruturados JSONL imutáveis |
| **Gateway de Saída (DLP)** | ✅ Implementado | DLP real com regras YAML |
| **Proxy de Credenciais** | ✅ Implementado | Segredos nunca expostos ao modelo |
| **Loop Regenerativo** | ✅ Implementado | Self-healing (suggest / ask / auto) |
| Gateway de Entrada | 🔳 Scaffold | Sanitização de conteúdo externo |
| Sandbox | 🔳 Scaffold | Isolamento real de execução |

---

## 🚀 Quickstart

```bash
pip install -r requirements.txt
```

```python
from permissions import PermissionEngine, Action
from gateway_out import DLPGateway
from credential_proxy import CredentialProxy
from core import RegenerativeLoop, HealingMode
from audit import AuditLogger

audit = AuditLogger(log_dir="logs/audit")

# Motor de permissões
engine = PermissionEngine.from_policy_dir("policies/", audit_logger=audit)

# DLP (Gateway de Saída)
dlp = DLPGateway.from_policy_file("policies/dlp_rules.yaml", audit_logger=audit)

# Proxy de credenciais (segredos fora do agente)
proxy = CredentialProxy(audit_logger=audit)
proxy.register("github_token", "ghp_xxx", allowed_domains=["api.github.com"])

# Loop regenerativo
loop = RegenerativeLoop(
    audit_logger=audit,
    permission_engine=engine,
    dlp_gateway=dlp,
    mode=HealingMode.AUTO,
)

# Exemplo de fluxo
decision = engine.evaluate_command("rm -rf /")
loop.observe(agent_id="agent-1", decision=decision.action.value, rule_id=decision.rule_id)

dlp_decision = dlp.scan("AKIAIOSFODNN7EXAMPLE")
if dlp_decision.blocked:
    print("DLP bloqueou:", dlp_decision.reason)

# Ciclo de self-healing
actions = loop.tick()
```

---

## 📁 Estrutura

```
Ventura.SEG/
├── src/
│   ├── permissions/        # ✅ Motor YAML + hot-reload
│   ├── audit/              # ✅ Logger imutável
│   ├── gateway_out/        # ✅ DLP real
│   ├── credential_proxy/   # ✅ Proxy de segredos
│   ├── core/               # ✅ Loop regenerativo
│   ├── gateway_in/         # Scaffold
│   └── sandbox/            # Scaffold
├── policies/
│   ├── allowlist_commands.yaml
│   ├── allowlist_domains.yaml
│   └── dlp_rules.yaml
├── docs/architecture.md
└── tests/
```

---

## 📝 Licença

**Apache License 2.0**

---

**Ventura Autor**  
Segurança de agentes como infraestrutura, não como afterthought.
