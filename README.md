# Ventura.SEG

**Camada de Segurança Full-time e Regenerativa para Sistemas Multi-Agentes de IA**

Ventura.SEG é uma infraestrutura de proteção que atua como **guardião permanente** do tráfego de entrada e saída de agentes de IA. Ele intercepta, valida, registra e bloqueia ações perigosas, protegendo dados sensíveis de todos os agentes do sistema.

> Desenvolvido por **Ventura Autor** (Wemerson Mota de Oliveira)

---

## 🛡️ Visão

Em sistemas multi-agentes, a maior superfície de ataque não é o modelo em si, mas o que entra e sai dele. Ventura.SEG implementa **defesa em profundidade** com:

- Gateway de entrada (nunca confiar em conteúdo externo)
- Motor de permissões (privilégio mínimo)
- Sandbox de execução real
- Proxy de credenciais (segredos nunca expostos ao modelo)
- Gateway de saída / DLP
- Auditoria imutável
- Capacidade regenerativa (self-healing)

---

## ✅ Status de Implementação

| Módulo | Status | Descrição |
|--------|--------|-----------|
| **Motor de Permissões** | ✅ Implementado | YAML + hot-reload + logs |
| **Sistema de Auditoria** | ✅ Implementado | Logs estruturados JSONL imutáveis |
| Gateway de Entrada | 🔳 Scaffold | Sanitização de conteúdo externo |
| Gateway de Saída (DLP) | 🔳 Scaffold | Validação de saída e exfiltração |
| Proxy de Credenciais | 🔳 Scaffold | Segredos fora do perímetro |
| Sandbox | 🔳 Scaffold | Isolamento real de execução |

---

## 🚀 Quickstart (Motor de Permissões)

```bash
pip install -r requirements.txt
```

```python
from permissions import PermissionEngine, Action
from audit import AuditLogger

# Inicializa auditoria + motor
audit = AuditLogger(log_dir="logs/audit")
engine = PermissionEngine.from_policy_dir("policies/", audit_logger=audit)

# Avalia comandos
decision = engine.evaluate_command("rm -rf /")
print(decision.action)        # Action.BLOCK
print(decision.reason)        # rm -rf e variantes destrutivas

# Hot-reload dinâmico (sem reiniciar)
engine.reload()
```

---

## 📁 Estrutura do Repositório

```
Ventura.SEG/
├── README.md
├── LICENSE                 # Apache License 2.0
├── SECURITY.md
├── THREAT_MODEL.md
├── requirements.txt
├── docs/
│   └── architecture.md
├── src/
│   ├── permissions/       # ✅ Motor completo
│   ├── audit/             # ✅ Logger imutável
│   ├── gateway_in/        # Scaffold
│   ├── gateway_out/       # Scaffold
│   ├── credential_proxy/  # Scaffold
│   └── sandbox/           # Scaffold
├── policies/
│   ├── allowlist_commands.yaml
│   ├── allowlist_domains.yaml
│   └── dlp_rules.yaml
└── tests/
    └── test_permission_engine.py
```

---

## 🛡️ Modelo de Ameaça Coberto

- Injeção de prompt indireta
- Exfiltração de dados
- Escalonamento de privilégio
- Abuso de credenciais
- Erros destrutivos do modelo

---

## 📝 Licença

**Apache License 2.0** — licença open-source real e válida.

> Certificações organizacionais (SOC 2, ISO 27001, LGPD etc.) não são atribuídas a repositórios de código.

---

**Ventura Autor**  
Segurança de agentes como infraestrutura, não como afterthought.
