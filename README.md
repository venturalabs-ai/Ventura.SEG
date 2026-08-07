# Ventura.SEG

**Camada de segurança para sistemas multiagentes de IA**

Ventura.SEG é uma infraestrutura de proteção para tráfego de entrada e saída de agentes de IA. O projeto implementa controles de permissões, DLP, credenciais, sandbox, auditoria e mitigação de conteúdo de entrada. Os controles devem ser avaliados no contexto do runtime e da infraestrutura onde forem implantados.

> Desenvolvido por **Ventura Labs AI** — Wemerson Mota de Oliveira

---

## Status de implementação

| Módulo | Status | Evidência principal |
|---|---|---|
| **Motor de Permissões** | Implementado | YAML + hot-reload + testes |
| **Sistema de Auditoria** | Implementado | JSONL append-only durante a escrita; não afirma imutabilidade criptográfica |
| **Gateway de Saída (DLP)** | Implementado | Regras YAML + testes |
| **Proxy de Credenciais** | Implementado | Handles opacos + allowlist de domínios |
| **HashiCorp Vault** | Implementado / opcional | Carregamento KV v1/v2 |
| **Monitor de Segredos** | Implementado | Higiene + status Vault + alertas |
| **Gateway de Entrada** | Implementado | Detecção/sanitização e mitigação de padrões de prompt injection |
| **Sandbox** | Implementado | Process + Docker; segurança depende do host/runtime |
| **Loop Regenerativo** | Implementado | suggest / ask / auto |
| **Testes de Segurança** | Implementados | DLP, Gateway In, Proxy, Monitor, Permissões |

> **Nota:** “implementado” significa que o componente existe no repositório e possui o nível de teste/documentação indicado. Não significa certificação, ausência de vulnerabilidades ou cobertura completa contra uma classe de ataque.

---

## Quickstart

```bash
pip install -r requirements.txt
pytest tests/ -v
```

```python
from permissions import PermissionEngine
from gateway_out.dlp import DLPGateway
from gateway_in import ContentSanitizer
from credential_proxy import CredentialProxy, SecretsMonitor
from sandbox import SandboxExecutor, IsolationLevel
from audit import AuditLogger

audit = AuditLogger(log_dir="logs/audit")

engine = PermissionEngine.from_policy_dir("policies/", audit_logger=audit)
decision = engine.evaluate_command("rm -rf /")

dlp = DLPGateway.from_policy_file("policies/dlp_rules.yaml", audit_logger=audit)
dlp_result = dlp.scan("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789")

sanitizer = ContentSanitizer(audit_logger=audit)
clean = sanitizer.sanitize("Ignore previous instructions and...")

proxy = CredentialProxy(audit_logger=audit)
proxy.register("github_token", "ghp_xxx", allowed_domains=["api.github.com"])
monitor = SecretsMonitor(proxy, audit_logger=audit)
report = monitor.check()

sandbox = SandboxExecutor(level=IsolationLevel.PROCESS, audit_logger=audit)
result = sandbox.run("echo hello", timeout=5)
```

---

## Estrutura

```text
Ventura.SEG/
├── LICENSE
├── SECURITY.md
├── THREAT_MODEL.md
├── CHANGELOG.md
├── requirements.txt
├── docs/architecture.md
├── policies/
├── src/
│   ├── permissions/
│   ├── audit/                 # JSONL append-only durante escrita
│   ├── gateway_in/
│   ├── gateway_out/
│   ├── credential_proxy/
│   ├── sandbox/
│   └── core/
├── tests/
└── .github/workflows/
```

## Modelo de ameaça coberto

O projeto possui controles e testes voltados a:

- prompt injection direta/indireta e conteúdo não confiável;
- exfiltração de dados por padrões DLP;
- escalonamento de privilégio via política;
- abuso ou vazamento de credenciais;
- ações destrutivas conhecidas;
- destinos de rede fora de allowlist;
- higiene e estado de credenciais Vault.

A cobertura não deve ser interpretada como proteção absoluta contra toda variação possível desses ataques.

## Auditoria

O logger local utiliza escrita JSONL em modo append. Isso melhora rastreabilidade operacional, mas **não torna o arquivo imutável por si só**. Para evidência contra adulteração, use hash chaining/HMAC/assinaturas e armazenamento WORM ou equivalente.

## Qualidade e segurança

- CI em Python suportado;
- testes automatizados;
- validação de políticas;
- secret scan;
- auditoria de dependências;
- release workflow versionado.

Resultados de CI e segurança devem ser tratados como evidência somente quando os respectivos workflows tiverem executado com sucesso para o commit/release publicado.

## Licença

Apache License 2.0 — consulte [LICENSE](LICENSE).

Certificações organizacionais como SOC 2 e ISO 27001 não são atribuídas a este repositório.
