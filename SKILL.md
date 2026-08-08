# SKILL — Ventura.SEG

> LOOP Skill Engine / Constrained Replay

## Identidade

| Campo | Valor |
|-------|-------|
| Nome | Ventura.SEG |
| Tipo | Camada de segurança para agentes de IA |
| Loop | Observar → Detectar → Validar → Corrigir → Verificar → Aprender |
| Fail mode | Fail-secure (bloquear na dúvida) |

## Capacidades

- Motor de permissões YAML (allow / block / ask)
- DLP de saída
- Gateway de entrada para detecção e mitigação de prompt injection
- Proxy de credenciais + HashiCorp Vault (OIDC/JWT + auto-renew)
- Sandbox (process / Docker)
- Consul Service Mesh (intentions + upstreams)
- Auditoria JSONL append-only durante a escrita; integridade criptográfica/WORM requer camada adicional

## Entradas

- Comandos shell, conteúdo externo, destinos de rede, handles de credencial

## Saídas

- Decisões auditáveis, logs, bloqueios, redações, handles opacos

## Restrições

- Nunca expor segredos ao modelo/agente
- Políticas versionadas; regras críticas devem permanecer fora de prompts livres
- Zero trust entre agentes
- Não tratar saída de LLM como determinística sem controle explícito do runtime
