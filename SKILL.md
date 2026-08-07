# SKILL — Ventura.SEG

> LOOP Skill Engine / Deterministic Replay

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
- Gateway de entrada (anti prompt-injection)
- Proxy de credenciais + HashiCorp Vault (OIDC/JWT + auto-renew)
- Sandbox (process / Docker)
- Consul Service Mesh (intentions + upstreams)
- Auditoria imutável JSONL

## Entradas

- Comandos shell, conteúdo externo, destinos de rede, handles de credencial

## Saídas

- Decisões auditáveis, logs, bloqueios, redações, handles opacos

## Restrições

- Nunca expor segredos ao modelo/agente
- Políticas 100% versionadas (sem hardcode de regras críticas)
- Zero trust entre agentes
