# Model Card — Ventura.SEG

## Tipo de sistema

**Control-plane de seguranca** para agentes de IA. Nao treina nem hospeda um foundation model proprio.

## Modelos externos

Qualquer LLM fica **fora** do SEG. O SEG intercepta entradas/saidas, aplica politicas YAML, DLP, proxy de credenciais e isolamento.

## Dados sensiveis

- Segredos nunca devem chegar ao contexto do modelo (credential proxy)
- Auditoria JSONL append-only (ver limites no THREAT_MODEL.md)

## Limitacoes

- Nao substitui WAF, EDR ou IAM corporativo
- Politicas mal escritas podem bloquear demais ou de menos
- Integridade forte de audit log exige backend WORM/HMAC (roadmap)

## Uso pretendido

Camada full-time ao redor de agentes (Claude, Copilot, agentes Ventura, etc.).
