# ADR 0001 — Gateways de entrada/saida + politicas YAML

## Status

Aceito (2026-08-07)

## Contexto

Agentes de IA consomem conteudo nao confiavel e emitem acoes (rede, disco, tools).

## Decisao

- Gateway de entrada: sanitiza e triagem antes do contexto do modelo
- Gateway de saida: DLP + allowlist
- Motor de permissoes em YAML (allow/block/ask) com default **block**
- Credenciais via proxy (handles opacos), Vault OIDC opcional
- Consul intentions default-deny para mesh

## Consequencias

- (+) Fail-secure e auditavel
- (+) Politica como codigo
- (-) Operacao exige disciplina de versionar policies/
- (-) Performance depende de manter validacoes leves no hot path
