# SLOs — Ventura.SEG

| Indicador | Alvo (v0.1) | Medicao |
|-----------|-------------|---------|
| Disponibilidade do control-plane | 99.5% mensal (single node) | healthcheck container/K8s |
| Latencia p95 decisao de politica (allow/block) | < 50 ms em memoria | testes de microbenchmark |
| Latencia p95 DLP scan (payload < 64 KB) | < 100 ms | testes |
| Taxa de falso positivo critico em DLP | monitorada; baseline em release notes | suite adversarial |
| Falha segura (fail-secure) | 100% dos caminhos de erro default block | testes de politica |
| Vazamento de secret em log/auditoria | 0 | gitleaks + review de audit JSONL |
| Renovacao de lease Vault | sucesso >= 99% quando configurado | metricas do auto_renew |

Error budget: 0.5% indisponibilidade/mes no no de controle.

Fora de escopo v0.1: multi-regiao ativo-ativo.
