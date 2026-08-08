# VEB Status — Ventura.SEG

**Nota alvo: A** | Tier C | Baseline VEB-1

| Criterio | Status |
|----------|--------|
| CI | ✅ matrix 3.11/3.12, coverage gate, bandit |
| Testes | ✅ pytest + test_health |
| Docker | ✅ Dockerfile + compose + HEALTHCHECK |
| Secret scanning | ✅ job secrets-scan + security.yml |
| SAST/SCA | ✅ bandit + pip-audit |
| Threat model | ✅ THREAT_MODEL.md |
| Observabilidade | ✅ core.health |
| SLOs | ✅ docs/SLO.md |
| Releases | ✅ release.yml + VERSION |
| SBOM | ✅ sbom job CI |
| ADR | ✅ docs/adr/0001-zero-trust-gateways.md |
| Model card | ✅ docs/MODEL_CARD.md (control-plane) |
| GPU | ✅ N/A documentado |
| SECURITY.md | ✅ |

**Achados criticos:** 0 abertos no baseline atual.

Atualizado: 2026-08-07
