# Changelog

Todas as mudanças relevantes deste projeto são documentadas aqui.

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [2.0.0] — 2026-08-07

### Added
- CI GitHub Actions (pytest)
- Dependabot, issue/PR templates
- CONTRIBUTING, CODE_OF_CONDUCT, SKILL.md
- Vault OIDC/JWT + renovação automática
- Consul Service Mesh, intentions e upstreams
- Gateway de entrada, sandbox, DLP expandido
- Testes de segurança (permissions, DLP, proxy, monitor, mesh)

### Security
- Default-deny em intentions e permissões
- Segredos nunca expostos ao agente

## [0.1.0] — 2026-08-07

### Added
- Bootstrap do repositório, Apache 2.0, motor de permissões e auditoria
