---
name: vault-oidc-setup
description: Configure Ventura.SEG Vault-backed credential loading without embedding secrets in code. Use when enabling or changing Vault authentication and KV access. Do not use when credentials remain local handles without Vault.
---

# Vault setup

- Inspect the existing credential proxy and Vault integration before changing configuration.
- Preserve supported KV v1 or v2 behavior.
- Keep tokens client secrets and credentials outside the repository.
- Prefer short-lived identity-based authentication when the deployment supports it.
- Restrict Vault policies to the exact secret paths required by the agent.
- Verify renewal or reauthentication behavior for expiring credentials.
- Add tests with mocks or disposable fixtures and never real secrets.
- Run credential and secrets-monitor tests followed by the full test suite.
- Do not claim OIDC support unless the current implementation or deployment configuration actually provides it.
