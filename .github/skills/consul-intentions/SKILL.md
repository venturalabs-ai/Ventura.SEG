---
name: consul-intentions
description: Add or review Consul service-mesh intentions only when Consul is an explicit Ventura.SEG deployment dependency. Use when the task names an existing Consul deployment or integration. Do not use when Consul is absent from the target environment or repository contract.
---

# Consul intentions

- Confirm the target deployment actually uses Consul before changing anything.
- Inspect existing deployment files and service identities first.
- Stop and report not applicable when no Consul dependency or deployment contract exists.
- When present preserve default-deny and add only the minimum required service-to-service allow rules.
- Bind intentions to concrete service identities rather than broad wildcards.
- Document required upstream and downstream relationships using existing deployment names.
- Validate configuration with the repository or deployment tooling already in use.
- Add integration coverage when the repository contains a Consul test harness.
- Never invent Consul files service names or runtime endpoints.
