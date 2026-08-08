---
name: policy-yaml-author
description: Author and validate Ventura.SEG permission policies against the repository policy engine. Use when changing allow block or ask decisions in policies. Do not use when the task is DLP content scanning or credential handling.
---

# Policy YAML author

- Inspect `policies/` and the permission engine before editing.
- Preserve the existing policy schema and decision vocabulary.
- Add the smallest rule that expresses the requested allow block or ask behavior.
- Prefer specific command or action matches over broad wildcards.
- Keep default-deny behavior intact when the existing policy uses it.
- Add or update tests covering allowed denied and ask outcomes.
- Run the repository policy tests and then `pytest tests/ -v`.
- Reject any change that requires a field or decision unsupported by the current engine.
