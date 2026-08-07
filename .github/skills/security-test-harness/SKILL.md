---
name: security-test-harness
description: Add adversarial regression tests for Ventura.SEG security controls using safe synthetic fixtures. Use when a control changes or a security bypass is discovered. Do not use when writing unrelated feature tests or performing live offensive testing.
---

# Security test harness

- Identify the exact control and failure mode before adding cases.
- Reuse the existing pytest structure and public component interfaces.
- Use synthetic secrets commands payloads and destinations only.
- Cover expected block allow ask sanitize or isolation behavior as applicable.
- Add negative controls so the test detects excessive false positives.
- Keep tests deterministic and independent from production services.
- Run the focused test first then `pytest tests/ -v`.
- Record the regression intent in the test name or nearby comment without exposing real sensitive data.
