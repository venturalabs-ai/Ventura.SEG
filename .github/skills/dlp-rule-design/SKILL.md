---
name: dlp-rule-design
description: Design DLP rules for Ventura.SEG with explicit detection tests and bounded false positives. Use when adding or tuning outbound sensitive-data detection. Do not use when changing command permissions or sandbox isolation.
---

# DLP rule design

- Inspect `policies/dlp_rules.yaml` and `src/gateway_out/` before editing.
- Reuse the current rule schema and matcher capabilities.
- Define the exact sensitive pattern and expected action first.
- Minimize broad regexes that match ordinary text.
- Add positive negative and boundary test cases.
- Include representative masked examples rather than real secrets.
- Run focused DLP tests and then `pytest tests/ -v`.
- Reject unsupported matcher fields instead of inventing them.
