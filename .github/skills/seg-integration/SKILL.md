---
name: seg-integration
description: Integrate an external Ventura agent with existing Ventura.SEG permission DLP credential audit and sandbox controls. Use when another repository must adopt SEG protections. Do not use when changing SEG internals without an integration target.
---

# SEG integration

- Identify the target agent entry points outbound calls credentials and executable actions.
- Map each risk surface to an existing Ventura.SEG component before writing adapters.
- Use public imports and configuration already documented by this repository.
- Start with permission checks audit logging and outbound DLP at the narrowest integration boundary.
- Add credential proxy and sandbox controls only where the target actually performs those operations.
- Keep target-specific glue outside core security primitives unless reuse is proven.
- Add an integration test that proves both an allowed path and a blocked risky path.
- Run Ventura.SEG tests and the target repository tests before declaring the integration complete.
