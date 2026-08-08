---
name: anomaly-triage
description: Triage suspicious Ventura.SEG events across audit gateway credential and sandbox evidence. Use when investigating anomalous agent behavior or security alerts. Do not use when authoring normal policies without an incident signal.
---

# Anomaly triage

- Collect the smallest relevant time window from audit and component outputs.
- Separate observed facts from hypotheses.
- Correlate permission decisions DLP findings input sanitization credential events and sandbox results.
- Identify the first control that detected or should have detected the behavior.
- Classify impact as contained attempted or confirmed using repository evidence only.
- Preserve logs and avoid destructive cleanup before evidence capture.
- Add a regression test for any reproducible control gap.
- Recommend the narrowest policy code or deployment change that closes the gap.
