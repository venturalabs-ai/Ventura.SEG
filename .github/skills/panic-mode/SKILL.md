---
name: panic-mode
description: Contain a suspected compromised agent by reducing privileges and isolating execution through existing Ventura.SEG controls. Use when active behavior may cause data loss credential abuse or destructive actions. Do not use when handling ordinary debugging or low-risk configuration changes.
---

# Panic mode

- Preserve evidence before modifying runtime state when safe to do so.
- Deny destructive or external actions through the existing permission layer.
- Revoke or disable exposed credential handles and restrict allowed destinations.
- Move suspicious execution to the strongest isolation level already supported by the deployment.
- Keep outbound DLP and input sanitization enabled during containment.
- Record every containment action through the existing audit path.
- Verify the suspect action can no longer complete.
- Run relevant security regression tests before restoring privileges.
- Restore capabilities incrementally and only from explicit evidence.
