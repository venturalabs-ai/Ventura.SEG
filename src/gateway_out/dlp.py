"""
Ventura.SEG — Gateway de Saída (DLP)
=====================================
Data Loss Prevention policy gateway.

Valida conteúdo que tenta sair do agente (comandos, body de requisições,
escrita em arquivos) contra regras YAML de DLP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


class DLPAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"
    REDACT = "redact"


@dataclass(frozen=True)
class DLPDecision:
    """Resultado de uma avaliação DLP."""
    action: DLPAction
    rule_id: Optional[str]
    reason: str
    matched_content: Optional[str] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action == DLPAction.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "matched_content": self.matched_content,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class DLPRule:
    id: str
    pattern: str
    action: DLPAction
    description: str = ""
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern, re.IGNORECASE)


class DLPGateway:
    """Gateway de saída orientado por políticas DLP."""

    def __init__(
        self,
        rules: list[DLPRule],
        default_action: DLPAction = DLPAction.ALLOW,
        audit_logger: Any = None,
        policy_path: Path | None = None,
    ) -> None:
        self.rules = rules
        self.default_action = default_action
        self.audit = audit_logger
        self._policy_path = policy_path

    @classmethod
    def from_policy_file(
        cls,
        policy_path: str | Path,
        audit_logger: Any = None,
    ) -> "DLPGateway":
        path = Path(policy_path)
        rules: list[DLPRule] = []
        default_action = DLPAction.ALLOW

        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            default_action = DLPAction(data.get("default_action", "allow"))
            for raw in data.get("rules", []):
                rules.append(
                    DLPRule(
                        id=raw["id"],
                        pattern=raw["pattern"],
                        action=DLPAction(raw["action"]),
                        description=raw.get("description", ""),
                    )
                )

        gateway = cls(
            rules=rules,
            default_action=default_action,
            audit_logger=audit_logger,
            policy_path=path,
        )

        if audit_logger:
            audit_logger.log_event(
                component="gateway_out",
                action="load_dlp_rules",
                decision="success",
                reason=f"Carregadas {len(rules)} regras DLP",
            )
        return gateway

    def scan(self, content: str, actor: str = "agent", context: str = "output") -> DLPDecision:
        if not content or not content.strip():
            return DLPDecision(DLPAction.ALLOW, None, "Conteúdo vazio")

        for rule in self.rules:
            match = rule.compiled.search(content)
            if match:
                matched = match.group(0)
                redacted = matched[:4] + "***" + matched[-4:] if len(matched) > 8 else "***"
                decision = DLPDecision(
                    action=rule.action,
                    rule_id=rule.id,
                    reason=rule.description or f"DLP rule '{rule.id}' matched",
                    matched_content=redacted,
                    confidence=1.0,
                    metadata={"context": context},
                )
                self._audit(content, decision, actor)
                return decision

        decision = DLPDecision(
            action=self.default_action,
            rule_id=None,
            reason="Nenhuma regra DLP correspondente",
            confidence=0.85,
            metadata={"context": context},
        )
        self._audit(content, decision, actor)
        return decision

    def reload(self) -> bool:
        if self._policy_path is None:
            return False
        try:
            new = DLPGateway.from_policy_file(self._policy_path, audit_logger=None)
            self.rules = new.rules
            self.default_action = new.default_action
            if self.audit:
                self.audit.log_event(
                    component="gateway_out",
                    action="hot_reload_dlp",
                    decision="success",
                    reason=f"{len(self.rules)} regras DLP recarregadas",
                )
            return True
        except Exception as exc:
            if self.audit:
                self.audit.log_event(
                    component="gateway_out",
                    action="hot_reload_dlp",
                    decision="failed",
                    reason=str(exc),
                )
            return False

    def _audit(self, content: str, decision: DLPDecision, actor: str) -> None:
        if self.audit is None:
            return
        self.audit.log_event(
            component="gateway_out",
            action="dlp_scan",
            decision=decision.action.value,
            reason=decision.reason,
            metadata={
                "rule_id": decision.rule_id,
                "actor": actor,
                "matched": decision.matched_content,
            },
        )
