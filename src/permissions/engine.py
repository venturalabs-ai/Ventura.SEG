"""
Ventura.SEG — Motor de Permissões
=================================
Motor de decisão allow / block / ask baseado em políticas YAML versionadas.
Fail-secure por padrão. Usa matching por regex (com preparação para AST futuro).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


@dataclass(frozen=True)
class PermissionDecision:
    """Resultado imutável de uma avaliação de permissão."""
    action: Action
    rule_id: Optional[str]
    reason: str
    matched_pattern: Optional[str] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action == Action.ALLOW

    @property
    def requires_human(self) -> bool:
        return self.action == Action.ASK

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "matched_pattern": self.matched_pattern,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class Rule:
    id: str
    pattern: str
    action: Action
    description: str = ""
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern, re.IGNORECASE)


class PermissionEngine:
    """
    Motor de permissões orientado a políticas YAML.

    Uso típico:
        engine = PermissionEngine.from_policy_dir("policies/")
        decision = engine.evaluate_command("rm -rf /")
        if decision.action == Action.BLOCK:
            ...
    """

    def __init__(
        self,
        command_rules: list[Rule],
        default_action: Action = Action.BLOCK,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
    ) -> None:
        self.command_rules = command_rules
        self.default_action = default_action
        self.allowed_domains = set(d.lower() for d in (allowed_domains or []))
        self.blocked_domains = set(d.lower() for d in (blocked_domains or []))

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_policy_dir(cls, policy_dir: str | Path) -> "PermissionEngine":
        """Carrega políticas a partir de um diretório de arquivos YAML."""
        policy_dir = Path(policy_dir)

        commands_path = policy_dir / "allowlist_commands.yaml"
        domains_path = policy_dir / "allowlist_domains.yaml"

        command_rules: list[Rule] = []
        default_action = Action.BLOCK

        if commands_path.exists():
            with open(commands_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            default_action = Action(data.get("default_action", "block"))
            for raw in data.get("rules", []):
                command_rules.append(
                    Rule(
                        id=raw["id"],
                        pattern=raw["pattern"],
                        action=Action(raw["action"]),
                        description=raw.get("description", ""),
                    )
                )

        allowed_domains: list[str] = []
        blocked_domains: list[str] = []

        if domains_path.exists():
            with open(domains_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            allowed_domains = data.get("allowed_domains", [])
            blocked_domains = data.get("blocked_domains", [])

        return cls(
            command_rules=command_rules,
            default_action=default_action,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
        )

    # ------------------------------------------------------------------
    # Avaliação de comandos
    # ------------------------------------------------------------------

    def evaluate_command(self, command: str) -> PermissionDecision:
        """
        Avalia um comando shell contra as regras carregadas.
        A primeira regra que der match vence (ordem de prioridade do YAML).
        """
        command = command.strip()
        if not command:
            return PermissionDecision(
                action=Action.BLOCK,
                rule_id=None,
                reason="Comando vazio",
            )

        for rule in self.command_rules:
            if rule.compiled.search(command):
                return PermissionDecision(
                    action=rule.action,
                    rule_id=rule.id,
                    reason=rule.description or f"Matched rule '{rule.id}'",
                    matched_pattern=rule.pattern,
                    confidence=1.0,
                )

        # Nenhuma regra bateu → aplica default (fail-secure)
        return PermissionDecision(
            action=self.default_action,
            rule_id=None,
            reason=f"Nenhuma regra correspondente. Aplicando default_action={self.default_action.value}",
            confidence=0.9,
        )

    # ------------------------------------------------------------------
    # Avaliação de domínios / rede
    # ------------------------------------------------------------------

    def evaluate_domain(self, domain: str) -> PermissionDecision:
        """Verifica se um domínio é permitido para saída de rede."""
        domain = domain.lower().strip()

        if domain in self.blocked_domains:
            return PermissionDecision(
                action=Action.BLOCK,
                rule_id="blocked_domain",
                reason=f"Domínio explicitamente bloqueado: {domain}",
            )

        if domain in self.allowed_domains:
            return PermissionDecision(
                action=Action.ALLOW,
                rule_id="allowed_domain",
                reason=f"Domínio na allowlist: {domain}",
            )

        # Suporte simples a subdomínios (ex: api.github.com quando github.com está permitido)
        for allowed in self.allowed_domains:
            if domain.endswith("." + allowed) or domain == allowed:
                return PermissionDecision(
                    action=Action.ALLOW,
                    rule_id="allowed_domain_sub",
                    reason=f"Subdomínio de allowlist ({allowed}): {domain}",
                )

        return PermissionDecision(
            action=Action.BLOCK,
            rule_id=None,
            reason=f"Domínio não está na allowlist: {domain}",
        )

    # ------------------------------------------------------------------
    # Utilitários
    # ------------------------------------------------------------------

    def reload(self, policy_dir: str | Path) -> None:
        """Recarrega as políticas em runtime (hot-reload)."""
        new_engine = PermissionEngine.from_policy_dir(policy_dir)
        self.command_rules = new_engine.command_rules
        self.default_action = new_engine.default_action
        self.allowed_domains = new_engine.allowed_domains
        self.blocked_domains = new_engine.blocked_domains
