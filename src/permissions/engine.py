"""
Ventura.SEG — Motor de Permissões
=================================
Motor de decisão allow / block / ask baseado em políticas YAML versionadas.

Características:
- Fail-secure por padrão (default_action = block)
- Hot-reload dinâmico de políticas sem reiniciar o processo
- Integração nativa com o sistema de auditoria (logs imutáveis)
- Matching por regex (preparado para evolução com parser AST)
- Decisões imutáveis e auditáveis
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

# Import opcional do logger de auditoria (evita circularidade em bootstrap)
try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


class Action(str, Enum):
    """Ações possíveis do motor de permissões."""
    ALLOW = "allow"   # Permitido automaticamente
    BLOCK = "block"   # Bloqueado automaticamente
    ASK = "ask"       # Requer aprovação humana


@dataclass(frozen=True)
class PermissionDecision:
    """
    Resultado imutável de uma avaliação de permissão.
    Uma vez criado, não pode ser alterado (garante integridade da auditoria).
    """
    action: Action
    rule_id: Optional[str]
    reason: str
    matched_pattern: Optional[str] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Atalho: True se a ação foi ALLOW."""
        return self.action == Action.ALLOW

    @property
    def requires_human(self) -> bool:
        """Atalho: True se a ação exige aprovação humana."""
        return self.action == Action.ASK

    def to_dict(self) -> dict[str, Any]:
        """Serializa a decisão para logs / API."""
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
    """Regra individual carregada do YAML."""
    id: str
    pattern: str
    action: Action
    description: str = ""
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Compila a regex uma única vez (performance)
        self.compiled = re.compile(self.pattern, re.IGNORECASE)


class PermissionEngine:
    """
    Motor de permissões orientado a políticas YAML.

    Exemplo de uso:
        from permissions import PermissionEngine
        from audit.logger import AuditLogger

        audit = AuditLogger()
        engine = PermissionEngine.from_policy_dir("policies/", audit_logger=audit)

        decision = engine.evaluate_command("rm -rf /")
        if decision.action == Action.BLOCK:
            print("Bloqueado:", decision.reason)
    """

    def __init__(
        self,
        command_rules: list[Rule],
        default_action: Action = Action.BLOCK,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        audit_logger: Any = None,
        policy_dir: str | Path | None = None,
    ) -> None:
        self.command_rules = command_rules
        self.default_action = default_action
        self.allowed_domains = set(d.lower() for d in (allowed_domains or []))
        self.blocked_domains = set(d.lower() for d in (blocked_domains or []))
        self.audit = audit_logger
        self._policy_dir = Path(policy_dir) if policy_dir else None

    # ------------------------------------------------------------------
    # Factory — carrega políticas do disco
    # ------------------------------------------------------------------

    @classmethod
    def from_policy_dir(
        cls,
        policy_dir: str | Path,
        audit_logger: Any = None,
    ) -> "PermissionEngine":
        """
        Carrega todas as políticas YAML de um diretório.

        Arquivos esperados:
          - allowlist_commands.yaml
          - allowlist_domains.yaml
        """
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

        engine = cls(
            command_rules=command_rules,
            default_action=default_action,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            audit_logger=audit_logger,
            policy_dir=policy_dir,
        )

        if audit_logger:
            audit_logger.log_event(
                component="permissions",
                action="load_policies",
                decision="success",
                reason=f"Carregadas {len(command_rules)} regras de comando",
            )

        return engine

    # ------------------------------------------------------------------
    # Avaliação de comandos
    # ------------------------------------------------------------------

    def evaluate_command(self, command: str, actor: str = "agent") -> PermissionDecision:
        """
        Avalia um comando shell contra as regras carregadas.

        A primeira regra que der match vence (ordem de prioridade do YAML).
        Toda decisão é automaticamente registrada no audit logger (se configurado).
        """
        command = command.strip()
        if not command:
            decision = PermissionDecision(
                action=Action.BLOCK,
                rule_id=None,
                reason="Comando vazio",
            )
            self._audit_decision(command, decision, actor)
            return decision

        for rule in self.command_rules:
            if rule.compiled.search(command):
                decision = PermissionDecision(
                    action=rule.action,
                    rule_id=rule.id,
                    reason=rule.description or f"Matched rule '{rule.id}'",
                    matched_pattern=rule.pattern,
                    confidence=1.0,
                )
                self._audit_decision(command, decision, actor)
                return decision

        # Nenhuma regra correspondente → fail-secure
        decision = PermissionDecision(
            action=self.default_action,
            rule_id=None,
            reason=f"Nenhuma regra correspondente. Aplicando default_action={self.default_action.value}",
            confidence=0.9,
        )
        self._audit_decision(command, decision, actor)
        return decision

    # ------------------------------------------------------------------
    # Avaliação de domínios / rede
    # ------------------------------------------------------------------

    def evaluate_domain(self, domain: str, actor: str = "agent") -> PermissionDecision:
        """Verifica se um domínio é permitido para saída de rede."""
        domain = domain.lower().strip()

        if domain in self.blocked_domains:
            decision = PermissionDecision(
                action=Action.BLOCK,
                rule_id="blocked_domain",
                reason=f"Domínio explicitamente bloqueado: {domain}",
            )
            self._audit_decision(domain, decision, actor)
            return decision

        if domain in self.allowed_domains:
            decision = PermissionDecision(
                action=Action.ALLOW,
                rule_id="allowed_domain",
                reason=f"Domínio na allowlist: {domain}",
            )
            self._audit_decision(domain, decision, actor)
            return decision

        # Suporte a subdomínios
        for allowed in self.allowed_domains:
            if domain.endswith("." + allowed) or domain == allowed:
                decision = PermissionDecision(
                    action=Action.ALLOW,
                    rule_id="allowed_domain_sub",
                    reason=f"Subdomínio de allowlist ({allowed}): {domain}",
                )
                self._audit_decision(domain, decision, actor)
                return decision

        decision = PermissionDecision(
            action=Action.BLOCK,
            rule_id=None,
            reason=f"Domínio não está na allowlist: {domain}",
        )
        self._audit_decision(domain, decision, actor)
        return decision

    # ------------------------------------------------------------------
    # Hot-reload dinâmico
    # ------------------------------------------------------------------

    def reload(self, policy_dir: str | Path | None = None) -> bool:
        """
        Recarrega as políticas em runtime sem reiniciar o processo.

        Retorna True se o reload foi bem-sucedido.
        Em caso de erro, mantém as regras antigas (fail-safe) e registra o problema.
        """
        target_dir = Path(policy_dir) if policy_dir else self._policy_dir
        if target_dir is None:
            if self.audit:
                self.audit.log_reload("unknown", False, "Nenhum policy_dir configurado")
            return False

        try:
            new_engine = PermissionEngine.from_policy_dir(target_dir, audit_logger=None)

            # Substitui o estado apenas se o carregamento foi bem-sucedido
            self.command_rules = new_engine.command_rules
            self.default_action = new_engine.default_action
            self.allowed_domains = new_engine.allowed_domains
            self.blocked_domains = new_engine.blocked_domains
            self._policy_dir = target_dir

            if self.audit:
                self.audit.log_reload(
                    str(target_dir),
                    True,
                    f"{len(self.command_rules)} regras recarregadas",
                )
            return True

        except Exception as exc:
            # Mantém as regras antigas — nunca deixa o motor sem política
            if self.audit:
                self.audit.log_reload(str(target_dir), False, str(exc))
            return False

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _audit_decision(
        self,
        target: str,
        decision: PermissionDecision,
        actor: str,
    ) -> None:
        """Registra a decisão no sistema de auditoria (se disponível)."""
        if self.audit is None:
            return
        self.audit.log_permission(
            command_or_target=target,
            decision=decision.action.value,
            reason=decision.reason,
            rule_id=decision.rule_id,
            actor=actor,
            metadata=decision.metadata,
        )
