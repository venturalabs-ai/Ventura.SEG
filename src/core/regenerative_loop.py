"""
Ventura.SEG — Loop Regenerativo (Self-Healing)
==============================================
Ciclo contínuo de segurança:

    Observar → Detectar → Validar → Corrigir → Verificar → Aprender

Capaz de:
- Detectar anomalias (muitos bloqueios seguidos, padrões suspeitos)
- Isolar agentes suspeitos (modo pânico)
- Recarregar políticas automaticamente
- Operar em três modos: suggest | ask | auto
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Optional

try:
    from audit.logger import AuditLogger, AuditLevel
except ImportError:
    AuditLogger = None  # type: ignore
    AuditLevel = None  # type: ignore


class HealingMode(str, Enum):
    SUGGEST = "suggest"   # Apenas registra e sugere ação
    ASK = "ask"           # Solicita aprovação humana antes de agir
    AUTO = "auto"         # Aplica correção automaticamente


class AnomalyType(str, Enum):
    HIGH_BLOCK_RATE = "high_block_rate"
    REPEATED_VIOLATION = "repeated_violation"
    CREDENTIAL_ABUSE = "credential_abuse"
    POLICY_LOAD_FAILURE = "policy_load_failure"
    UNKNOWN = "unknown"


@dataclass
class Anomaly:
    type: AnomalyType
    description: str
    severity: float          # 0.0 – 1.0
    agent_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class HealingAction:
    anomaly: Anomaly
    action_taken: str
    success: bool
    details: str = ""


class RegenerativeLoop:
    """
    Loop de auto-recuperação e detecção de anomalias.

    Uso:
        loop = RegenerativeLoop(
            audit_logger=audit,
            permission_engine=engine,
            dlp_gateway=dlp,
            mode=HealingMode.AUTO,
        )

        # A cada decisão de segurança:
        loop.observe(agent_id="agent-1", decision="block", rule_id="destructive-rm")

        # Periodicamente:
        actions = loop.tick()
    """

    def __init__(
        self,
        audit_logger: Any = None,
        permission_engine: Any = None,
        dlp_gateway: Any = None,
        mode: HealingMode = HealingMode.SUGGEST,
        block_rate_threshold: float = 0.7,
        window_size: int = 50,
        repeated_threshold: int = 5,
    ) -> None:
        self.audit = audit_logger
        self.engine = permission_engine
        self.dlp = dlp_gateway
        self.mode = mode

        # Janela deslizante de decisões por agente
        self._history: dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=window_size))
        self._violation_count: dict[str, int] = defaultdict(int)
        self._isolated_agents: set[str] = set()

        self.block_rate_threshold = block_rate_threshold
        self.repeated_threshold = repeated_threshold
        self.window_size = window_size

        # Callbacks opcionais para integração externa
        self.on_isolate: Optional[Callable[[str], None]] = None
        self.on_suggest: Optional[Callable[[Anomaly], None]] = None

    # ------------------------------------------------------------------
    # Observação
    # ------------------------------------------------------------------

    def observe(
        self,
        agent_id: str,
        decision: str,
        rule_id: Optional[str] = None,
    ) -> None:
        """
        Registra uma decisão de segurança para análise posterior.

        decision: "allow" | "block" | "ask"
        """
        self._history[agent_id].append(decision)

        if decision == "block":
            self._violation_count[agent_id] += 1

        if self.audit:
            self.audit.log_event(
                component="regenerative_loop",
                action="observe",
                decision=decision,
                reason=f"agent={agent_id} rule={rule_id}",
                metadata={"agent_id": agent_id, "rule_id": rule_id},
            )

    # ------------------------------------------------------------------
    # Detecção + Correção (tick)
    # ------------------------------------------------------------------

    def tick(self) -> list[HealingAction]:
        """
        Executa um ciclo completo do loop regenerativo.

        Deve ser chamado periodicamente (ex: a cada N segundos ou a cada N eventos).
        """
        anomalies = self._detect()
        actions: list[HealingAction] = []

        for anomaly in anomalies:
            action = self._heal(anomaly)
            if action:
                actions.append(action)

        return actions

    def _detect(self) -> list[Anomaly]:
        """Detecta anomalias com base no histórico recente."""
        found: list[Anomaly] = []

        for agent_id, history in self._history.items():
            if len(history) < 10:
                continue  # janela ainda pequena demais

            blocks = sum(1 for d in history if d == "block")
            rate = blocks / len(history)

            if rate >= self.block_rate_threshold:
                found.append(Anomaly(
                    type=AnomalyType.HIGH_BLOCK_RATE,
                    description=f"Taxa de bloqueio alta ({rate:.0%}) para agente {agent_id}",
                    severity=min(rate, 1.0),
                    agent_id=agent_id,
                    metadata={"block_rate": rate, "window": len(history)},
                ))

            if self._violation_count[agent_id] >= self.repeated_threshold:
                found.append(Anomaly(
                    type=AnomalyType.REPEATED_VIOLATION,
                    description=f"Violações repetidas ({self._violation_count[agent_id]}) do agente {agent_id}",
                    severity=0.8,
                    agent_id=agent_id,
                    metadata={"count": self._violation_count[agent_id]},
                ))

        return found

    def _heal(self, anomaly: Anomaly) -> Optional[HealingAction]:
        """Aplica ação corretiva de acordo com o modo configurado."""

        if self.mode == HealingMode.SUGGEST:
            if self.on_suggest:
                self.on_suggest(anomaly)
            if self.audit:
                self.audit.log_event(
                    component="regenerative_loop",
                    action="suggest",
                    decision="suggested",
                    reason=anomaly.description,
                    metadata=anomaly.metadata,
                )
            return HealingAction(
                anomaly=anomaly,
                action_taken="suggest",
                success=True,
                details="Ação apenas sugerida (modo suggest)",
            )

        if self.mode == HealingMode.ASK:
            # Em modo ASK apenas registra — a aprovação humana é externa
            if self.audit:
                self.audit.log_event(
                    component="regenerative_loop",
                    action="ask_approval",
                    decision="pending",
                    reason=anomaly.description,
                )
            return HealingAction(
                anomaly=anomaly,
                action_taken="ask",
                success=True,
                details="Aguardando aprovação humana",
            )

        # Modo AUTO
        if anomaly.type in (AnomalyType.HIGH_BLOCK_RATE, AnomalyType.REPEATED_VIOLATION):
            return self._isolate_agent(anomaly)

        if anomaly.type == AnomalyType.POLICY_LOAD_FAILURE:
            return self._reload_policies(anomaly)

        return None

    def _isolate_agent(self, anomaly: Anomaly) -> HealingAction:
        """Isola o agente suspeito (modo pânico)."""
        agent_id = anomaly.agent_id or "unknown"
        self._isolated_agents.add(agent_id)

        if self.on_isolate:
            self.on_isolate(agent_id)

        if self.audit:
            self.audit.log_event(
                component="regenerative_loop",
                action="isolate_agent",
                decision="isolated",
                reason=anomaly.description,
                metadata={"agent_id": agent_id},
            )

        return HealingAction(
            anomaly=anomaly,
            action_taken="isolate",
            success=True,
            details=f"Agente {agent_id} isolado",
        )

    def _reload_policies(self, anomaly: Anomaly) -> HealingAction:
        """Tenta recarregar políticas (self-healing de configuração)."""
        success = True
        details = []

        if self.engine and hasattr(self.engine, "reload"):
            ok = self.engine.reload()
            details.append(f"permissions_reload={'ok' if ok else 'fail'}")
            success = success and ok

        if self.dlp and hasattr(self.dlp, "reload"):
            ok = self.dlp.reload()
            details.append(f"dlp_reload={'ok' if ok else 'fail'}")
            success = success and ok

        if self.audit:
            self.audit.log_event(
                component="regenerative_loop",
                action="reload_policies",
                decision="success" if success else "failed",
                reason="; ".join(details),
            )

        return HealingAction(
            anomaly=anomaly,
            action_taken="reload_policies",
            success=success,
            details="; ".join(details),
        )

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------

    def is_isolated(self, agent_id: str) -> bool:
        """Verifica se um agente está isolado."""
        return agent_id in self._isolated_agents

    def release_agent(self, agent_id: str) -> None:
        """Libera um agente previamente isolado."""
        self._isolated_agents.discard(agent_id)
        self._violation_count[agent_id] = 0
        if self.audit:
            self.audit.log_event(
                component="regenerative_loop",
                action="release_agent",
                decision="released",
                reason=f"Agente {agent_id} liberado",
            )
