"""
Ventura.SEG — Sistema de Auditoria e Logs
=========================================
Logging estruturado, append-only durante a escrita e correlacionável por sessão.
Todas as decisões de segurança são registradas com timestamp, identidade,
ação solicitada, decisão e justificativa.

Observação: arquivo JSONL em modo append não é, por si só, armazenamento
criptograficamente imutável. Garantias de tamper evidence/immutability exigem
hash chain, assinatura/checkpoint e/ou armazenamento WORM/append-only externo.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


class AuditLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class AuditLogger:
    """
    Logger de auditoria append-only durante a operação normal.

    - Escreve em arquivo JSON Lines (um evento por linha)
    - Também emite para stdout em formato legível
    - Cada evento recebe um event_id único e session_id
    - Não afirma imutabilidade criptográfica do arquivo local
    """

    def __init__(
        self,
        log_dir: str | Path = "logs/audit",
        session_id: Optional[str] = None,
        also_console: bool = True,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or str(uuid4())
        self.also_console = also_console

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.log_file = self.log_dir / f"audit-{date_str}.jsonl"

        self._py_logger = logging.getLogger("ventura.seg.audit")
        self._py_logger.setLevel(logging.INFO)
        if not self._py_logger.handlers and also_console:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
            )
            self._py_logger.addHandler(handler)

    def _write(self, event: dict[str, Any]) -> None:
        """Acrescenta o evento ao arquivo JSONL em modo append."""
        event["event_id"] = str(uuid4())
        event["session_id"] = self.session_id
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

        if self.also_console:
            level = event.get("level", "INFO")
            msg = (
                f"[{event.get('component', 'core')}] "
                f"{event.get('action', '')} → {event.get('decision', '')} "
                f"| {event.get('reason', '')}"
            )
            if level == "CRITICAL" or level == "SECURITY":
                self._py_logger.warning(msg)
            else:
                self._py_logger.info(msg)

    def log_permission(
        self,
        command_or_target: str,
        decision: str,
        reason: str,
        rule_id: Optional[str] = None,
        actor: str = "system",
        metadata: Optional[dict] = None,
    ) -> None:
        """Registra uma decisão do motor de permissões."""
        self._write({
            "level": "SECURITY",
            "component": "permissions",
            "action": "evaluate",
            "target": command_or_target,
            "decision": decision,
            "reason": reason,
            "rule_id": rule_id,
            "actor": actor,
            "metadata": metadata or {},
        })

    def log_event(
        self,
        component: str,
        action: str,
        decision: str = "info",
        reason: str = "",
        level: AuditLevel = AuditLevel.INFO,
        metadata: Optional[dict] = None,
    ) -> None:
        """Registra um evento genérico de auditoria."""
        self._write({
            "level": level.value,
            "component": component,
            "action": action,
            "decision": decision,
            "reason": reason,
            "metadata": metadata or {},
        })

    def log_reload(self, policy_path: str, success: bool, details: str = "") -> None:
        """Registra hot-reload de políticas."""
        self._write({
            "level": "INFO",
            "component": "permissions",
            "action": "hot_reload",
            "target": policy_path,
            "decision": "success" if success else "failed",
            "reason": details,
        })
